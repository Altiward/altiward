package intune

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "secret-bearer-token-123"

type fixedToken string

func (f fixedToken) Token(context.Context) (string, error) { return string(f), nil }

// sleeps records every wait instead of making it.
type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d = append(s.d, d)
	return nil
}

func (s *sleeps) got() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.d...)
}

func newClient(srv *httptest.Server) (*Client, *sleeps) {
	s := &sleeps{}
	return &Client{Tokens: fixedToken(testToken), HTTP: srv.Client(), BaseURL: srv.URL + "/v1.0", Sleep: s.sleep}, s
}

func TestMacsFollowsPagesAndKeepsOnlyMacs(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Path != "/v1.0/deviceManagement/managedDevices" {
			t.Errorf("path = %q", r.URL.Path)
		}
		switch r.URL.Query().Get("$skiptoken") {
		case "":
			if got := r.URL.Query().Get("$filter"); got != "operatingSystem eq 'macOS'" {
				t.Errorf("$filter = %q", got)
			}
			if got := r.URL.Query().Get("$select"); got != "id,serialNumber,azureADDeviceId,userPrincipalName,deviceName,lastSyncDateTime,operatingSystem" {
				t.Errorf("$select = %q", got)
			}
			fmt.Fprintf(w, `{"value":[
				{"id":"id-1","serialNumber":"C02AAA","azureADDeviceId":"entra-1","userPrincipalName":"ann@example.com","deviceName":"Ann's MacBook","lastSyncDateTime":"2026-10-20T09:30:00+01:00","operatingSystem":"macOS"},
				{"id":"id-win","serialNumber":"WIN1","azureADDeviceId":"entra-w","userPrincipalName":"bob@example.com","deviceName":"PC","lastSyncDateTime":"2026-10-20T09:30:00Z","operatingSystem":"Windows"}
			],"@odata.nextLink":%q}`, srv.URL+"/v1.0/deviceManagement/managedDevices?$skiptoken=p2")
		case "p2":
			fmt.Fprintf(w, `{"value":[
				{"id":"id-2","serialNumber":"C02BBB","azureADDeviceId":"entra-2","userPrincipalName":"cy@example.com","deviceName":"Cy's Mac","lastSyncDateTime":"0001-01-01T00:00:00Z","operatingSystem":"macOS"}
			],"@odata.nextLink":%q}`, srv.URL+"/v1.0/deviceManagement/managedDevices?$skiptoken=p3")
		case "p3":
			fmt.Fprint(w, `{"value":[
				{"id":"id-3","serialNumber":"C02CCC","azureADDeviceId":"","userPrincipalName":"","deviceName":"Spare","lastSyncDateTime":"2026-10-21T00:00:00.5Z","operatingSystem":"macOS"}
			]}`)
		default:
			t.Errorf("unexpected skiptoken %q", r.URL.Query().Get("$skiptoken"))
		}
	}))
	defer srv.Close()
	c, _ := newClient(srv)
	got, err := c.Macs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d devices, want 3: %+v", len(got), got)
	}
	want := Device{
		ID: "id-1", Serial: "C02AAA", EntraDeviceID: "entra-1", PrimaryUPN: "ann@example.com", Name: "Ann's MacBook",
		LastCheckIn: time.Date(2026, 10, 20, 8, 30, 0, 0, time.UTC),
	}
	if got[0] != want {
		t.Errorf("first device = %+v, want %+v", got[0], want)
	}
	if got[0].LastCheckIn.Location() != time.UTC {
		t.Errorf("LastCheckIn is not UTC: %v", got[0].LastCheckIn.Location())
	}
	if got[1].ID != "id-2" || !got[1].LastCheckIn.IsZero() {
		t.Errorf("never-synced device = %+v, want zero LastCheckIn", got[1])
	}
	if got[2].ID != "id-3" || got[2].Serial != "C02CCC" || got[2].LastCheckIn.Location() != time.UTC {
		t.Errorf("third device = %+v", got[2])
	}
}

func TestMacsRefusesANextLinkToAnotherHost(t *testing.T) {
	var other int
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other++
		fmt.Fprint(w, `{"value":[]}`)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"value":[],"@odata.nextLink":%q}`, evil.URL+"/v1.0/deviceManagement/managedDevices?$skiptoken=x")
	}))
	defer srv.Close()
	c, _ := newClient(srv)
	_, err := c.Macs(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nextLink") {
		t.Fatalf("err = %v, want one naming nextLink", err)
	}
	if other != 0 {
		t.Errorf("%d requests reached the other host", other)
	}
}

func TestRetriesAsTold(t *testing.T) {
	cases := []struct {
		name       string
		statuses   []int
		retryAfter string
		wantSleeps []time.Duration
		wantCalls  int
		wantErr    bool
	}{
		{"429 with Retry-After", []int{429, 200}, "2", []time.Duration{2 * time.Second}, 2, false},
		{"503 without Retry-After backs off 2 s then 4 s", []int{503, 503, 200}, "", []time.Duration{2 * time.Second, 4 * time.Second}, 3, false},
		{"three tries at most", []int{503, 503, 503, 200}, "", []time.Duration{2 * time.Second, 4 * time.Second}, 3, true},
		{"wait capped at 60 s", []int{429, 429, 429}, "3600", []time.Duration{time.Minute, time.Minute}, 3, true},
		{"504 retried", []int{504, 200}, "", []time.Duration{2 * time.Second}, 2, false},
		{"500 retried", []int{500, 200}, "", []time.Duration{2 * time.Second}, 2, false},
		{"401 not retried", []int{401, 200}, "", nil, 1, true},
		{"unparseable Retry-After falls back", []int{429, 200}, "soon", []time.Duration{2 * time.Second}, 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				st := tc.statuses[calls]
				calls++
				if st != 200 {
					if tc.retryAfter != "" {
						w.Header().Set("Retry-After", tc.retryAfter)
					}
					w.WriteHeader(st)
					fmt.Fprint(w, `{"error":{"code":"TooBusy","message":"slow down"}}`)
					return
				}
				fmt.Fprint(w, `{"value":[]}`)
			}))
			defer srv.Close()
			c, s := newClient(srv)
			_, err := c.Macs(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if calls != tc.wantCalls {
				t.Errorf("calls = %d, want %d", calls, tc.wantCalls)
			}
			got := s.got()
			if len(got) != len(tc.wantSleeps) {
				t.Fatalf("sleeps = %v, want %v", got, tc.wantSleeps)
			}
			for i := range got {
				if got[i] != tc.wantSleeps[i] {
					t.Errorf("sleeps = %v, want %v", got, tc.wantSleeps)
				}
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "HTTP ") {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestRetryWaitHonoursCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(429)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{Tokens: fixedToken(testToken), HTTP: srv.Client(), BaseURL: srv.URL}
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := c.Macs(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("the default Sleep ignored cancellation")
	}
}

func TestDeviceNotFound(t *testing.T) {
	const id = "0f8fad5b-d9cb-469f-a165-70867728950e"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.0/deviceManagement/managedDevices/"+id {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(404)
		fmt.Fprint(w, `{"error":{"code":"ResourceNotFound","message":"gone"}}`)
	}))
	defer srv.Close()
	c, _ := newClient(srv)
	_, err := c.Device(context.Background(), id)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDeviceReturnsUDID(t *testing.T) {
	const id = "0f8fad5b-d9cb-469f-a165-70867728950e"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("$select"); got != "id,serialNumber,udid,azureADDeviceId,userPrincipalName,deviceName,lastSyncDateTime" {
			t.Errorf("$select = %q", got)
		}
		fmt.Fprintf(w, `{"id":%q,"serialNumber":"C02AAA","udid":"UDID-1","azureADDeviceId":"entra-1","userPrincipalName":"ann@example.com","deviceName":"Mac","lastSyncDateTime":"2026-10-20T08:30:00Z"}`, id)
	}))
	defer srv.Close()
	c, _ := newClient(srv)
	d, err := c.Device(context.Background(), " "+id+" ")
	if err != nil {
		t.Fatal(err)
	}
	want := Device{ID: id, Serial: "C02AAA", UDID: "UDID-1", EntraDeviceID: "entra-1", PrimaryUPN: "ann@example.com", Name: "Mac",
		LastCheckIn: time.Date(2026, 10, 20, 8, 30, 0, 0, time.UTC)}
	if d != want {
		t.Errorf("device = %+v, want %+v", d, want)
	}
}

func TestDeviceRefusesABadIDBeforeAnyRequest(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer srv.Close()
	c, _ := newClient(srv)
	for _, id := range []string{"{{deviceid}}", "", "../users", "abc/def"} {
		if _, err := c.Device(context.Background(), id); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Device(%q) err = %v, want a validation error", id, err)
		}
	}
	if calls != 0 {
		t.Errorf("%d requests were made", calls)
	}
}

func TestForbiddenNamesThePermission(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`)
	}))
	defer srv.Close()
	c, _ := newClient(srv)
	_, err := c.Macs(context.Background())
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"DeviceManagementManagedDevices.Read.All", "Authorization_RequestDenied", "HTTP 403"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err %q lacks %q", err, want)
		}
	}
}

func TestErrorsNeverCarryTheToken(t *testing.T) {
	// A hostile or careless server that echoes the Authorization header back.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprintf(w, `{"error":{"code":"BadRequest","message":%q}}`, "bad header "+r.Header.Get("Authorization")+" / "+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}))
	c, _ := newClient(srv)
	_, err := c.Macs(context.Background())
	if err == nil || !strings.Contains(err.Error(), "BadRequest") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error carries the token: %v", err)
	}
	// A body that is not Graph's, and a refused connection.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
		fmt.Fprint(w, "<html>"+r.Header.Get("Authorization")+"</html>")
	})
	_, err = c.Macs(context.Background())
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Errorf("non-Graph body: err = %v", err)
	}
	srv.Close()
	_, err = c.Macs(context.Background())
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Errorf("closed server: err = %v", err)
	}
}

func TestDevicesBySerialEscapesAndValidates(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.URL.Query().Get("$filter"); got != "serialNumber eq 'C02XK0AAJGH5'" {
			t.Errorf("$filter = %q", got)
		}
		fmt.Fprint(w, `{"value":[{"id":"id-1","serialNumber":"C02XK0AAJGH5","deviceName":"Mac","lastSyncDateTime":"2026-10-20T08:30:00Z"}]}`)
	}))
	defer srv.Close()
	c, _ := newClient(srv)
	got, err := c.DevicesBySerial(context.Background(), "C02XK0AAJGH5")
	if err != nil || len(got) != 1 || got[0].ID != "id-1" {
		t.Fatalf("got %+v, err %v", got, err)
	}
	for _, bad := range []string{"x' or 1 eq 1", "", strings.Repeat("A", 33), "C02 XK", "C02\n"} {
		if _, err := c.DevicesBySerial(context.Background(), bad); err == nil {
			t.Errorf("DevicesBySerial(%q) accepted", bad)
		}
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (the bad serials must not reach Graph)", calls)
	}
}

func TestValidDeviceID(t *testing.T) {
	const g = "0f8fad5b-d9cb-469f-a165-70867728950e"
	for in, want := range map[string]bool{
		"{{deviceid}}":                         false,
		"{{DeviceID}}":                         false,
		"":                                     false,
		"{" + g + "}":                          false,
		g:                                      true,
		strings.ToUpper(g):                     true,
		"  " + g + "\n":                        true,
		g + "0":                                false,
		"0f8fad5bd9cb469fa16570867728950e":     false,
		"0f8fad5b-d9cb-469f-a165-70867728950g": false,
	} {
		if got := ValidDeviceID(in); got != want {
			t.Errorf("ValidDeviceID(%q) = %v, want %v", in, got, want)
		}
	}
}
