package mdm_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/intune"
	"github.com/Altiward/altiward/backend/internal/mdm"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// fakeSource answers Macs with macs and err, and remembers the deadline it was given.
type fakeSource struct {
	macs     []intune.Device
	err      error
	calls    int
	deadline time.Time
}

func (f *fakeSource) Macs(ctx context.Context) ([]intune.Device, error) {
	f.calls++
	f.deadline, _ = ctx.Deadline()
	return f.macs, f.err
}

func (f *fakeSource) Device(context.Context, string) (intune.Device, error) {
	return intune.Device{}, errors.New("not used by the sync")
}

func (f *fakeSource) DevicesBySerial(context.Context, string) ([]intune.Device, error) {
	return nil, errors.New("not used by the sync")
}

func newSync(st store.Store, src mdm.Source, now time.Time) *mdm.Sync {
	return &mdm.Sync{Store: st, Source: src, TenantID: "acme", Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return now }}
}

func copyOf(t *testing.T, st store.Store) ([]store.MDMDevice, store.MDMSync) {
	t.Helper()
	ctx := context.Background()
	devices, err := st.MDMDevices(ctx, "acme", store.MDMIntune)
	if err != nil {
		t.Fatal(err)
	}
	status, err := st.MDMSyncStatus(ctx, "acme", store.MDMIntune)
	if err != nil {
		t.Fatal(err)
	}
	return devices, status
}

func TestSyncStoresTheMacs(t *testing.T) {
	now := testfixture.Time(t, "2026-10-27T12:00:00Z")
	src := &fakeSource{macs: []intune.Device{
		{ID: "0A1B2C3D-0000-4000-8000-00000000000A", Serial: "C02AAA", EntraDeviceID: "e-a", UDID: "U-A",
			PrimaryUPN: "jdoe@example.com", Name: "JDOE-MBP", LastCheckIn: now.Add(-time.Hour)},
		{ID: "0a1b2c3d-0000-4000-8000-00000000000b", Serial: "C02BBB", Name: "Spare"},
	}}
	st := store.NewMemory(nil)
	started := time.Now()
	if err := newSync(st, src, now).Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	devices, status := copyOf(t, st)
	want := []store.MDMDevice{
		{TenantID: "acme", Source: store.MDMIntune, DeviceID: "0a1b2c3d-0000-4000-8000-00000000000a", Serial: "C02AAA",
			EntraDeviceID: "e-a", PrimaryUPN: "jdoe@example.com", Name: "JDOE-MBP", LastCheckIn: now.Add(-time.Hour)},
		{TenantID: "acme", Source: store.MDMIntune, DeviceID: "0a1b2c3d-0000-4000-8000-00000000000b", Serial: "C02BBB", Name: "Spare"},
	}
	if fmt.Sprint(devices) != fmt.Sprint(want) {
		t.Fatalf("copy = %+v\nwant %+v", devices, want)
	}
	if status.LastSuccessAt == nil || !status.LastSuccessAt.Equal(now) || status.Devices != 2 || status.LastErrorAt != nil {
		t.Fatalf("status = %+v", status)
	}
	// Graph's paging has no page cap, so the pass runs under a deadline.
	if src.deadline.IsZero() || src.deadline.After(started.Add(5*time.Minute+time.Second)) {
		t.Fatalf("Macs ran with deadline %v, want within 5 minutes", src.deadline)
	}
}

func TestSyncKeepsTheOldCopyWhenAPageFails(t *testing.T) {
	t0 := testfixture.Time(t, "2026-10-27T12:00:00Z")
	old := store.MDMDevice{DeviceID: "00000000-0000-4000-8000-0000000000aa", Serial: "C02OLD", Name: "Old", LastCheckIn: t0}
	check := func(t *testing.T, src mdm.Source, wantErr string) {
		t.Helper()
		st := store.NewMemory(nil)
		if err := st.ReplaceMDMDevices(context.Background(), "acme", store.MDMIntune, []store.MDMDevice{old}, t0); err != nil {
			t.Fatal(err)
		}
		now := t0.Add(15 * time.Minute)
		err := newSync(st, src, now).Once(context.Background())
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("Once = %v, want %q", err, wantErr)
		}
		devices, status := copyOf(t, st)
		if len(devices) != 1 || devices[0].DeviceID != old.DeviceID {
			t.Fatalf("copy after a failed sync = %+v", devices)
		}
		if status.LastSuccessAt == nil || !status.LastSuccessAt.Equal(t0) || status.Devices != 1 ||
			status.LastErrorAt == nil || !status.LastErrorAt.Equal(now) || !strings.Contains(status.LastError, wantErr) {
			t.Fatalf("status after a failed sync = %+v", status)
		}
	}

	t.Run("a source that hands back the pages it read", func(t *testing.T) {
		check(t, &fakeSource{macs: []intune.Device{{ID: "00000000-0000-4000-8000-000000000001", Serial: "C02NEW"}},
			err: errors.New("intune: HTTP 400 BadRequest: page 2")}, "page 2")
	})

	t.Run("Graph failing on page 2", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("page") == "2" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":{"code":"BadRequest","message":"page 2 failed"}}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"value":[{"id":"00000000-0000-4000-8000-000000000001","serialNumber":"C02NEW",`+
				`"operatingSystem":"macOS"}],"@odata.nextLink":%q}`, srv.URL+"/deviceManagement/managedDevices?page=2")
		}))
		defer srv.Close()
		check(t, &intune.Client{Tokens: staticToken("t"), HTTP: srv.Client(), BaseURL: srv.URL}, "page 2 failed")
	})
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

func TestSyncSkipsWhenAnotherReplicaClaimed(t *testing.T) {
	now := testfixture.Time(t, "2026-10-27T12:00:00Z")
	st := store.NewMemory(nil)
	// Another replica claimed this round a minute ago.
	if ok, err := st.ClaimMDMSync(context.Background(), "acme", store.MDMIntune, now.Add(-time.Minute), mdm.Interval); err != nil || !ok {
		t.Fatalf("claim = %v, %v", ok, err)
	}
	src := &fakeSource{macs: []intune.Device{{ID: "00000000-0000-4000-8000-000000000001", Serial: "C02NEW"}}}
	if err := newSync(st, src, now).Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if devices, status := copyOf(t, st); src.calls != 0 || len(devices) != 0 || status.LastSuccessAt != nil {
		t.Fatalf("synced anyway: %d calls, copy %+v, status %+v", src.calls, devices, status)
	}
	// Once its claim is half an interval old, this replica takes over.
	if err := newSync(st, src, now.Add(mdm.Interval/2)).Once(context.Background()); err != nil || src.calls != 1 {
		t.Fatalf("after half an interval: %v, %d calls", err, src.calls)
	}
}

// lockedBuffer is a log that Run writes while the test reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestSyncErrorsNeverShowTheNextLink: from page 2 on, a request's URL is Graph's nextLink,
// whose $skiptoken can name the last device read. A request that fails there, by running
// out of time, must not put it in the error viewers see, or in the log.
func TestSyncErrorsNeverShowTheNextLink(t *testing.T) {
	const skiptoken = "LastDeviceName='JDOE-MBP',LastDeviceId='9f8e7d6c-0000-4000-8000-000000000009'"
	for _, c := range []struct {
		name       string
		clientWait time.Duration // the HTTP client's timeout; 0 for none
		passWait   time.Duration // the pass's deadline
		want       string
	}{
		{"past the pass's deadline", 0, 300 * time.Millisecond, "listing the Macs took longer than 300ms"},
		{"past the HTTP client's timeout", 300 * time.Millisecond, 5 * time.Minute, "Client.Timeout"},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer mdm.SetPassTimeout(c.passWait)()
			stop := make(chan struct{})
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("$skiptoken") == "" {
					next := srv.URL + "/deviceManagement/managedDevices?$skiptoken=" + url.QueryEscape(skiptoken)
					_, _ = fmt.Fprintf(w, `{"value":[{"id":"00000000-0000-4000-8000-000000000001","serialNumber":"C02NEW",`+
						`"operatingSystem":"macOS"}],"@odata.nextLink":%q}`, next)
					return
				}
				select { // page 2 never answers
				case <-r.Context().Done():
				case <-stop:
				}
			}))
			defer srv.Close()
			defer close(stop)

			client := &http.Client{Timeout: c.clientWait}
			st := store.NewMemory(nil)
			logs := &lockedBuffer{}
			graph := &intune.Client{Tokens: staticToken("t"), HTTP: client, BaseURL: srv.URL}
			s := newSync(st, graph, testfixture.Time(t, "2026-10-27T12:00:00Z"))
			s.Log = slog.New(slog.NewTextHandler(logs, nil))
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { s.Run(ctx, time.Hour); close(done) }()
			for end := time.Now().Add(10 * time.Second); !strings.Contains(logs.String(), "Intune sync failed"); {
				if time.Now().After(end) {
					t.Fatal("no warning logged")
				}
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			<-done

			_, status := copyOf(t, st)
			for what, text := range map[string]string{"last_error": status.LastError, "log": logs.String()} {
				if !strings.Contains(text, c.want) {
					t.Errorf("%s %q lacks %q", what, text, c.want)
				}
				for _, leak := range []string{"skiptoken", "LastDevice", "JDOE-MBP", "9f8e7d6c"} {
					if strings.Contains(text, leak) {
						t.Errorf("%s shows %q: %s", what, leak, text)
					}
				}
			}
		})
	}
}
