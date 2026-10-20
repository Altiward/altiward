package sentinel_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Altiward/altiward/integrations/sentinel"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

func TestUploadPostsGzippedArraysToStream(t *testing.T) {
	var calls atomic.Int32
	var total atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/dataCollectionRules/dcr-123/streams/Custom-AltiwardOCSF" ||
			r.URL.Query().Get("api-version") != "2023-01-01" ||
			r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("unexpected request %s %v", r.URL, r.Header)
			w.WriteHeader(400)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var rows []map[string]any
		if err := json.NewDecoder(zr).Decode(&rows); err != nil {
			t.Error(err)
			return
		}
		total.Add(int32(len(rows)))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := &sentinel.Client{Endpoint: srv.URL, RuleID: "dcr-123", Stream: "Custom-AltiwardOCSF", Tokens: staticToken("tok"), MaxBatchBytes: 300}
	rows := []any{}
	for i := 0; i < 6; i++ {
		rows = append(rows, map[string]any{"EventUid": i, "Message": strings.Repeat("m", 60)})
	}
	if err := c.Upload(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 2 || total.Load() != 6 {
		t.Fatalf("calls = %d rows = %d", calls.Load(), total.Load())
	}
}

func TestUploadSurfacesHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":"InvalidStream"}}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	c := &sentinel.Client{Endpoint: srv.URL, RuleID: "dcr", Stream: "s", Tokens: staticToken("t")}
	if err := c.Upload(context.Background(), []any{1}); err == nil || !strings.Contains(err.Error(), "InvalidStream") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientCredentialsCachesToken(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = r.ParseForm()
		if r.URL.Path != "/tenant-1/oauth2/v2.0/token" || r.Form.Get("grant_type") != "client_credentials" ||
			r.Form.Get("scope") != "https://monitor.azure.com//.default" || r.Form.Get("client_secret") != "s3cret" {
			http.Error(w, "bad request", 400)
			return
		}
		w.Write([]byte(`{"access_token":"tok-` + string(rune('0'+requests.Load())) + `","expires_in":3600}`))
	}))
	defer srv.Close()

	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	cc := &sentinel.ClientCredentials{TenantID: "tenant-1", ClientID: "app", ClientSecret: "s3cret", AuthorityHost: srv.URL, Now: func() time.Time { return now }}
	first, err := cc.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, _ := cc.Token(context.Background())
	if first != "tok-1" || second != first || requests.Load() != 1 {
		t.Fatalf("first=%s second=%s requests=%d", first, second, requests.Load())
	}
	now = now.Add(56 * time.Minute) // inside the 5-minute refresh margin
	third, _ := cc.Token(context.Background())
	if third != "tok-2" {
		t.Fatalf("token not refreshed: %s", third)
	}
}

// imds stands in for the Azure Instance Metadata Service: it fails with the given
// statuses in turn, then issues tokens named mi-<request number><client_id>.
func imds(t *testing.T, requests *atomic.Int32, statuses ...int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(requests.Add(1))
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/metadata/identity/oauth2/token" || r.Header.Get("Metadata") != "true" ||
			q.Get("api-version") != "2018-02-01" || q.Get("resource") != "https://monitor.azure.com/" {
			t.Errorf("unexpected request %s %s %v", r.Method, r.URL, r.Header)
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		if n <= len(statuses) {
			http.Error(w, `{"error":"invalid_request","error_description":"Identity not found"}`, statuses[n-1])
			return
		}
		// IMDS sends the numbers as strings.
		fmt.Fprintf(w, `{"access_token":"mi-%d%s","expires_in":"86399","expires_on":"1792000000",`+
			`"resource":"https://monitor.azure.com/","token_type":"Bearer"}`, n, q.Get("client_id"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestManagedIdentityCachesToken(t *testing.T) {
	var requests atomic.Int32
	srv := imds(t, &requests)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	mi := &sentinel.ManagedIdentity{Host: srv.URL, Now: func() time.Time { return now }}
	first, err := mi.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, _ := mi.Token(context.Background())
	if first != "mi-1" || second != first || requests.Load() != 1 {
		t.Fatalf("first=%s second=%s requests=%d", first, second, requests.Load())
	}
	now = now.Add(23*time.Hour + 56*time.Minute) // inside the 5-minute refresh margin
	if third, _ := mi.Token(context.Background()); third != "mi-2" {
		t.Fatalf("token not refreshed: %s", third)
	}
}

func TestManagedIdentityUserAssigned(t *testing.T) {
	var requests atomic.Int32
	srv := imds(t, &requests)
	mi := &sentinel.ManagedIdentity{Host: srv.URL, ClientID: "abc"}
	if tok, err := mi.Token(context.Background()); err != nil || tok != "mi-1abc" {
		t.Fatalf("token=%s err=%v", tok, err)
	}
}

func TestManagedIdentityRetriesTransientErrors(t *testing.T) {
	var requests atomic.Int32
	srv := imds(t, &requests, http.StatusTooManyRequests, http.StatusInternalServerError)
	mi := &sentinel.ManagedIdentity{Host: srv.URL, RetryDelay: time.Millisecond}
	if tok, err := mi.Token(context.Background()); err != nil || tok != "mi-3" {
		t.Fatalf("token=%s err=%v requests=%d", tok, err, requests.Load())
	}
}

func TestManagedIdentityGivesUpAfterThreeTries(t *testing.T) {
	var requests atomic.Int32
	srv := imds(t, &requests, 503, 503, 503, 503)
	mi := &sentinel.ManagedIdentity{Host: srv.URL, RetryDelay: time.Millisecond}
	_, err := mi.Token(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "managed identity: ") || !strings.Contains(err.Error(), "HTTP 503") ||
		requests.Load() != 3 {
		t.Fatalf("err=%v requests=%d", err, requests.Load())
	}
}

func TestManagedIdentityExplainsAMissingIdentity(t *testing.T) {
	var requests atomic.Int32
	srv := imds(t, &requests, http.StatusBadRequest)
	mi := &sentinel.ManagedIdentity{Host: srv.URL, RetryDelay: time.Millisecond}
	_, err := mi.Token(context.Background())
	if err == nil || requests.Load() != 1 { // a 400 is a set-up mistake: no retry
		t.Fatalf("err=%v requests=%d", err, requests.Load())
	}
	for _, want := range []string{"managed identity: ", "Identity not found", "az vm identity assign", "Monitoring Metrics Publisher"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}
