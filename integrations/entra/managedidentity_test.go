package entra_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Altiward/altiward/integrations/entra"
)

const (
	testResource = "https://example.test/"
	imdsHint     = "hint for a VM: assign an identity"
	endpointHint = "hint for a container app: assign an identity"
)

// imds stands in for the Azure Instance Metadata Service: it fails with the given
// statuses in turn, then issues tokens named mi-<request number><client_id>.
func imds(t *testing.T, requests *atomic.Int32, statuses ...int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(requests.Add(1))
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/metadata/identity/oauth2/token" || r.Header.Get("Metadata") != "true" ||
			q.Get("api-version") != "2018-02-01" || q.Get("resource") != "https://example.test/" {
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
			`"resource":"https://example.test/","token_type":"Bearer"}`, n, q.Get("client_id"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestManagedIdentityCachesToken(t *testing.T) {
	var requests atomic.Int32
	srv := imds(t, &requests)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	mi := &entra.ManagedIdentity{Resource: testResource, IMDSHint: imdsHint, EndpointHint: endpointHint, Host: srv.URL, Now: func() time.Time { return now }}
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
	mi := &entra.ManagedIdentity{Resource: testResource, IMDSHint: imdsHint, EndpointHint: endpointHint, Host: srv.URL, ClientID: "abc"}
	if tok, err := mi.Token(context.Background()); err != nil || tok != "mi-1abc" {
		t.Fatalf("token=%s err=%v", tok, err)
	}
}

func TestManagedIdentityRetriesTransientErrors(t *testing.T) {
	var requests atomic.Int32
	srv := imds(t, &requests, http.StatusTooManyRequests, http.StatusInternalServerError)
	mi := &entra.ManagedIdentity{Resource: testResource, IMDSHint: imdsHint, EndpointHint: endpointHint, Host: srv.URL, RetryDelay: time.Millisecond}
	if tok, err := mi.Token(context.Background()); err != nil || tok != "mi-3" {
		t.Fatalf("token=%s err=%v requests=%d", tok, err, requests.Load())
	}
}

func TestManagedIdentityGivesUpAfterThreeTries(t *testing.T) {
	var requests atomic.Int32
	srv := imds(t, &requests, 503, 503, 503, 503)
	mi := &entra.ManagedIdentity{Resource: testResource, IMDSHint: imdsHint, EndpointHint: endpointHint, Host: srv.URL, RetryDelay: time.Millisecond}
	_, err := mi.Token(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "managed identity: ") || !strings.Contains(err.Error(), "HTTP 503") ||
		requests.Load() != 3 {
		t.Fatalf("err=%v requests=%d", err, requests.Load())
	}
}

func TestManagedIdentityExplainsAMissingIdentity(t *testing.T) {
	var requests atomic.Int32
	srv := imds(t, &requests, http.StatusBadRequest)
	mi := &entra.ManagedIdentity{Resource: testResource, IMDSHint: imdsHint, EndpointHint: endpointHint, Host: srv.URL, RetryDelay: time.Millisecond}
	_, err := mi.Token(context.Background())
	if err == nil || requests.Load() != 1 { // a 400 is a set-up mistake: no retry
		t.Fatalf("err=%v requests=%d", err, requests.Load())
	}
	for _, want := range []string{"managed identity: ", "Identity not found", imdsHint} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

// identityEndpoint stands in for a Container App's identity endpoint: it fails with the
// given statuses in turn, then issues tokens named ca-<request number><client_id> that
// expire an hour after now, as unix seconds in a string.
func identityEndpoint(t *testing.T, requests *atomic.Int32, now time.Time, statuses ...int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(requests.Add(1))
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/msi/token" || r.Header.Get("X-IDENTITY-HEADER") != "header-1" ||
			r.Header.Get("Metadata") != "" || q.Get("api-version") != "2019-08-01" || q.Get("resource") != "https://example.test/" {
			t.Errorf("unexpected request %s %s %v", r.Method, r.URL, r.Header)
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		if n <= len(statuses) {
			http.Error(w, `{"statusCode":400,"message":"No User Assigned or Delegated Managed Identity found"}`, statuses[n-1])
			return
		}
		fmt.Fprintf(w, `{"access_token":"ca-%d%s","expires_on":"%d","resource":"https://example.test/",`+
			`"token_type":"Bearer","client_id":"%s"}`, n, q.Get("client_id"), now.Add(time.Hour).Unix(), q.Get("client_id"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestManagedIdentityOnAContainerApp(t *testing.T) {
	var requests atomic.Int32
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	srv := identityEndpoint(t, &requests, now)
	mi := &entra.ManagedIdentity{Resource: testResource, IMDSHint: imdsHint, EndpointHint: endpointHint, Endpoint: srv.URL + "/msi/token", Header: "header-1", Now: func() time.Time { return now }}
	first, err := mi.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, _ := mi.Token(context.Background())
	if first != "ca-1" || second != first || requests.Load() != 1 {
		t.Fatalf("first=%s second=%s requests=%d", first, second, requests.Load())
	}
	now = now.Add(56 * time.Minute) // expires_on is an hour on: inside the 5-minute refresh margin
	if third, _ := mi.Token(context.Background()); third != "ca-2" {
		t.Fatalf("token not refreshed: %s", third)
	}
}

func TestManagedIdentityOnAContainerAppUserAssigned(t *testing.T) {
	var requests atomic.Int32
	srv := identityEndpoint(t, &requests, time.Now())
	mi := &entra.ManagedIdentity{Resource: testResource, IMDSHint: imdsHint, EndpointHint: endpointHint, Endpoint: srv.URL + "/msi/token", Header: "header-1", ClientID: "abc"}
	if tok, err := mi.Token(context.Background()); err != nil || tok != "ca-1abc" {
		t.Fatalf("token=%s err=%v", tok, err)
	}
}

func TestManagedIdentityOnAContainerAppRetriesTransientErrors(t *testing.T) {
	var requests atomic.Int32
	srv := identityEndpoint(t, &requests, time.Now(), http.StatusTooManyRequests, http.StatusInternalServerError)
	mi := &entra.ManagedIdentity{Resource: testResource, IMDSHint: imdsHint, EndpointHint: endpointHint, Endpoint: srv.URL + "/msi/token", Header: "header-1", RetryDelay: time.Millisecond}
	if tok, err := mi.Token(context.Background()); err != nil || tok != "ca-3" {
		t.Fatalf("token=%s err=%v requests=%d", tok, err, requests.Load())
	}
}

func TestManagedIdentityOnAContainerAppExplainsAMissingIdentity(t *testing.T) {
	var requests atomic.Int32
	srv := identityEndpoint(t, &requests, time.Now(), http.StatusBadRequest)
	mi := &entra.ManagedIdentity{Resource: testResource, IMDSHint: imdsHint, EndpointHint: endpointHint, Endpoint: srv.URL + "/msi/token", Header: "header-1", RetryDelay: time.Millisecond}
	_, err := mi.Token(context.Background())
	if err == nil || requests.Load() != 1 {
		t.Fatalf("err=%v requests=%d", err, requests.Load())
	}
	for _, want := range []string{"managed identity: identity endpoint HTTP 400", "No User Assigned", endpointHint} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "header-1") {
		t.Errorf("error shows the identity header: %v", err)
	}
}

func TestManagedIdentityAddsTheRightHint(t *testing.T) {
	var vm atomic.Int32
	imdsSrv := imds(t, &vm, http.StatusBadRequest)
	_, err := (&entra.ManagedIdentity{Host: imdsSrv.URL, Resource: testResource, IMDSHint: imdsHint, EndpointHint: endpointHint}).Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), imdsHint) || strings.Contains(err.Error(), endpointHint) {
		t.Fatalf("IMDS error = %v", err)
	}

	var ca atomic.Int32
	endpointSrv := identityEndpoint(t, &ca, time.Now(), http.StatusBadRequest)
	_, err = (&entra.ManagedIdentity{Endpoint: endpointSrv.URL + "/msi/token", Header: "header-1", Resource: testResource, IMDSHint: imdsHint, EndpointHint: endpointHint}).Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), endpointHint) || strings.Contains(err.Error(), imdsHint) {
		t.Fatalf("identity endpoint error = %v", err)
	}
}

func TestManagedIdentityNeedsAResource(t *testing.T) {
	if _, err := (&entra.ManagedIdentity{}).Token(context.Background()); err == nil || !strings.Contains(err.Error(), "Resource is empty") {
		t.Fatalf("err = %v", err)
	}
}
