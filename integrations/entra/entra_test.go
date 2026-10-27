package entra_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Altiward/altiward/integrations/entra"
)

func TestClientCredentialsCachesToken(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = r.ParseForm()
		if r.URL.Path != "/tenant-1/oauth2/v2.0/token" || r.Form.Get("grant_type") != "client_credentials" ||
			r.Form.Get("scope") != "https://example.test/.default" || r.Form.Get("client_secret") != "s3cret" {
			http.Error(w, "bad request", 400)
			return
		}
		w.Write([]byte(`{"access_token":"tok-` + string(rune('0'+requests.Load())) + `","expires_in":3600}`))
	}))
	defer srv.Close()

	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	cc := &entra.ClientCredentials{Scope: "https://example.test/.default", TenantID: "tenant-1", ClientID: "app", ClientSecret: "s3cret", AuthorityHost: srv.URL, Now: func() time.Time { return now }}
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

func TestClientCredentialsNeedsAScope(t *testing.T) {
	cc := &entra.ClientCredentials{TenantID: "tenant-1", ClientID: "app", ClientSecret: "s3cret"}
	if _, err := cc.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "Scope is empty") {
		t.Fatalf("err = %v", err)
	}
}
