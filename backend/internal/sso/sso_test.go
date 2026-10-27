package sso_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/config"
	"github.com/Altiward/altiward/backend/internal/sso"
	"github.com/Altiward/altiward/backend/internal/sso/ssotest"
)

func provider(t *testing.T, issuer string, client *http.Client) *sso.Provider {
	return sso.New(config.OIDC{
		Issuer: issuer, ClientID: ssotest.ClientID, ConsoleURL: "https://altiward.example.com", Tenant: "acme",
		GroupsClaim: "groups", Scopes: []string{"openid"},
		AdminGroups: []string{"admins"}, OperatorGroups: []string{"ops"}, ViewerGroups: []string{"view", "ops-readers"},
	}, client, time.Now)
}

func TestTheHighestRoleWins(t *testing.T) {
	p := provider(t, "https://idp.example.com", http.DefaultClient)
	for _, c := range []struct {
		groups []string
		role   auth.ConsoleRole
		ok     bool
	}{
		{[]string{"view"}, auth.Viewer, true}, {[]string{"ops-readers", "ops"}, auth.Operator, true},
		{[]string{"view", "admins", "ops"}, auth.Admin, true}, {[]string{"Admins"}, "", false}, {nil, "", false},
	} {
		if role, ok := p.RoleFor(c.groups); role != c.role || ok != c.ok {
			t.Errorf("%v: %q %v", c.groups, role, ok)
		}
	}
}

func TestIdentityFallsBackFromEmail(t *testing.T) {
	idp := ssotest.New(t)
	p := provider(t, idp.URL, idp.Client())
	ctx := context.Background()
	for _, c := range []struct {
		claims map[string]any
		email  string
	}{
		{map[string]any{"email": "a@example.com", "preferred_username": "b@example.com"}, "a@example.com"},
		{map[string]any{"preferred_username": "b@example.com", "upn": "c@example.com"}, "b@example.com"},
		{map[string]any{"upn": "c@example.com"}, "c@example.com"},
		{map[string]any{"sub": "only-a-subject"}, "only-a-subject"},
	} {
		verifier, nonce := oauth2.GenerateVerifier(), "n-1"
		authURL, err := p.AuthCodeURL(ctx, "s", nonce, verifier)
		if err != nil {
			t.Fatal(err)
		}
		c.claims["groups"] = "view" // a single group may come as a string
		back := idp.Authorize(authURL, c.claims)
		code := mustQuery(t, back, "code")
		id, err := p.Exchange(ctx, code, verifier, nonce)
		if err != nil || id.Email != c.email || len(id.Groups) != 1 || id.Groups[0] != "view" {
			t.Errorf("%v: %+v, %v", c.claims, id, err)
		}
	}
}

func TestSignOutURL(t *testing.T) {
	idp := ssotest.New(t, ssotest.WithEndSession())
	p := provider(t, idp.URL, idp.Client())
	to, ok := p.SignOutURL(context.Background(), "https://altiward.example.com/signed-out")
	if !ok {
		t.Fatal("no sign-out URL")
	}
	u, err := neturl.Parse(to)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != idp.URL+"/logout" {
		t.Errorf("sign-out URL = %s", to)
	}
	q := u.Query()
	if len(q) != 2 || q.Get("client_id") != ssotest.ClientID ||
		q.Get("post_logout_redirect_uri") != "https://altiward.example.com/signed-out" {
		t.Errorf("query = %v", q)
	}
}

func TestSignOutURLWithoutEndSession(t *testing.T) {
	idp := ssotest.New(t)
	p := provider(t, idp.URL, idp.Client())
	if to, ok := p.SignOutURL(context.Background(), "https://altiward.example.com/signed-out"); ok || to != "" {
		t.Errorf("got %q, %v", to, ok)
	}
}

func TestDiscoveryIsRetriedAfterAFailure(t *testing.T) {
	down := true
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/keys"})
	}))
	defer srv.Close()
	// Down at first: the server starts anyway, and sign-in works once it's back.
	p := provider(t, srv.URL, srv.Client())
	if _, err := p.AuthCodeURL(context.Background(), "s", "n", "v"); err == nil {
		t.Fatal("discovered a provider that is down")
	}
	down = false
	if u, err := p.AuthCodeURL(context.Background(), "s", "n", "v"); err != nil || mustQuery(t, u, "state") != "s" {
		t.Fatalf("%s, %v", u, err)
	}
}

func mustQuery(t *testing.T, raw, key string) string {
	t.Helper()
	u, err := neturl.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}
