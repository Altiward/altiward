package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/config"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/sso"
	"github.com/Altiward/altiward/backend/internal/sso/ssotest"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// ssoEnv is a server with single sign-on through a fake identity provider, and a clock
// the test moves.
type ssoEnv struct {
	h     http.Handler
	idp   *ssotest.Provider
	store *store.Memory
	now   time.Time
	log   *bytes.Buffer // what the server logged
	// idpDown makes every request to the identity provider fail, as if it were unreachable.
	idpDown bool
}

// downable is a transport that fails while the environment's identity provider is "down".
type downable struct {
	env   *ssoEnv
	inner http.RoundTripper
}

func (d downable) RoundTrip(r *http.Request) (*http.Response, error) {
	if d.env.idpDown {
		return nil, errors.New("identity provider unreachable")
	}
	return d.inner.RoundTrip(r)
}

// newSSOServer starts the server; each of more adds an option made from its store.
func newSSOServer(t *testing.T, more ...func(*store.Memory) api.Option) *ssoEnv {
	t.Helper()
	return newSSOServerWith(t, ssotest.New(t), nil, more...)
}

// newSSOServerWith is newSSOServer with a chosen identity provider, and a change to the
// single sign-on settings.
func newSSOServerWith(t *testing.T, idp *ssotest.Provider, settings func(*config.OIDC), more ...func(*store.Memory) api.Option) *ssoEnv {
	t.Helper()
	env := &ssoEnv{idp: idp, store: store.NewMemory(nil), now: serverNow(t), log: &bytes.Buffer{}}
	clock := func() time.Time { return env.now }
	env.idp.Now = clock
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	if err != nil {
		t.Fatal(err)
	}
	tokens.BreakGlass()
	cfg := config.OIDC{
		Issuer: env.idp.URL, ClientID: ssotest.ClientID, ClientSecret: "secret", ConsoleURL: "https://altiward.example.com",
		Tenant: "acme", GroupsClaim: "groups", Scopes: []string{"openid", "email", "profile"},
		AdminGroups: []string{"g-admin"}, OperatorGroups: []string{"g-ops"}, ViewerGroups: []string{"g-view"},
	}
	if settings != nil {
		settings(&cfg)
	}
	idpClient := env.idp.Client()
	idpClient.Transport = downable{env: env, inner: idpClient.Transport}
	provider := sso.New(cfg, idpClient, clock)
	opts := []api.Option{api.WithSSO(provider, true)}
	for _, m := range more {
		opts = append(opts, m(env.store))
	}
	env.h = api.New(env.store, tokens, slog.New(slog.NewTextHandler(env.log, nil)), clock, opts...)
	health := testfixture.Event(t, "agent-health")
	if _, err := env.store.Ingest(context.Background(), "acme", []event.Event{health}, env.now); err != nil {
		t.Fatal(err)
	}
	return env
}

// browser keeps cookies between requests, as a browser on the console's origin would.
type browser struct {
	t       *testing.T
	h       http.Handler
	cookies map[string]*http.Cookie
	csrf    string
}

func (e *ssoEnv) browser(t *testing.T) *browser {
	return &browser{t: t, h: e.h, cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(method, target string, body any, headers ...string) (*httptest.ResponseRecorder, map[string]any) {
	b.t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, r)
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

// mutate sends a change with the session's CSRF token.
func (b *browser) mutate(method, target string, body any) (*httptest.ResponseRecorder, map[string]any) {
	b.t.Helper()
	return b.do(method, target, body, "X-CSRF-Token", b.csrf)
}

// signIn goes through the whole flow: the console's sign-in link, the identity provider,
// and back. It returns where the callback sent the browser.
func (b *browser) signIn(idp *ssotest.Provider, next string, claims map[string]any) string {
	b.t.Helper()
	rec, _ := b.do("GET", "/v1/auth/login?next="+url.QueryEscape(next), nil)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), idp.URL+"/authorize?") {
		b.t.Fatalf("login: %d %v", rec.Code, rec.Header())
	}
	back, err := url.Parse(idp.Authorize(rec.Header().Get("Location"), claims))
	if err != nil {
		b.t.Fatal(err)
	}
	if back.Scheme+"://"+back.Host+back.Path != "https://altiward.example.com/v1/auth/callback" {
		b.t.Fatalf("redirect URL = %s", back)
	}
	rec, _ = b.do("GET", back.RequestURI(), nil)
	if rec.Code != http.StatusFound {
		b.t.Fatalf("callback: %d %s", rec.Code, rec.Body)
	}
	if _, ok := b.cookies["__Host-altiward_login"]; ok {
		b.t.Fatal("the sign-in cookie outlived the callback")
	}
	if rec, me := b.do("GET", "/v1/auth/me", nil); rec.Code == http.StatusOK {
		b.csrf, _ = me["csrf_token"].(string)
	}
	return rec.Header().Get("Location")
}

func person(groups ...any) map[string]any {
	return map[string]any{"email": "jane.doe@example.com", "name": "Jane Doe", "groups": groups}
}

func TestSignInThroughSSO(t *testing.T) {
	env := newSSOServer(t)
	b := env.browser(t)
	if rec, out := b.do("GET", "/v1/auth/config", nil); rec.Code != 200 || out["sso"] != true {
		t.Fatalf("config: %d %v", rec.Code, out)
	}
	if rec, _ := b.do("GET", "/v1/devices", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("before sign-in: %d", rec.Code)
	}
	if to := b.signIn(env.idp, "/fleet?serial=C02", person("g-other", "g-ops")); to != "/fleet?serial=C02" {
		t.Fatalf("returned to %q", to)
	}
	c := b.cookies["__Host-altiward_session"]
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("session cookie = %+v", c)
	}
	rec, me := b.do("GET", "/v1/auth/me", nil)
	if rec.Code != 200 || me["actor"] != "jane.doe@example.com" || me["name"] != "Jane Doe" || me["role"] != "operator" ||
		me["method"] != "sso" || b.csrf == "" {
		t.Fatalf("me: %d %v", rec.Code, me)
	}
	if rec, _ := b.do("GET", "/v1/devices", nil); rec.Code != 200 {
		t.Fatalf("read: %d", rec.Code)
	}

	// Changes need the CSRF token, and the role.
	if rec, out := b.do("POST", "/v1/devices/"+fixtureSerial+"/revoke", nil); rec.Code != 403 || !strings.Contains(out["error"].(string), "CSRF") {
		t.Fatalf("no CSRF token: %d %v", rec.Code, out)
	}
	if rec, _ := b.do("POST", "/v1/devices/"+fixtureSerial+"/revoke", nil, "X-CSRF-Token", "wrong"); rec.Code != 403 {
		t.Fatalf("wrong CSRF token: %d", rec.Code)
	}
	rec, cmd := b.mutate("POST", "/v1/devices/"+fixtureSerial+"/revoke", nil)
	if rec.Code != http.StatusCreated || cmd["issued_by"] != "jane.doe@example.com" {
		t.Fatalf("revoke: %d %v", rec.Code, cmd)
	}
	if rec, out := b.mutate("PUT", "/v1/settings", map[string]any{"silent_after_hours": 24}); rec.Code != 403 ||
		out["error"] != "this needs the admin role; you have operator" {
		t.Fatalf("operator changed settings: %d %v", rec.Code, out)
	}

	// The audit log names the person, for signing in and for the revoke.
	entries, _ := env.store.ListAudit(context.Background(), "acme", store.AuditFilter{})
	if len(entries) != 2 || entries[0].Action != store.AuditRevokeDevice || entries[1].Action != store.AuditSignIn ||
		entries[0].Actor != "jane.doe@example.com" || entries[1].Actor != "jane.doe@example.com" || entries[1].Detail["role"] != "operator" {
		t.Fatalf("audit = %+v", entries)
	}
}

func TestRolesFollowGroups(t *testing.T) {
	env := newSSOServer(t)
	for _, c := range []struct {
		groups            []any
		role              string
		revoke, put, test int
	}{
		// No SIEM is configured, so an admin's test event gets as far as saying so.
		{[]any{"g-view"}, "viewer", 403, 403, 403},
		{[]any{"g-view", "g-ops"}, "operator", 201, 403, 403},
		{[]any{"g-ops", "g-admin"}, "admin", 201, 200, 409},
	} {
		b := env.browser(t)
		b.signIn(env.idp, "/", person(c.groups...))
		if _, me := b.do("GET", "/v1/auth/me", nil); me["role"] != c.role {
			t.Fatalf("%v: role %v", c.groups, me["role"])
		}
		if rec, _ := b.mutate("POST", "/v1/devices/"+fixtureSerial+"/revoke", nil); rec.Code != c.revoke {
			t.Errorf("%s revoke: %d", c.role, rec.Code)
		}
		if rec, _ := b.mutate("PUT", "/v1/settings", map[string]any{"silent_after_hours": 24}); rec.Code != c.put {
			t.Errorf("%s settings: %d", c.role, rec.Code)
		}
		if rec, _ := b.mutate("POST", "/v1/exports/test", nil); rec.Code != c.test {
			t.Errorf("%s test event: %d", c.role, rec.Code)
		}
	}
}

func TestSignInRefusals(t *testing.T) {
	env := newSSOServer(t)
	refused := func(t *testing.T, b *browser, rec *httptest.ResponseRecorder, reason string) {
		t.Helper()
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/?sso_error="+reason {
			t.Fatalf("got %d %q, want refusal %q", rec.Code, rec.Header().Get("Location"), reason)
		}
		if _, ok := b.cookies["__Host-altiward_session"]; ok {
			t.Fatal("a refused sign-in got a session")
		}
	}
	start := func(t *testing.T, b *browser) string {
		rec, _ := b.do("GET", "/v1/auth/login", nil)
		return rec.Header().Get("Location")
	}
	callback := func(t *testing.T, b *browser, back string) *httptest.ResponseRecorder {
		u, _ := url.Parse(back)
		rec, _ := b.do("GET", u.RequestURI(), nil)
		return rec
	}

	t.Run("in no group with a role", func(t *testing.T) {
		b := env.browser(t)
		refused(t, b, callback(t, b, env.idp.Authorize(start(t, b), person("g-other"))), "no_role")
	})
	t.Run("named like the server or a token", func(t *testing.T) {
		// Activity would show the person as the server itself, or as a token.
		for _, name := range []string{store.ServerActor, "Altiward:server", "token:3f2a9c1b", "break-glass:3f2a9c1b"} {
			b := env.browser(t)
			claims := person("g-admin")
			claims["email"] = name
			refused(t, b, callback(t, b, env.idp.Authorize(start(t, b), claims)), "failed")
		}
		// Without an email, the actor falls back to the preferred username.
		b := env.browser(t)
		claims := person("g-admin")
		delete(claims, "email")
		claims["preferred_username"] = store.ServerActor
		refused(t, b, callback(t, b, env.idp.Authorize(start(t, b), claims)), "failed")
		entries, err := env.store.ListAudit(context.Background(), "acme", store.AuditFilter{})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range entries {
			if a.Action == store.AuditSignIn {
				t.Fatalf("recorded a sign-in as %q", a.Actor)
			}
		}
	})
	t.Run("too many groups for the claim", func(t *testing.T) {
		b := env.browser(t)
		claims := person()
		// Entra ID's overage: a pointer to Microsoft Graph instead of the groups.
		claims["groups"], claims["_claim_names"] = nil, map[string]any{"groups": "src1"}
		claims["_claim_sources"] = map[string]any{"src1": map[string]any{
			"endpoint": "https://graph.windows.net/tenant/users/user-1/getMemberObjects"}}
		refused(t, b, callback(t, b, env.idp.Authorize(start(t, b), claims)), "groups")
	})
	t.Run("state from another sign-in", func(t *testing.T) {
		b := env.browser(t)
		back := env.idp.Authorize(start(t, b), person("g-admin"))
		refused(t, b, callback(t, b, strings.Replace(back, "state=", "state=x", 1)), "failed")
	})
	t.Run("no sign-in cookie: expired, or another browser", func(t *testing.T) {
		b, other := env.browser(t), env.browser(t)
		refused(t, other, callback(t, other, env.idp.Authorize(start(t, b), person("g-admin"))), "expired")
	})
	t.Run("ID token for another sign-in", func(t *testing.T) {
		b := env.browser(t)
		claims := person("g-admin")
		claims["nonce"] = "replayed"
		refused(t, b, callback(t, b, env.idp.Authorize(start(t, b), claims)), "failed")
	})
	t.Run("ID token for another application", func(t *testing.T) {
		b := env.browser(t)
		claims := person("g-admin")
		claims["aud"] = "someone-else"
		refused(t, b, callback(t, b, env.idp.Authorize(start(t, b), claims)), "failed")
	})
	t.Run("the provider refused", func(t *testing.T) {
		b := env.browser(t)
		start(t, b)
		rec, _ := b.do("GET", "/v1/auth/callback?error=access_denied&state=x", nil)
		refused(t, b, rec, "denied")
	})
	t.Run("a next page on another site", func(t *testing.T) {
		for _, next := range []string{"//evil.example", "https://evil.example", "/\\evil.example", "/\t/evil.example", "/v1/auth/logout"} {
			if to := env.browser(t).signIn(env.idp, next, person("g-view")); to != "/" {
				t.Errorf("next %q returned to %q", next, to)
			}
		}
	})
}

// A person named like a console token would show as one in the audit log, and set off the
// break-glass alert.
func TestSingleSignOnRefusesTokenLikeNames(t *testing.T) {
	env := newSSOServer(t)
	// The SIEM's rules match the prefix in any case. A name with a colon is refused too, as
	// no email or UPN has one and every token's name does (so is one with a lookalike
	// hyphen), and so is a name with a control or format character, such as a zero-width
	// space or a byte order mark.
	names := []string{"break-glass:3f2a9c1b", "token:3f2a9c1b", "Break-Glass:3f2a9c1b", "TOKEN:3f2a9c1b", " break-glass:3f2a9c1b",
		"break\u2010glass:3f2a9c1b", "\u200bbreak-glass:3f2a9c1b", "\ufefftoken:3f2a9c1b", "jane:doe@example.com"}
	for _, name := range names {
		b := env.browser(t)
		rec, _ := b.do("GET", "/v1/auth/login", nil)
		claims := person("g-admin")
		claims["email"] = name
		back, err := url.Parse(env.idp.Authorize(rec.Header().Get("Location"), claims))
		if err != nil {
			t.Fatal(err)
		}
		rec, _ = b.do("GET", back.RequestURI(), nil)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/?sso_error=failed" {
			t.Errorf("%s: %d %q, want refusal %q", name, rec.Code, rec.Header().Get("Location"), "failed")
		}
		if _, ok := b.cookies["__Host-altiward_session"]; ok {
			t.Errorf("%s got a session", name)
		}
	}
	sessions, _ := env.store.ListConsoleSessions(context.Background(), "acme", env.now)
	entries, _ := env.store.ListAudit(context.Background(), "acme", store.AuditFilter{})
	if len(sessions) != 0 || len(entries) != 0 {
		t.Fatalf("sessions = %+v, audit = %+v", sessions, entries)
	}
	if n := strings.Count(env.log.String(), "the name could pass for the Altiward server or a console token"); n != len(names) {
		t.Errorf("want %d refusals logged, log:\n%s", len(names), env.log)
	}

	// Anyone else still signs in.
	b := env.browser(t)
	if to := b.signIn(env.idp, "/", person("g-admin")); to != "/" {
		t.Fatalf("returned to %q", to)
	}
	if _, ok := b.cookies["__Host-altiward_session"]; !ok {
		t.Fatal("a person got no session")
	}
	if entries := signIns(t, env.store); len(entries) != 1 || entries[0].Actor != "jane.doe@example.com" {
		t.Fatalf("sign-ins = %+v", entries)
	}
}

func TestSessionsExpireAndSignOut(t *testing.T) {
	env := newSSOServer(t)
	b := env.browser(t)
	b.signIn(env.idp, "/", person("g-admin"))

	// Use keeps it alive; an hour unused ends it.
	for range 3 {
		env.now = env.now.Add(50 * time.Minute)
		if rec, _ := b.do("GET", "/v1/devices", nil); rec.Code != 200 {
			t.Fatalf("active session ended: %d", rec.Code)
		}
	}
	env.now = env.now.Add(61 * time.Minute)
	if rec, _ := b.do("GET", "/v1/devices", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("idle session: %d", rec.Code)
	}

	// However busy, it ends after 12 hours.
	b.signIn(env.idp, "/", person("g-admin"))
	for elapsed := time.Duration(0); elapsed < api.SessionLifetime-30*time.Minute; elapsed += 30 * time.Minute {
		env.now = env.now.Add(30 * time.Minute)
		if rec, _ := b.do("GET", "/v1/devices", nil); rec.Code != 200 {
			t.Fatalf("ended after %s: %d", elapsed, rec.Code)
		}
	}
	env.now = env.now.Add(31 * time.Minute)
	if rec, _ := b.do("GET", "/v1/devices", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session outlived 12 hours: %d", rec.Code)
	}

	// Signing out needs the CSRF token, ends the session and is audited.
	b.signIn(env.idp, "/", person("g-admin"))
	if rec, _ := b.do("POST", "/v1/auth/logout", nil); rec.Code != 403 {
		t.Fatalf("logout without CSRF: %d", rec.Code)
	}
	stolen := *b.cookies["__Host-altiward_session"]
	if rec, _ := b.mutate("POST", "/v1/auth/logout", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if _, ok := b.cookies["__Host-altiward_session"]; ok {
		t.Fatal("logout left the cookie")
	}
	b.cookies[stolen.Name] = &stolen // a copy of the cookie is dead too
	if rec, _ := b.do("GET", "/v1/auth/me", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", rec.Code)
	}
	entries, _ := env.store.ListAudit(context.Background(), "acme", store.AuditFilter{Limit: 1})
	if entries[0].Action != store.AuditSignOut || entries[0].Actor != "jane.doe@example.com" {
		t.Fatalf("audit = %+v", entries[0])
	}
}

func TestSignOutOfTheProvider(t *testing.T) {
	env := newSSOServerWith(t, ssotest.New(t, ssotest.WithEndSession()), func(c *config.OIDC) { c.ProviderSignOut = true })
	b := env.browser(t)
	b.signIn(env.idp, "/", person("g-admin"))
	stolen := *b.cookies["__Host-altiward_session"]
	rec, out := b.mutate("POST", "/v1/auth/logout", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("logout: %d %v", rec.Code, rec.Header())
	}
	to, err := url.Parse(out["provider_sign_out_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if to.Scheme+"://"+to.Host+to.Path != env.idp.URL+"/logout" || len(to.Query()) != 2 ||
		to.Query().Get("client_id") != ssotest.ClientID ||
		to.Query().Get("post_logout_redirect_uri") != "https://altiward.example.com/signed-out" {
		t.Errorf("provider_sign_out_url = %s", to)
	}
	// The next sign-in asks for the account picker, whichever way the person signed out.
	if _, ok := b.cookies["__Host-altiward_signed_out"]; !ok {
		t.Error("logout did not set the signed-out cookie")
	}
	// Altiward's own session is over before the browser leaves for the provider.
	if _, ok := b.cookies["__Host-altiward_session"]; ok {
		t.Fatal("logout left the cookie")
	}
	b.cookies[stolen.Name] = &stolen
	if rec, _ := b.do("GET", "/v1/auth/me", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", rec.Code)
	}
	entries, _ := env.store.ListAudit(context.Background(), "acme", store.AuditFilter{Limit: 1})
	if entries[0].Action != store.AuditSignOut || entries[0].Actor != "jane.doe@example.com" {
		t.Fatalf("audit = %+v", entries[0])
	}
}

func TestSignOutStaysLocalByDefault(t *testing.T) {
	// The provider offers an end session endpoint, but the setting is off.
	env := newSSOServerWith(t, ssotest.New(t, ssotest.WithEndSession()), nil)
	b := env.browser(t)
	b.signIn(env.idp, "/", person("g-admin"))
	rec, _ := b.mutate("POST", "/v1/auth/logout", nil)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := b.do("GET", "/v1/auth/me", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", rec.Code)
	}
}

func TestSignOutStaysLocalWhenTheProviderHasNoEndpoint(t *testing.T) {
	env := newSSOServerWith(t, ssotest.New(t), func(c *config.OIDC) { c.ProviderSignOut = true })
	b := env.browser(t)
	b.signIn(env.idp, "/", person("g-admin"))
	rec, _ := b.mutate("POST", "/v1/auth/logout", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body)
	}
	if n := strings.Count(env.log.String(), "level=WARN"); n != 1 || !strings.Contains(env.log.String(), "end_session_endpoint") {
		t.Errorf("want one warning about end_session_endpoint, log:\n%s", env.log)
	}
	entries, _ := env.store.ListAudit(context.Background(), "acme", store.AuditFilter{Limit: 1})
	if entries[0].Action != store.AuditSignOut {
		t.Fatalf("audit = %+v", entries[0])
	}
}

func TestSignInAsksForTheAccountPickerOnRequestAndAfterSignOut(t *testing.T) {
	env := newSSOServer(t)
	b := env.browser(t)
	// prompt is the prompt the login redirect asks the identity provider for, and whether
	// it asks at all.
	prompt := func(target string) (string, bool) {
		t.Helper()
		rec, _ := b.do("GET", target, nil)
		if rec.Code != http.StatusFound {
			t.Fatalf("%s: %d", target, rec.Code)
		}
		to, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		_, ok := to.Query()["prompt"]
		if len(to.Query()["prompt"]) > 1 || to.Query().Has("login_hint") {
			t.Fatalf("%s: redirected with %v", target, to.Query())
		}
		return to.Query().Get("prompt"), ok
	}
	wantPrompt := func(target, want string) {
		t.Helper()
		if got, ok := prompt(target); got != want || ok != (want != "") {
			t.Fatalf("%s: prompt = %q (present %v), want %q", target, got, ok, want)
		}
	}

	wantPrompt("/v1/auth/login", "")
	wantPrompt("/v1/auth/login?select_account=1", "select_account")
	wantPrompt("/v1/auth/login?select_account=true", "")
	wantPrompt("/v1/auth/login?select_account=", "")
	// Nothing else in the request reaches the identity provider's prompt or hints.
	wantPrompt("/v1/auth/login?prompt=none", "")
	wantPrompt("/v1/auth/login?prompt=none&login_hint=x&select_account=1", "select_account")

	// A failed sign-out leaves nothing behind.
	if rec, _ := b.do("POST", "/v1/auth/logout", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("logout without a session: %d", rec.Code)
	}
	if _, ok := b.cookies["__Host-altiward_signed_out"]; ok {
		t.Fatal("a failed logout set the signed-out cookie")
	}
	wantPrompt("/v1/auth/login", "")

	b.signIn(env.idp, "/", person("g-admin"))
	if rec, _ := b.do("POST", "/v1/auth/logout", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF: %d", rec.Code)
	}
	if _, ok := b.cookies["__Host-altiward_signed_out"]; ok {
		t.Fatal("a refused logout set the signed-out cookie")
	}
	rec, _ := b.mutate("POST", "/v1/auth/logout", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	var marker *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-altiward_signed_out" {
			marker = c
		}
	}
	if marker == nil || marker.Value != "1" || marker.MaxAge != 0 || marker.Path != "/" ||
		!marker.HttpOnly || !marker.Secure || marker.SameSite != http.SameSiteLaxMode {
		t.Fatalf("signed-out cookie = %+v", marker)
	}

	// The next sign-in picks an account and uses the marker up; the one after is one click.
	wantPrompt("/v1/auth/login", "select_account")
	if _, ok := b.cookies["__Host-altiward_signed_out"]; ok {
		t.Fatal("the login left the signed-out cookie")
	}
	wantPrompt("/v1/auth/login", "")

	// Asking for the picker by hand works too, and a later sign-out sets the marker again.
	b.signIn(env.idp, "/", person("g-admin"))
	if rec, _ := b.mutate("POST", "/v1/auth/logout", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("second logout: %d", rec.Code)
	}
	if _, ok := b.cookies["__Host-altiward_signed_out"]; !ok {
		t.Fatal("the second logout did not set the signed-out cookie")
	}
	wantPrompt("/v1/auth/login?select_account=1", "select_account")
	if _, ok := b.cookies["__Host-altiward_signed_out"]; ok {
		t.Fatal("the login left the signed-out cookie")
	}
	wantPrompt("/v1/auth/login", "")

	// A token has no session to end, so signing out with one leaves no marker.
	rec, _ = do(t, env.h, "POST", "/v1/auth/logout", consoleToken, nil)
	if rec.Code != http.StatusNoContent || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("token logout: %d %v", rec.Code, rec.Result().Cookies())
	}
}

func TestSignedOutMarkerSurvivesAnUnreachableIdentityProvider(t *testing.T) {
	env := newSSOServer(t)
	b := env.browser(t)
	// The server has not met the provider yet, so it has to discover it on this login. The
	// browser carries the marker a sign-out left.
	b.cookies["__Host-altiward_signed_out"] = &http.Cookie{Name: "__Host-altiward_signed_out", Value: "1"}

	// The provider is down, so the sign-in fails and the marker is kept for the retry.
	env.idpDown = true
	rec, _ := b.do("GET", "/v1/auth/login", nil)
	if to := rec.Header().Get("Location"); rec.Code != http.StatusFound || to != "/?sso_error=unavailable" {
		t.Fatalf("login with the provider down: %d %s", rec.Code, to)
	}
	if _, ok := b.cookies["__Host-altiward_signed_out"]; !ok {
		t.Fatal("an unreachable provider used up the signed-out cookie")
	}

	// Back up: the retry asks for the picker and uses the marker up.
	env.idpDown = false
	rec, _ = b.do("GET", "/v1/auth/login", nil)
	if to := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.Contains(to, "prompt=select_account") {
		t.Fatalf("retry: %d %s", rec.Code, to)
	}
	if _, ok := b.cookies["__Host-altiward_signed_out"]; ok {
		t.Fatal("the retry left the signed-out cookie")
	}
}

func TestAdminsListAndEndConsoleSignIns(t *testing.T) {
	env := newSSOServer(t)
	admin, viewer := env.browser(t), env.browser(t)
	viewer.signIn(env.idp, "/", map[string]any{"email": "bob@example.com", "name": "Bob", "groups": []any{"g-view"}})
	env.now = env.now.Add(time.Minute)
	admin.signIn(env.idp, "/", person("g-admin"))

	// Only an admin sees who is signed in.
	if rec, _ := viewer.do("GET", "/v1/console-sessions", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer listed sessions: %d", rec.Code)
	}
	rec, out := admin.do("GET", "/v1/console-sessions", nil)
	list, _ := out["sessions"].([]any)
	if rec.Code != 200 || len(list) != 2 {
		t.Fatalf("list: %d %v", rec.Code, out)
	}
	mine, bobs := list[0].(map[string]any), list[1].(map[string]any)
	if mine["actor"] != "jane.doe@example.com" || mine["current"] != true || bobs["actor"] != "bob@example.com" ||
		bobs["current"] != false || bobs["role"] != "viewer" || bobs["name"] != "Bob" {
		t.Fatalf("sessions = %v", list)
	}
	id, _ := bobs["id"].(string)
	if len(id) != 64 || strings.Contains(rec.Body.String(), "csrf") {
		t.Fatalf("id %q, or the list leaks a CSRF token: %s", id, rec.Body)
	}

	// Ending one needs the CSRF token, signs that person out, and is audited.
	if rec, _ := admin.do("DELETE", "/v1/console-sessions/"+id, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("end without CSRF: %d", rec.Code)
	}
	if rec, _ := admin.mutate("DELETE", "/v1/console-sessions/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("end: %d", rec.Code)
	}
	if rec, _ := viewer.do("GET", "/v1/auth/me", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("ended session still works: %d", rec.Code)
	}
	if rec, _ := admin.mutate("DELETE", "/v1/console-sessions/"+id, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("ending it twice: %d", rec.Code)
	}
	if rec, _ := admin.mutate("DELETE", "/v1/console-sessions/not-hex", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("bad id: %d", rec.Code)
	}
	entries, _ := env.store.ListAudit(context.Background(), "acme", store.AuditFilter{Limit: 1})
	if e := entries[0]; e.Action != store.AuditEndConsoleSession || e.Actor != "jane.doe@example.com" ||
		e.Target != "bob@example.com" || e.Detail["name"] != "Bob" {
		t.Fatalf("audit = %+v", e)
	}

	// A break-glass token is an admin too, with no session of its own.
	rec, out = do(t, env.h, "GET", "/v1/console-sessions", consoleToken, nil)
	if list, _ := out["sessions"].([]any); rec.Code != 200 || len(list) != 1 || list[0].(map[string]any)["current"] != false {
		t.Fatalf("break-glass list: %d %v", rec.Code, out)
	}
}

func TestBreakGlassTokensAreAuditedAdmins(t *testing.T) {
	env := newSSOServer(t)
	rec, me := do(t, env.h, "GET", "/v1/auth/me", consoleToken, nil)
	actor, _ := me["actor"].(string)
	if rec.Code != 200 || me["role"] != "admin" || me["method"] != "token" || !strings.HasPrefix(actor, "break-glass:") ||
		me["csrf_token"] != nil {
		t.Fatalf("me: %d %v", rec.Code, me)
	}
	// A token needs no CSRF token: browsers don't send it by themselves.
	if rec, _ := do(t, env.h, "PUT", "/v1/settings", consoleToken, map[string]any{"silent_after_hours": 24}); rec.Code != 200 {
		t.Fatalf("settings: %d", rec.Code)
	}
	// The change, and the sign-in the token's first request recorded.
	entries, _ := env.store.ListAudit(context.Background(), "acme", store.AuditFilter{})
	if len(entries) != 2 || entries[0].Actor != actor || entries[0].Action != store.AuditChangeSettings ||
		entries[1].Actor != actor || entries[1].Action != store.AuditSignIn {
		t.Fatalf("audit = %+v", entries)
	}
	if rec, _ := do(t, env.h, "GET", "/v1/devices", "not-a-token-at-all", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rec.Code)
	}
	if rec, _ := do(t, env.h, "GET", "/v1/devices", agentToken, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("agent token: %d", rec.Code)
	}
}

func TestWithoutSSO(t *testing.T) {
	h := newServer(t)
	if rec, out := do(t, h, "GET", "/v1/auth/config", "", nil); rec.Code != 200 || out["sso"] != false {
		t.Fatalf("config: %d %v", rec.Code, out)
	}
	if rec, _ := do(t, h, "GET", "/v1/auth/login", "", nil); rec.Code != 404 {
		t.Fatalf("login: %d", rec.Code)
	}
	rec, me := do(t, h, "GET", "/v1/auth/me", consoleToken, nil)
	if actor, _ := me["actor"].(string); rec.Code != 200 || me["role"] != "admin" || !strings.HasPrefix(actor, "token:") {
		t.Fatalf("me: %d %v", rec.Code, me)
	}
	if rec, _ := do(t, h, "GET", "/v1/auth/me", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("me without a token: %d", rec.Code)
	}
}
