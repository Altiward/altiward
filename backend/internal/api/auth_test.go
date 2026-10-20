package api_test

import (
	"bytes"
	"context"
	"encoding/json"
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
}

// newSSOServer starts the server; each of more adds an option made from its store.
func newSSOServer(t *testing.T, more ...func(*store.Memory) api.Option) *ssoEnv {
	t.Helper()
	env := &ssoEnv{idp: ssotest.New(t), store: store.NewMemory(nil), now: serverNow(t)}
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
	provider := sso.New(cfg, env.idp.Client(), clock)
	opts := []api.Option{api.WithSSO(provider, true)}
	for _, m := range more {
		opts = append(opts, m(env.store))
	}
	env.h = api.New(env.store, tokens, slog.New(slog.NewTextHandler(io.Discard, nil)), clock, opts...)
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
	entries, _ := env.store.ListAudit(context.Background(), "acme", store.AuditFilter{})
	if len(entries) != 1 || entries[0].Actor != actor {
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
