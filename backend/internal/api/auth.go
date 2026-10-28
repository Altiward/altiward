package api

// Console sign-in. A console request is judged by its bearer token if it has an
// Authorization header, otherwise by the session cookie single sign-on set. A cookie
// request that changes anything must also carry the session's CSRF token.
//
//	GET  /v1/auth/config    none            whether single sign-on is on
//	GET  /v1/auth/login     none            start signing in: redirect to the identity provider
//	                                        (?select_account=1 asks it for its account picker)
//	GET  /v1/auth/callback  none            where the identity provider sends people back
//	GET  /v1/auth/me        console         who is signed in, their role and CSRF token
//	POST /v1/auth/logout    console         end the session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/sso"
	"github.com/Altiward/altiward/backend/internal/store"
)

const (
	SessionLifetime  = 12 * time.Hour   // however busy
	SessionIdle      = time.Hour        // unused
	TokenSignInEvery = time.Hour        // how long a console token's sign-in covers its use (token_use.go)
	loginLifetime    = 10 * time.Minute // from leaving for the identity provider to coming back
	// sessionTouch is how stale a session's expiry may get before a request extends it, so
	// a busy console doesn't write on every call.
	sessionTouch = time.Minute
	csrfHeader   = "X-CSRF-Token"
)

// WithSSO turns on single sign-on through p. secureCookies marks the cookies Secure, with
// the __Host- prefix; it is false only for a console served over plain http on localhost.
func WithSSO(p *sso.Provider, secureCookies bool) Option {
	return func(s *Server) { s.sso, s.secureCookies = p, secureCookies }
}

func (s *Server) cookieName(base string) string {
	if s.secureCookies {
		return "__Host-" + base
	}
	return base
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(name), Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode,
	})
}

// console checks the caller may use a console endpoint that needs role need, and for a
// cookie session that the CSRF token matches.
func (s *Server) console(need auth.ConsoleRole, h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _, ok := s.consolePrincipal(w, r)
		if !ok {
			return
		}
		if !p.ConsoleRole.Allows(need) {
			writeError(w, http.StatusForbidden, fmt.Sprintf("this needs the %s role; you have %s", need, p.ConsoleRole))
			return
		}
		h(w, r, p)
	})
}

// consolePrincipal authenticates a console caller, writing the error if it can't. The
// session is set for a caller signed in through single sign-on.
func (s *Server) consolePrincipal(w http.ResponseWriter, r *http.Request) (auth.Principal, *store.ConsoleSession, bool) {
	if auth.HasBearer(r) || s.sso == nil {
		p, ok := s.tokens.Authenticate(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return p, nil, false
		}
		if p.Role != auth.RoleConsole {
			writeError(w, http.StatusForbidden, "token not valid for this endpoint")
			return p, nil, false
		}
		if err := s.recordTokenUse(r, p); err != nil {
			s.serverError(w, "record console token sign-in", err)
			return p, nil, false
		}
		return p, nil, true
	}
	sess, ok := s.session(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "sign in to the console")
		return auth.Principal{}, nil, false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead &&
		subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeader)), []byte(sess.CSRFToken)) != 1 {
		writeError(w, http.StatusForbidden, "missing or wrong "+csrfHeader+" header")
		return auth.Principal{}, nil, false
	}
	if now := s.now(); sess.ExpiresAt.Before(sess.EndsAt) && sess.ExpiresAt.Sub(now) < SessionIdle-sessionTouch {
		if err := s.store.ExtendConsoleSession(r.Context(), sess.TokenHash, now.Add(SessionIdle)); err != nil {
			s.log.Warn("extend console session", "err", err)
		}
	}
	return auth.Principal{
		TenantID: sess.TenantID, Role: auth.RoleConsole, Actor: sess.Actor, Name: sess.Name,
		ConsoleRole: auth.ConsoleRole(sess.Role),
	}, &sess, true
}

// session finds the live session the request's cookie names.
func (s *Server) session(r *http.Request) (store.ConsoleSession, bool) {
	c, err := r.Cookie(s.cookieName("altiward_session"))
	if err != nil || c.Value == "" {
		return store.ConsoleSession{}, false
	}
	sess, err := s.store.ConsoleSession(r.Context(), tokenHash(c.Value), s.now())
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("load console session", "err", err)
		}
		return store.ConsoleSession{}, false
	}
	return sess, true
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func (s *Server) authConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"sso": s.sso != nil})
}

// loginState is what the sign-in cookie carries between leaving for the identity provider
// and coming back.
type loginState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Next     string `json:"next"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.sso == nil {
		writeError(w, http.StatusNotFound, "single sign-on isn't set up")
		return
	}
	// The account picker is for someone who asked for it, or who has just signed out. The
	// marker that sign-out left is used up once the browser is sent to the identity
	// provider, however that sign-in ends, but it stays if the provider can't be reached.
	selectAccount := r.URL.Query().Get("select_account") == "1"
	_, signedOut := r.Cookie(s.cookieName("altiward_signed_out"))
	if signedOut == nil {
		selectAccount = true
	}
	st := loginState{State: rand.Text(), Nonce: rand.Text(), Verifier: oauth2.GenerateVerifier(), Next: safeNext(r.URL.Query().Get("next"))}
	to, err := s.sso.AuthCodeURL(r.Context(), st.State, st.Nonce, st.Verifier, selectAccount)
	if err != nil {
		s.log.Error("single sign-on unavailable", "err", err)
		signInFailed(w, r, "unavailable")
		return
	}
	if signedOut == nil {
		s.setCookie(w, "altiward_signed_out", "", -1)
	}
	b, _ := json.Marshal(st)
	s.setCookie(w, "altiward_login", base64.RawURLEncoding.EncodeToString(b), int(loginLifetime.Seconds()))
	http.Redirect(w, r, to, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	if s.sso == nil {
		writeError(w, http.StatusNotFound, "single sign-on isn't set up")
		return
	}
	var st loginState
	c, err := r.Cookie(s.cookieName("altiward_login"))
	s.setCookie(w, "altiward_login", "", -1) // one use, whatever happens
	if err == nil {
		if b, derr := base64.RawURLEncoding.DecodeString(c.Value); derr == nil {
			err = json.Unmarshal(b, &st)
		} else {
			err = derr
		}
	}
	q := r.URL.Query()
	switch {
	case err != nil || st.State == "":
		signInFailed(w, r, "expired") // took over ten minutes, or another browser
		return
	case q.Get("error") != "":
		s.log.Warn("identity provider refused sign-in", "error", q.Get("error"), "description", q.Get("error_description"))
		signInFailed(w, r, "denied")
		return
	case subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1:
		s.log.Warn("sign-in state doesn't match")
		signInFailed(w, r, "failed")
		return
	}
	id, err := s.sso.Exchange(r.Context(), q.Get("code"), st.Verifier, st.Nonce)
	if errors.Is(err, sso.ErrGroupsOverage) {
		s.log.Warn("sign-in refused: no groups claim", "actor", id.Email, "err", err)
		signInFailed(w, r, "groups")
		return
	}
	if err != nil {
		s.log.Warn("sign-in failed", "err", err)
		signInFailed(w, r, "failed")
		return
	}
	// Some identity providers let people choose their names, and one like a console
	// token's would pass for the token in the audit log.
	if strings.HasPrefix(id.Email, "token:") || strings.HasPrefix(id.Email, "break-glass:") {
		s.log.Warn("sign-in refused: the name looks like a console token", "actor", id.Email)
		signInFailed(w, r, "failed")
		return
	}
	role, ok := s.sso.RoleFor(id.Groups)
	if !ok {
		s.log.Warn("sign-in refused: no role for the person's groups", "actor", id.Email, "groups", len(id.Groups))
		signInFailed(w, r, "no_role")
		return
	}

	now := s.now()
	token := rand.Text()
	sess := store.ConsoleSession{
		TokenHash: tokenHash(token), TenantID: s.sso.Tenant(), Subject: id.Subject, Actor: id.Email, Name: id.Name,
		Role: string(role), CSRFToken: rand.Text(), CreatedAt: now, EndsAt: now.Add(SessionLifetime),
		ExpiresAt: now.Add(SessionIdle),
	}
	p := auth.Principal{TenantID: sess.TenantID, Actor: sess.Actor}
	a, err := s.auditEntry(p, store.AuditSignIn, "console", map[string]any{"role": role, "name": id.Name, "subject": id.Subject})
	if err == nil {
		err = s.store.CreateConsoleSession(r.Context(), sess, a)
	}
	if err != nil {
		s.log.Error("create console session", "err", err)
		signInFailed(w, r, "failed")
		return
	}
	s.log.Info("signed in", "tenant", sess.TenantID, "actor", sess.Actor, "role", role)
	s.setCookie(w, "altiward_session", token, 0)
	http.Redirect(w, r, st.Next, http.StatusFound)
}

// signInFailed sends the browser back to the console's sign-in page with a reason it can
// explain.
func signInFailed(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, "/?sso_error="+reason, http.StatusFound)
}

// safeNext keeps the page to return to on this site: a path, never another origin.
// Browsers drop tabs and line breaks from URLs and read a backslash as a slash, so any of
// them could turn "/\t/evil.example" into "//evil.example".
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/v1/") ||
		strings.ContainsFunc(next, func(r rune) bool { return r == '\\' || r < 0x20 || r == 0x7f }) {
		return "/"
	}
	return next
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	out := map[string]any{"actor": p.Actor, "name": p.Name, "role": p.ConsoleRole, "method": "token"}
	if sess != nil {
		out["method"], out["csrf_token"], out["ends_at"] = "sso", sess.CSRFToken, sess.EndsAt
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if auth.HasBearer(r) || s.sso == nil {
		w.WriteHeader(http.StatusNoContent) // a token has no session to end
		return
	}
	p, sess, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	s.setCookie(w, "altiward_session", "", -1)
	a, err := s.auditEntry(p, store.AuditSignOut, "console", map[string]any{})
	if err == nil {
		err = s.store.EndConsoleSession(r.Context(), p.TenantID, sess.TokenHash, a)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, "end console session", err)
		return
	}
	// Tell the next sign-in to show the account picker, so signing out isn't undone by one
	// click that signs the same account straight back in.
	s.setCookie(w, "altiward_signed_out", "1", 0)
	// The session has ended whatever happens next. With the setting on, the console sends
	// the browser to the provider to end its session too. The address comes from
	// configuration and the provider's metadata, never from the request.
	if s.sso.ProviderSignOut() {
		if to, ok := s.sso.SignOutURL(r.Context(), s.sso.SignedOutURL()); ok {
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, map[string]string{"provider_sign_out_url": to})
			return
		}
		s.log.Warn("signed out of the console only: the identity provider has no end_session_endpoint, or can't be reached")
	}
	w.WriteHeader(http.StatusNoContent)
}
