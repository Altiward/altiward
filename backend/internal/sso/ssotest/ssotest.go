// Package ssotest is a fake OIDC identity provider for tests: discovery, signing keys, an
// authorize step tests drive by hand, and a token endpoint that checks PKCE.
package ssotest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const ClientID = "altiward-console"

// Provider is a running fake identity provider.
type Provider struct {
	*httptest.Server
	t   *testing.T
	key *rsa.PrivateKey
	// Now stamps ID tokens; tests move it to expire them.
	Now func() time.Time

	endSession bool

	mu    sync.Mutex
	codes map[string]grant
}

type grant struct {
	claims    map[string]any
	challenge string
	redirect  string
}

// Option changes what the fake provider offers.
type Option func(*Provider)

// WithEndSession adds an end_session_endpoint to the discovery document, as Entra ID has.
func WithEndSession() Option { return func(p *Provider) { p.endSession = true } }

// New starts a provider, stopped when the test ends.
func New(t *testing.T, opts ...Option) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{t: t, key: key, Now: time.Now, codes: map[string]grant{}}
	for _, o := range opts {
		o(p)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer": p.URL, "authorization_endpoint": p.URL + "/authorize", "token_endpoint": p.URL + "/token",
			"jwks_uri": p.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		}
		if p.endSession {
			doc["end_session_endpoint"] = p.URL + "/logout"
		}
		writeJSON(w, doc)
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", p.token)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// Authorize stands for the person signing in at the provider: it takes the authorize URL
// the server redirected the browser to, and returns the callback URL the provider would
// send the browser back to, with a code whose ID token carries claims (plus the standard
// ones). Claims with a nil value are left out.
func (p *Provider) Authorize(authURL string, claims map[string]any) string {
	p.t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		p.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		p.t.Fatalf("authorize request: %v", q)
	}
	all := map[string]any{"iss": p.URL, "aud": ClientID, "sub": "user-1", "nonce": q.Get("nonce")}
	for k, v := range claims {
		if v == nil {
			delete(all, k)
		} else {
			all[k] = v
		}
	}
	code := rand.Text()
	p.mu.Lock()
	p.codes[code] = grant{claims: all, challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	p.mu.Unlock()
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		p.t.Fatal(err)
	}
	back.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
	return back.String()
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	g, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case !ok:
		writeOAuthError(w, "unknown or used code")
		return
	case base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge:
		writeOAuthError(w, "PKCE verifier doesn't match")
		return
	case r.PostForm.Get("redirect_uri") != g.redirect:
		writeOAuthError(w, "redirect_uri doesn't match")
		return
	}
	now := p.Now()
	claims := map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	for k, v := range g.claims {
		claims[k] = v
	}
	writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": p.Sign(claims)})
}

// Sign makes a JWT with the provider's key.
func (p *Provider) Sign(claims map[string]any) string {
	p.t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		p.t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		p.t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		p.t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		p.t.Fatal(err)
	}
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": desc})
}
