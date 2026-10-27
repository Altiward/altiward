// Package sso signs people in to the console through the deployment's identity provider
// with the OIDC authorization code flow and PKCE. go-oidc does discovery, key
// rotation and the ID token's signature, issuer, audience and expiry checks; this package
// adds the nonce check, reads who the person is and maps their groups to a console role.
package sso

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/config"
)

// CallbackPath is where the identity provider sends people back to.
const CallbackPath = "/v1/auth/callback"

// SignedOutPath is the console page the identity provider sends people back to after it
// signs them out. It must be registered with the provider as a sign-out redirect URI.
const SignedOutPath = "/signed-out"

// Identity is who signed in, from a verified ID token.
type Identity struct {
	Subject string
	Email   string // email, else preferred_username, else upn, else the subject
	Name    string
	Groups  []string
}

// ErrGroupsOverage is Entra ID leaving the groups claim out because the person is in too
// many groups. The app registration must limit the claim to assigned groups, or use roles.
var ErrGroupsOverage = errors.New("the identity provider left the groups claim out because the person is in too many groups")

// Provider is the configured identity provider. It discovers the provider's endpoints on
// first use, and again after a failure, so the server starts while the provider is down.
type Provider struct {
	cfg    config.OIDC
	client *http.Client
	now    func() time.Time

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	// endSession is the provider's end_session_endpoint; empty if it has none.
	endSession string
}

func New(cfg config.OIDC, client *http.Client, now func() time.Time) *Provider {
	return &Provider{cfg: cfg, client: client, now: now}
}

// Tenant is the Altiward tenant everyone who signs in belongs to.
func (p *Provider) Tenant() string { return p.cfg.Tenant }

// RedirectURL is the callback the identity provider must allow.
func (p *Provider) RedirectURL() string { return p.cfg.ConsoleURL + CallbackPath }

// discover returns the OAuth configuration and ID token verifier, fetching the provider's
// metadata the first time.
func (p *Provider) discover(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.oauth != nil {
		return p.oauth, p.verifier, nil
	}
	// The provider keeps the client, not ctx, for fetching signing keys later.
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, p.client), p.cfg.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("discover %s: %w", p.cfg.Issuer, err)
	}
	p.oauth = &oauth2.Config{
		ClientID: p.cfg.ClientID, ClientSecret: p.cfg.ClientSecret, Endpoint: provider.Endpoint(),
		RedirectURL: p.RedirectURL(), Scopes: p.cfg.Scopes,
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, nil, fmt.Errorf("read %s's metadata: %w", p.cfg.Issuer, err)
	}
	p.endSession = meta.EndSession
	p.verifier = provider.Verifier(&oidc.Config{ClientID: p.cfg.ClientID, Now: p.now})
	return p.oauth, p.verifier, nil
}

// SignedOutURL is where the identity provider sends people back to after it signs them out.
func (p *Provider) SignedOutURL() string { return p.cfg.ConsoleURL + SignedOutPath }

// ProviderSignOut is whether signing out of the console also signs the person out of the
// identity provider (ALTIWARD_OIDC_PROVIDER_SIGN_OUT).
func (p *Provider) ProviderSignOut() bool { return p.cfg.ProviderSignOut }

// SignOutURL is where to send the browser to sign the person out of the identity
// provider, which then returns it to postLogout. It is false if the provider has no
// end_session_endpoint, or can't be reached.
func (p *Provider) SignOutURL(ctx context.Context, postLogout string) (string, bool) {
	if _, _, err := p.discover(ctx); err != nil {
		return "", false
	}
	p.mu.Lock()
	endSession := p.endSession
	p.mu.Unlock()
	u, err := url.Parse(endSession)
	if endSession == "" || err != nil {
		return "", false
	}
	u.RawQuery = url.Values{"client_id": {p.cfg.ClientID}, "post_logout_redirect_uri": {postLogout}}.Encode()
	return u.String(), true
}

// AuthCodeURL is where to send the browser to sign in; selectAccount asks the provider to
// show its account picker instead of reusing the browser's signed-in account.
func (p *Provider) AuthCodeURL(ctx context.Context, state, nonce, verifier string, selectAccount bool) (string, error) {
	oc, _, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if selectAccount {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "select_account"))
	}
	return oc.AuthCodeURL(state, opts...), nil
}

// Exchange redeems the code the provider sent back and verifies the ID token it returns.
func (p *Provider) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	oc, v, err := p.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	ctx = oidc.ClientContext(ctx, p.client)
	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("redeem code: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Identity{}, errors.New("the token response has no ID token")
	}
	idt, err := v.Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("verify ID token: %w", err)
	}
	if idt.Nonce != nonce {
		return Identity{}, errors.New("the ID token's nonce doesn't match the sign-in")
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("read ID token claims: %w", err)
	}
	id := Identity{Subject: idt.Subject, Name: claimString(claims, "name")}
	for _, k := range []string{"email", "preferred_username", "upn"} {
		if id.Email = claimString(claims, k); id.Email != "" {
			break
		}
	}
	if id.Email == "" {
		id.Email = idt.Subject
	}
	switch g := claims[p.cfg.GroupsClaim].(type) {
	case []any:
		for _, v := range g {
			if s, ok := v.(string); ok {
				id.Groups = append(id.Groups, s)
			}
		}
	case string:
		id.Groups = []string{g}
	case nil:
		if names, ok := claims["_claim_names"].(map[string]any); ok && names[p.cfg.GroupsClaim] != nil {
			return id, ErrGroupsOverage
		}
	}
	return id, nil
}

// RoleFor is the highest role any of groups maps to; ok is false if none does.
func (p *Provider) RoleFor(groups []string) (role auth.ConsoleRole, ok bool) {
	for _, r := range []struct {
		role   auth.ConsoleRole
		groups []string
	}{{auth.Admin, p.cfg.AdminGroups}, {auth.Operator, p.cfg.OperatorGroups}, {auth.Viewer, p.cfg.ViewerGroups}} {
		for _, g := range groups {
			if slices.Contains(r.groups, g) {
				return r.role, true
			}
		}
	}
	return "", false
}

func claimString(claims map[string]any, key string) string {
	s, _ := claims[key].(string)
	return s
}
