// Package auth resolves bearer tokens to a tenant and role.
//
// Static tokens from configuration: per-tenant enrollment tokens, which agents use
// only to enroll, and console/API tokens, which have the admin role. With single sign-on
// console tokens are break-glass logins, and people sign in to the console with
// a session cookie instead (backend/internal/api). Tokens are kept only as SHA-256
// digests. Enrolled agents sign their requests instead (device.go).
package auth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

type Role string

const (
	RoleAgent   Role = "agent"
	RoleConsole Role = "console"
)

// ConsoleRole is what a console caller may do. Each role includes the ones below.
type ConsoleRole string

const (
	Viewer   ConsoleRole = "viewer"   // read everything
	Operator ConsoleRole = "operator" // also revoke admin rights
	Admin    ConsoleRole = "admin"    // also approve and revoke enrollments, change settings
)

var roleRank = map[ConsoleRole]int{Viewer: 1, Operator: 2, Admin: 3}

// Allows reports whether r includes need. An unknown role allows nothing.
func (r ConsoleRole) Allows(need ConsoleRole) bool {
	return roleRank[r] > 0 && roleRank[r] >= roleRank[need]
}

// Valid reports whether r is one of the three roles.
func (r ConsoleRole) Valid() bool { return roleRank[r] > 0 }

type Principal struct {
	TenantID string
	Role     Role
	// Set for signed agent requests: the enrolled Mac making the request.
	DeviceID string
	Serial   string
	// Actor names a console caller in the audit log. For a token it is "token:" and the
	// first 8 hex digits of the token's SHA-256, which tells tokens apart without revealing
	// them, or "break-glass:" and the same digits once single sign-on is on. For a person
	// signed in through single sign-on it is their email.
	Actor string
	// For console callers: what they may do. Tokens are admins.
	ConsoleRole ConsoleRole
	// For a person signed in through single sign-on: their display name, if the identity
	// provider sent one.
	Name string
}

type Tokens struct {
	byDigest map[[32]byte]Principal
}

// Parse builds a token table from "tenant=token,tenant=token" lists per role.
func Parse(agentTokens, consoleTokens string) (*Tokens, error) {
	t := &Tokens{byDigest: map[[32]byte]Principal{}}
	for role, list := range map[Role]string{RoleAgent: agentTokens, RoleConsole: consoleTokens} {
		for _, entry := range strings.Split(list, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			tenant, token, ok := strings.Cut(entry, "=")
			if !ok || tenant == "" || len(token) < 16 {
				return nil, fmt.Errorf("invalid %s token entry %q: want tenant=token with a token of at least 16 characters", role, redact(entry))
			}
			digest := sha256.Sum256([]byte(token))
			if _, dup := t.byDigest[digest]; dup {
				return nil, errors.New("the same token is configured twice")
			}
			p := Principal{TenantID: tenant, Role: role, Actor: fmt.Sprintf("token:%x", digest[:4])}
			if role == RoleConsole {
				p.ConsoleRole = Admin
			}
			t.byDigest[digest] = p
		}
	}
	return t, nil
}

// BreakGlass marks console tokens as break-glass logins, for when single sign-on is on:
// their audit actor becomes "break-glass:" and the fingerprint.
func (t *Tokens) BreakGlass() {
	for d, p := range t.byDigest {
		if p.Role == RoleConsole {
			p.Actor = "break-glass:" + strings.TrimPrefix(p.Actor, "token:")
			t.byDigest[d] = p
		}
	}
}

// HasBearer reports whether the request carries an Authorization header, which decides
// whether it is judged as a token request or a session-cookie one.
func HasBearer(r *http.Request) bool { return r.Header.Get("Authorization") != "" }

// Authenticate returns the principal for the request's bearer token.
// Comparing fixed-size digests by map lookup avoids timing leaks on the token itself.
func (t *Tokens) Authenticate(r *http.Request) (Principal, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return Principal{}, false
	}
	p, ok := t.byDigest[sha256.Sum256([]byte(token))]
	return p, ok
}

// Principals lists every configured token's principal (tenant, role and actor
// fingerprint), never the tokens, ordered by tenant, role and actor.
func (t *Tokens) Principals() []Principal {
	out := make([]Principal, 0, len(t.byDigest))
	for _, p := range t.byDigest {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.TenantID != b.TenantID {
			return a.TenantID < b.TenantID
		}
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		return a.Actor < b.Actor
	})
	return out
}

// redact keeps the tenant name for the error message and never any part of a token.
func redact(entry string) string {
	tenant, _, ok := strings.Cut(entry, "=")
	if !ok {
		return "…"
	}
	return tenant + "=…"
}
