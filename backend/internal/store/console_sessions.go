package store

import (
	"context"
	"time"
)

// ConsoleSession is a person signed in to the console through single sign-on.
type ConsoleSession struct {
	TokenHash []byte // SHA-256 of the token in the session cookie
	TenantID  string
	Subject   string // the identity provider's subject
	Actor     string // email, as audit entries name them
	Name      string
	Role      string // auth.ConsoleRole
	CSRFToken string
	CreatedAt time.Time
	EndsAt    time.Time // when it ends however busy it is
	ExpiresAt time.Time // EndsAt, or sooner if it goes unused
}

type ConsoleSessions interface {
	// CreateConsoleSession stores s and records a, its sign-in, in one transaction. It also
	// removes sessions that expired before s was created.
	CreateConsoleSession(ctx context.Context, s ConsoleSession, a AuditEntry) error
	// ConsoleSession returns the session for tokenHash, or ErrNotFound if there is none or
	// it expired at or before now.
	ConsoleSession(ctx context.Context, tokenHash []byte, now time.Time) (ConsoleSession, error)
	// ExtendConsoleSession moves the session's expiry to expiresAt, never past its EndsAt.
	ExtendConsoleSession(ctx context.Context, tokenHash []byte, expiresAt time.Time) error
	// EndConsoleSession removes the tenant's session and records a, its sign-out or an
	// admin ending it, in one transaction; ErrNotFound if it was already gone or belongs
	// to another tenant, and then nothing is recorded.
	EndConsoleSession(ctx context.Context, tenantID string, tokenHash []byte, a AuditEntry) error
	// ListConsoleSessions returns the tenant's sessions that haven't expired at now,
	// newest first.
	ListConsoleSessions(ctx context.Context, tenantID string, now time.Time) ([]ConsoleSession, error)
}
