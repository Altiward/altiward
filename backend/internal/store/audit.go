package store

import (
	"context"
	"time"
)

// The audit log of console actions. Each mutating console call hands its entry to the
// store method that makes the change, which writes both in one transaction: a change is
// never made without its entry, and an entry never records a change that rolled back.
// Entries are append-only, except that PurgeAudit removes those past the retention period.

// Audit actions.
const (
	AuditRevokeSession     = "revoke_session"
	AuditRevokeDevice      = "revoke_device"
	AuditApproveEnrollment = "approve_enrollment"
	AuditRevokeEnrollment  = "revoke_enrollment"
	AuditChangeSettings    = "change_settings"
	AuditSignIn            = "sign_in"       // through single sign-on, or a console token's first request in an hour (detail.method "token")
	AuditSignOut           = "sign_out"      // signing out; a session that just expires records nothing
	AuditTestExport        = "test_export"   // a test event for the SIEM: the entry is the event
	AuditRetryExports      = "retry_exports" // retrying a sink's failed exports now
	// An admin ending someone's console sign-in; the target is that person's actor.
	AuditEndConsoleSession = "end_console_session"
)

// AuditEntry is one console action.
type AuditEntry struct {
	ID       string         `json:"id"` // lower-case UUID
	TenantID string         `json:"tenant_id"`
	At       time.Time      `json:"at"`
	Actor    string         `json:"actor"`  // who did it: a console token's fingerprint until SSO
	Action   string         `json:"action"` // one of the Audit* actions
	Target   string         `json:"target"` // the session ID, serial, device ID or "settings"
	Detail   map[string]any `json:"detail"`
	// Seq numbers entries in the order the store recorded them. It orders entries with the
	// same At and, with At, is the cursor for the next page.
	Seq int64 `json:"seq"`
}

// AuditFilter pages through the log, newest first. For the next page, pass the last
// entry's At and Seq as Before and BeforeSeq.
type AuditFilter struct {
	Before    *time.Time // only entries before this time
	BeforeSeq *int64     // with Before: also entries at Before with a lower Seq
	Limit     int        // at most MaxAuditPage
}

// MaxAuditPage caps ListAudit.
const MaxAuditPage = 500

// MinAuditRetention is the shortest retention period: Postgres refuses to delete a younger
// entry (see audit_log_append_only in migration 0001).
const MinAuditRetention = 365 * 24 * time.Hour

type Audit interface {
	// ListAudit returns the tenant's entries, newest first.
	ListAudit(ctx context.Context, tenantID string, f AuditFilter) ([]AuditEntry, error)
	// PurgeAudit removes entries, across tenants, recorded before before, and returns how
	// many. It keeps any still waiting to be exported, and Postgres keeps any younger than
	// MinAuditRetention whatever before says.
	PurgeAudit(ctx context.Context, before time.Time) (int64, error)
	// RecordAudit records a console action that changes nothing else, such as a test event
	// for the SIEM, and queues it for every sink.
	RecordAudit(ctx context.Context, a AuditEntry) error
	// RecordTokenSignIn records a, a console token's sign-in, unless the tenant already has
	// a token sign-in by a.Actor from within before a.At up to a minute after it (clocks
	// differ between instances). It returns the time of the covering entry, the newest, or
	// a.At when it recorded a. Calls for one actor run one at a time, so only one of
	// several at once records.
	RecordTokenSignIn(ctx context.Context, a AuditEntry, within time.Duration) (time.Time, error)
}

// tokenSignInSkew is how far ahead of a sign-in an entry can be and still cover it.
const tokenSignInSkew = time.Minute

func auditLimit(n int) int {
	if n <= 0 || n > MaxAuditPage {
		return MaxAuditPage
	}
	return n
}

func (a *AuditEntry) normalize() {
	if a.Detail == nil {
		a.Detail = map[string]any{}
	}
}
