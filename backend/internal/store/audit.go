package store

import (
	"context"
	"maps"
	"math"
	"time"

	"github.com/Altiward/altiward/backend/internal/session"
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
	AuditSignIn            = "sign_in"       // through single sign-on
	AuditSignOut           = "sign_out"      // signing out; a session that just expires records nothing
	AuditTestExport        = "test_export"   // a test event for the SIEM: the entry is the event
	AuditRetryExports      = "retry_exports" // retrying a sink's failed exports now
	// An admin ending someone's console sign-in; the target is that person's actor.
	AuditEndConsoleSession = "end_console_session"
	// The server removing an organisation's history past the period it keeps, once per run
	// that removed anything; the target is "history".
	AuditExpireHistory = "expire_history"
	// The server removing a Mac that stopped checking in longer ago than the organisation
	// keeps history (Store.RemoveDevice); the target is the serial. The keys it revoked
	// with the Mac each have a revoke_enrollment entry, with RevokeReasonRemoved.
	AuditRemoveDevice = "remove_device"
)

// RevokeReasonRemoved is the reason in the detail of a revoke_enrollment entry the server
// wrote for a key it revoked when it removed the key's Mac.
const RevokeReasonRemoved = "removed"

// ServerActor is the actor of what the server does by itself, such as expiring history.
// No person or token can carry it: tokens are "token:" or "break-glass:" and a fingerprint,
// and single sign-on refuses anyone whose name starts with any of these prefixes.
const ServerActor = "altiward:server"

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

// withRetired returns a with "retired": true in its detail, for a revoke that retired the
// Mac. The caller's map is left as it was.
func withRetired(a AuditEntry) AuditEntry {
	detail := maps.Clone(a.Detail)
	if detail == nil {
		detail = map[string]any{}
	}
	detail["retired"] = true
	a.Detail = detail
	return a
}

// removalEntries are the Activity entries for removing d, a Mac of tenantID that stopped
// checking in: a revoke_enrollment entry for each key in revoked, then the remove_device
// entry with counts, what went with it. c and now are the run's: the period in force is
// the days between them.
func removalEntries(tenantID string, d session.Device, revoked []string, c HistoryCutoff, now time.Time,
	counts ExpiryCounts) ([]AuditEntry, error) {
	out := make([]AuditEntry, 0, len(revoked)+1)
	add := func(action, target string, detail map[string]any) error {
		id, err := NewDeviceID() // a random UUID, as for device IDs
		if err != nil {
			return err
		}
		out = append(out, AuditEntry{ID: id, TenantID: tenantID, At: now, Actor: ServerActor, Action: action,
			Target: target, Detail: detail})
		return nil
	}
	for _, deviceID := range revoked {
		if err := add(AuditRevokeEnrollment, deviceID, map[string]any{"serial": d.Serial, "reason": RevokeReasonRemoved}); err != nil {
			return nil, err
		}
	}
	detail := map[string]any{
		"last_check_in": d.CheckedInAt().UTC(),
		"days":          int(math.Round(now.Sub(c.Before).Hours() / 24)),
		"counts":        counts,
	}
	// So that SIEM content can close the finding the alert opened.
	if d.Silent() {
		detail["silent_event_id"] = d.Silence.EventID
	}
	if err := add(AuditRemoveDevice, d.Serial, detail); err != nil {
		return nil, err
	}
	return out, nil
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
}

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
