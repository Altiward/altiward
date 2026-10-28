// Package store persists events, the sessions and devices derived from them, and the
// outbox that feeds SIEM exporters. Ingest writes all four in one transaction so an
// event is never stored without its session update or its export obligations. Console
// actions are queued for export in the transaction that records them, the same way.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/session"
)

var ErrNotFound = errors.New("not found")

// ErrSessionOwnerConflict rejects the entire ingestion batch without acknowledging it.
var ErrSessionOwnerConflict = session.ErrOwnerConflict

// IngestResult lists event IDs by outcome. Duplicates are events already stored,
// typically an agent retrying after a lost response; they are not re-applied. Accepted and
// Duplicate answer the agent, so they list only the events it sent, never those the
// server raised while storing them.
type IngestResult struct {
	Accepted  []string
	Duplicate []string
	// RaisedIDTaken lists the IDs of events the server raised but didn't store, because an
	// event of another type or for another Mac already had the ID. The IDs derive from the
	// installation's secret, so only tampering does this. Never sent to the agent.
	RaisedIDTaken []string
}

// StoredEvent is an event as received.
type StoredEvent struct {
	event.Event
	ReceivedAt time.Time `json:"received_at"`
}

type SessionFilter struct {
	DeviceSerial string
	LocalUser    string
	OpenOnly     bool
	Since, Until *time.Time // on started_at
	Limit        int
}

// ExportItem is one event, or one console action, owed to one SIEM sink.
type ExportItem struct {
	ID       int64
	TenantID string
	Sink     string
	Attempts int
	Event    StoredEvent // zero when Audit is set
	Audit    *AuditEntry // a console action
}

type Store interface {
	Credentials
	Installations
	Coverage
	Commands
	Audit
	ConsoleSessions
	MDM

	// Ingest stores events in order, folding each new one into its session and device
	// and queueing it for every configured export sink. A session ownership conflict
	// rejects the entire batch atomically, including its events and export obligations.
	Ingest(ctx context.Context, tenantID string, events []event.Event, receivedAt time.Time) (IngestResult, error)

	ListSessions(ctx context.Context, tenantID string, f SessionFilter) ([]session.Session, error)
	// ReportSessions returns every session that is open or started at or after since, with
	// no page limit, for the overview to fold.
	ReportSessions(ctx context.Context, tenantID string, since time.Time) ([]session.Session, error)
	// GetSession returns the session and its events oldest first.
	GetSession(ctx context.Context, tenantID, sessionID string) (session.Session, []StoredEvent, error)
	ListDevices(ctx context.Context, tenantID string) ([]Device, error)
	// SilenceCandidates returns devices across all tenants that were last seen at or
	// before seenBefore, or that have an agent.silent alert open.
	SilenceCandidates(ctx context.Context, seenBefore time.Time) ([]Device, error)

	// AdminGroupSnapshotCandidates returns the Macs, across all tenants, that are due a daily
	// snapshot of their admin group: not retired, with a group reported, and checked in
	// since the given time.
	AdminGroupSnapshotCandidates(ctx context.Context, since time.Time) ([]DeviceRef, error)
	// RaiseAdminGroupSnapshot stores the day's agent.admin_group snapshot of the group last
	// reported for the Mac, and queues it for every sink, unless it is stored already. It
	// reads the Mac's row under the tenant's ingest lock, so a change can't slip in between,
	// and takes the day from the database's clock, so a server with a fast clock can't take
	// tomorrow's ID. now is the event's time; the Mac must have checked in within 24 hours
	// of it. It returns false when nothing was stored: the Mac is unknown, retired or
	// quiet, has no group reported, or has today's snapshot already.
	RaiseAdminGroupSnapshot(ctx context.Context, tenantID, serial string, now time.Time) (bool, error)

	// BackfillAdminGroups raises, once, the agent.admin_group events that the health
	// readings stored before Installation().AdminGroupStartedAt would have raised, and
	// returns how many it stored. It walks each Mac's readings in arrival order (received
	// time, then event ID) with the rules ingest uses, so it stores what ingest would have.
	// Each event's ID derives from its reading, so one already stored (a repeat, or a Mac
	// that ingest has covered since) is left alone and not counted. It never changes the
	// admin group a Mac last reported, which ingest owns. It records now as
	// Installation().AdminGroupBackfilledAt once every Mac is done, and returns 0 at once
	// when that is set. After an error nothing is recorded, so a later call walks again.
	BackfillAdminGroups(ctx context.Context, now time.Time) (raised int, err error)

	// ClaimExports leases up to limit due items for sink so concurrent workers don't double-send.
	ClaimExports(ctx context.Context, sink string, limit int, lease time.Duration, now time.Time) ([]ExportItem, error)
	// CompleteExports removes delivered items and records deliveredAt as their sinks' last
	// delivery for each tenant, unless a later one is already recorded.
	CompleteExports(ctx context.Context, ids []int64, deliveredAt time.Time) error
	RetryExports(ctx context.Context, ids []int64, lastError string, retryAt time.Time) error
	// ExportStatus is the tenant's share of each sink's queue, by sink, with when the sink
	// last delivered for the tenant. A sink with nothing waiting and nothing delivered is
	// left out.
	ExportStatus(ctx context.Context, tenantID string) ([]ExportBacklog, error)
	// RetryExportsNow makes the tenant's items waiting for sink due at now, instead of when
	// their backoff ends, records a with it, and returns how many it changed.
	RetryExportsNow(ctx context.Context, tenantID, sink string, now time.Time, a AuditEntry) (int64, error)

	Close()
}

// DeviceRef names a Mac.
type DeviceRef struct {
	TenantID, Serial string
}

// MaxSessionPage caps ListSessions.
const MaxSessionPage = 500

func clampLimit(n int) int {
	if n <= 0 || n > MaxSessionPage {
		return MaxSessionPage
	}
	return n
}
