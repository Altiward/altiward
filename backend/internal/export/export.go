// Package export drains the export outbox into SIEM sinks. Delivery is
// at-least-once: an item is deleted only after its sink accepts it, and a failed
// batch is retried with exponential backoff, so events survive SIEM outages. The outbox
// holds console actions as well as agent events.
package export

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/Altiward/altiward/backend/internal/ocsf"
	"github.com/Altiward/altiward/backend/internal/store"
)

// Record is one event, or one console action, ready for a sink. An event can make more
// than one record (ocsf.Map), each with its own UID.
type Record struct {
	TenantID string
	Event    store.StoredEvent // zero when Audit is set
	Audit    *store.AuditEntry
	OCSF     ocsf.Record
}

// Time is when it happened.
func (r Record) Time() time.Time {
	if r.Audit != nil {
		return r.Audit.At
	}
	return r.Event.Timestamp
}

// UID is the audit entry's ID, or the record's OCSF metadata.uid: the event ID, or one
// derived from it for an event's further records.
func (r Record) UID() string {
	if r.Audit != nil {
		return r.Audit.ID
	}
	if uid := ocsf.UID(r.OCSF); uid != "" {
		return uid
	}
	return r.Event.EventID
}

// Type is the event type, or "console." and the action.
func (r Record) Type() string {
	if r.Audit != nil {
		return ocsf.AuditEventType(*r.Audit)
	}
	return string(r.Event.Type)
}

// Host names the Mac an event came from; console actions come from the server.
func (r Record) Host() string {
	if r.Audit != nil {
		return "altiward"
	}
	return r.Event.Device.Serial
}

// Sink delivers a batch; an error means none of it may be assumed delivered.
type Sink interface {
	Name() string
	Send(ctx context.Context, records []Record) error
}

type Worker struct {
	Store     store.Store
	Sinks     []Sink
	BatchSize int
	Lease     time.Duration
	Log       *slog.Logger
	Now       func() time.Time
}

// Backoff after the nth consecutive failure (n starts at 1): 30s doubling, capped at an hour.
func Backoff(n int) time.Duration {
	d := 30 * time.Second * time.Duration(math.Pow(2, float64(min(n-1, 7))))
	return min(d, time.Hour)
}

// Run drains every sink, then waits interval, until ctx is cancelled.
func (w *Worker) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		for _, s := range w.Sinks {
			if _, err := w.Drain(ctx, s); err != nil && ctx.Err() == nil {
				w.Log.Warn("export failed", "sink", s.Name(), "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Drain sends due items to one sink until none are left or a send fails.
func (w *Worker) Drain(ctx context.Context, s Sink) (sent int, err error) {
	for ctx.Err() == nil {
		now := w.Now()
		items, err := w.Store.ClaimExports(ctx, s.Name(), w.BatchSize, w.Lease, now)
		if err != nil || len(items) == 0 {
			return sent, err
		}
		var records []Record
		var ids []int64
		maxAttempts := 0
		for _, it := range items {
			ids = append(ids, it.ID)
			maxAttempts = max(maxAttempts, it.Attempts)
			if it.Audit != nil {
				records = append(records, Record{TenantID: it.TenantID, Audit: it.Audit, OCSF: ocsf.MapAudit(*it.Audit)})
			} else {
				for _, r := range ocsf.Map(it.Event, it.TenantID) {
					records = append(records, Record{TenantID: it.TenantID, Event: it.Event, OCSF: r})
				}
			}
		}
		if len(records) > 0 {
			if err := s.Send(ctx, records); err != nil {
				retryAt := now.Add(Backoff(maxAttempts + 1))
				if rerr := w.Store.RetryExports(ctx, ids, err.Error(), retryAt); rerr != nil {
					w.Log.Error("could not reschedule exports", "sink", s.Name(), "err", rerr)
				}
				return sent, err
			}
		}
		// Items that map to nothing (e.g. agent.health) are complete as well.
		if err := w.Store.CompleteExports(ctx, ids, w.Now()); err != nil {
			return sent, err
		}
		sent += len(records)
	}
	return sent, ctx.Err()
}
