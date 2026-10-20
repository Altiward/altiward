// Package retention removes audit entries past the retention period a deployment sets with
// ALTIWARD_AUDIT_RETENTION_DAYS. With no period set it isn't started, and entries stay.
package retention

import (
	"context"
	"log/slog"
	"time"

	"github.com/Altiward/altiward/backend/internal/store"
)

// Audit purges the audit log of entries older than After.
type Audit struct {
	Store store.Store
	After time.Duration // at least store.MinAuditRetention
	Log   *slog.Logger
	Now   func() time.Time
}

// Run purges, then waits interval, until ctx is cancelled. Several replicas purging at
// once is harmless: each deletes what the others haven't.
func (a *Audit) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := a.Purge(ctx); err != nil && ctx.Err() == nil {
			a.Log.Warn("audit retention failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Purge removes the entries that are due and logs how many. Entries still waiting to be
// exported stay until a later run.
func (a *Audit) Purge(ctx context.Context) (int64, error) {
	after := max(a.After, store.MinAuditRetention)
	n, err := a.Store.PurgeAudit(ctx, a.Now().Add(-after))
	if err == nil && n > 0 {
		a.Log.Info("removed audit entries past retention", "count", n, "retention_days", int(after.Hours()/24))
	}
	return n, err
}
