package monitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Altiward/altiward/backend/internal/store"
)

// snapshotWithin is how recently a Mac must have checked in to be snapshotted.
const snapshotWithin = 24 * time.Hour

// AdminGroups sends each Mac's admin group to the SIEM once a day, as an agent.admin_group
// snapshot, so that a day's records alone say who was in a Mac's group. The store decides
// whether a Mac is still due one when it raises it, and a snapshot's ID names its day, so
// several API replicas sweeping at once store each snapshot once.
type AdminGroups struct {
	Store store.Store
	Log   *slog.Logger
	Now   func() time.Time
}

// Run sweeps firstDelay after it starts, then every interval, until ctx is cancelled. The
// first sweep waits because, during an update, an older revision can run beside this one
// and mark the new event type as exported without sending it (it doesn't know the type).
// The wait gives the update time to finish, so the first snapshots aren't lost that way.
func (a *AdminGroups) Run(ctx context.Context, interval, firstDelay time.Duration) {
	timer := time.NewTimer(firstDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if _, err := a.Sweep(ctx); err != nil && ctx.Err() == nil {
			a.Log.Warn("admin group snapshot sweep failed", "err", err)
		}
		timer.Reset(interval)
	}
}

// Sweep raises the snapshots that are due and returns how many were stored. An error with
// one Mac doesn't stop the others; the next sweep retries it.
func (a *AdminGroups) Sweep(ctx context.Context) (raised int, err error) {
	now := a.Now()
	macs, err := a.Store.AdminGroupSnapshotCandidates(ctx, now.Add(-snapshotWithin))
	if err != nil {
		return 0, err
	}
	var errs []error
	for _, mac := range macs {
		if ctx.Err() != nil {
			break
		}
		ok, err := a.Store.RaiseAdminGroupSnapshot(ctx, mac.TenantID, mac.Serial, now)
		if err != nil {
			errs = append(errs, fmt.Errorf("device %s/%s: %w", mac.TenantID, mac.Serial, err))
			continue
		}
		if ok {
			raised++
		}
	}
	if raised > 0 {
		a.Log.Info("admin group snapshots", "raised", raised)
	}
	return raised, errors.Join(errs...)
}
