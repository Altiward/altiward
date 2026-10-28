package retention

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Altiward/altiward/backend/internal/store"
)

// History removes each organisation's history past the period it keeps
// (TenantSettings.History): ended sessions with their events, events and commands. It
// never removes what a SIEM is still waiting for or, under the default period, anything
// received before the SIEM's coverage starts, and the stores never remove anything from
// the last 90 days. It does nothing until the admin group backfill has finished, since the
// backfill reads the stored health readings that expiry removes.
type History struct {
	Store store.Store
	// Sinks are the SIEM sinks configured; with any, a SIEM is connected.
	Sinks     []string
	Log       *slog.Logger
	Now       func() time.Time
	BatchSize int // rows per statement; 1000 when 0
}

// Run purges, then waits interval, until ctx is cancelled. Several replicas purging at
// once is harmless: each removes what the others haven't, and each records only what it
// removed itself.
func (h *History) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := h.Purge(ctx); err != nil && ctx.Err() == nil {
			h.Log.Warn("history expiry failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Purge removes, for every organisation, the history that is due, and returns how much it
// removed in all. A failure for one organisation doesn't stop the others.
func (h *History) Purge(ctx context.Context) (store.ExpiryCounts, error) {
	var total store.ExpiryCounts
	in, err := h.Store.Installation(ctx)
	if err != nil {
		return total, err
	}
	if in.AdminGroupBackfilledAt == nil {
		h.Log.Info("history expiry waits until the admin group from stored readings has been sent")
		return total, nil
	}
	tenants, err := h.Store.Tenants(ctx)
	if err != nil {
		return total, err
	}
	var errs []error
	for _, tenant := range tenants {
		n, err := h.purge(ctx, tenant)
		total.Add(n)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", tenant, err))
			if ctx.Err() != nil {
				break
			}
		}
	}
	return total, errors.Join(errs...)
}

// purge removes one organisation's history that is due, and records what it removed.
func (h *History) purge(ctx context.Context, tenant string) (store.ExpiryCounts, error) {
	var n store.ExpiryCounts
	settings, err := h.Store.TenantSettings(ctx, tenant)
	if err != nil {
		return n, err
	}
	days, reason := settings.History(len(h.Sinks) > 0)
	if days == 0 {
		return n, nil // kept for good
	}
	days = max(days, store.MinHistoryDays) // the settings refuse less; the stores floor it too
	now := h.Now()
	c := store.HistoryCutoff{Before: now.AddDate(0, 0, -days)}
	if reason == store.HistoryReasonDefaultSIEM {
		covered, err := h.Store.SinkCoverage(ctx, h.Sinks)
		if err != nil {
			return n, err
		}
		if covered == nil {
			// A SIEM is connected but nothing says since when, so nothing is known to have
			// reached it: keep everything rather than guess.
			h.Log.Warn("history kept: no record of when the SIEM was connected", "tenant", tenant, "sinks", h.Sinks)
			return n, nil
		}
		c.NotBefore = covered
	}
	batch := h.BatchSize
	if batch <= 0 {
		batch = 1000
	}
	for {
		got, err := h.Store.ExpireHistory(ctx, tenant, c, batch)
		n.Add(got)
		if err != nil {
			return n, errors.Join(err, h.record(ctx, tenant, now, days, reason, c, n))
		}
		if got == (store.ExpiryCounts{}) {
			break
		}
	}
	// Removing whole Macs that have stopped checking in comes here, adding to n.Macs.
	h.Log.Info("history expiry", "tenant", tenant, "days", days, "reason", reason, "before", c.Before,
		"events", n.Events, "sessions", n.Sessions, "commands", n.Commands, "macs", n.Macs)
	return n, h.record(ctx, tenant, now, days, reason, c, n)
}

// record writes one Activity entry for what a run removed for tenant, which goes to the
// SIEM like any other, so routine expiry is never silent. A run that removed nothing
// records nothing.
func (h *History) record(ctx context.Context, tenant string, now time.Time, days int, reason string,
	c store.HistoryCutoff, n store.ExpiryCounts) error {
	if n == (store.ExpiryCounts{}) {
		return nil
	}
	id, err := store.NewDeviceID() // a random UUID, as for device IDs
	if err != nil {
		return err
	}
	detail := map[string]any{"before": c.Before.UTC(), "days": days, "reason": reason, "counts": n}
	if c.NotBefore != nil {
		detail["held_before"] = c.NotBefore.UTC()
	}
	if err := h.Store.RecordAudit(ctx, store.AuditEntry{ID: id, TenantID: tenant, At: now, Actor: store.ServerActor,
		Action: store.AuditExpireHistory, Target: "history", Detail: detail}); err != nil {
		return fmt.Errorf("record history expiry: %w", err)
	}
	return nil
}
