package retention

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Altiward/altiward/backend/internal/store"
)

// recordTimeout bounds the write of the entry for what a run removed, which doesn't stop
// when the run does: what was removed stays removed.
const recordTimeout = 10 * time.Second

// History removes each organisation's history past the period it keeps
// (TenantSettings.History): ended sessions with their events, events and commands, and then
// the Macs that stopped checking in before it, revoking their keys (Store.RemoveDevice). It
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
	err = h.expire(ctx, tenant, c, now, batch, &n)
	// Each batch is removed for good as it goes, so what a run removed before it failed or
	// was stopped, as at shutdown, is logged and recorded all the same.
	h.Log.Info("history expiry", "tenant", tenant, "days", days, "reason", reason, "before", c.Before,
		"events", n.Events, "sessions", n.Sessions, "commands", n.Commands, "macs", n.Macs)
	return n, errors.Join(err, h.record(ctx, tenant, now, days, reason, c, n))
}

// expire removes the tenant's history that c allows, batch by batch, and then its Macs that
// stopped checking in, adding to n. now is the run's time.
func (h *History) expire(ctx context.Context, tenant string, c store.HistoryCutoff, now time.Time, batch int,
	n *store.ExpiryCounts) error {
	for {
		got, err := h.Store.ExpireHistory(ctx, tenant, c, batch)
		n.Add(got)
		if err != nil {
			return err
		}
		if got == (store.ExpiryCounts{}) {
			break
		}
	}
	return h.removeMacs(ctx, tenant, c, now, n)
}

// removeMacs removes the tenant's Macs that stopped checking in before c.Before, adding
// what went with them to n. The store decides on each under the Mac's own locks, and keeps
// any that something still holds. One Mac that fails doesn't stop the others.
func (h *History) removeMacs(ctx context.Context, tenant string, c store.HistoryCutoff, now time.Time,
	n *store.ExpiryCounts) error {
	serials, err := h.Store.RemovalCandidates(ctx, tenant, c.Before)
	if err != nil {
		return err
	}
	var errs []error
	for _, serial := range serials {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		r, err := h.Store.RemoveDevice(ctx, tenant, serial, c, now)
		n.Add(r.Counts)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("remove %s: %w", serial, err))
		case r.Removed:
			h.Log.Info("quiet Mac removed", "tenant", tenant, "serial", serial, "revoked_keys", len(r.RevokedKeys),
				"events", r.Counts.Events, "sessions", r.Counts.Sessions, "commands", r.Counts.Commands)
		case r.Skipped != "":
			h.Log.Debug("quiet Mac kept", "tenant", tenant, "serial", serial, "reason", r.Skipped)
		}
	}
	return errors.Join(errs...)
}

// record writes one Activity entry for what a run removed for tenant, which goes to the
// SIEM like any other, so routine expiry is never silent. A run that removed nothing
// records nothing. The entry is written even once ctx is cancelled, within recordTimeout.
func (h *History) record(ctx context.Context, tenant string, now time.Time, days int, reason string,
	c store.HistoryCutoff, n store.ExpiryCounts) error {
	if n == (store.ExpiryCounts{}) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
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
