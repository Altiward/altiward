// Package monitor raises the events only the backend can notice. A Mac whose agent was
// removed can't report anything, so the backend watches for the silence and raises
// agent.silent itself, then agent.silent with state resumed when the Mac checks in again.
//
// Raised events go through Store.Ingest like the agent's, so they reach the timeline, the
// device record and the export outbox in one transaction. Their event IDs are derived from
// what they report, so several API replicas sweeping at once store each alert only once.
package monitor

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/session"
	"github.com/Altiward/altiward/backend/internal/store"
)

// Check returns the agent.silent event device d is owed at now, if any: silent once it has
// gone silentAfter without checking in, resumed once it checks in again after that.
//
// Check-ins are timed by the server's clock (Device.CheckedInAt), so a Mac whose clock is
// days behind isn't reported silent, and one running ahead isn't left unreported.
func Check(d session.Device, now time.Time, silentAfter time.Duration) (event.Event, bool) {
	seen := d.CheckedInAt()
	if d.Silent() {
		if !back(d) {
			return event.Event{}, false
		}
		return raise(d, now, "resumed/"+d.Silence.EventID, map[string]any{
			"state":          event.SilentStateResumed,
			"last_seen_at":   timestamp(seen),
			"silent_since":   timestamp(d.Silence.LastSeenAt),
			"alert_event_id": d.Silence.EventID,
		}), true
	}
	if seen.IsZero() || now.Sub(seen) < silentAfter {
		return event.Event{}, false
	}
	return raise(d, now, "silent/"+timestamp(seen), map[string]any{
		"state":                event.SilentStateSilent,
		"last_seen_at":         timestamp(seen),
		"silent_after_seconds": int(silentAfter.Seconds()),
	}), true
}

// back reports whether a silent Mac has checked in since: the server received an event
// from it after raising the alert. When the receive time is unknown, it falls back to
// comparing the Mac's own timestamps.
func back(d session.Device) bool {
	if !d.LastReceivedAt.IsZero() {
		return d.LastReceivedAt.After(d.Silence.At)
	}
	return d.LastSeenAt.After(d.Silence.LastSeenAt)
}

func raise(d session.Device, now time.Time, key string, detail map[string]any) event.Event {
	return event.Event{
		SchemaVersion: event.SchemaVersion,
		EventID:       nameUUID(d.TenantID + "/" + d.Serial + "/" + key),
		Type:          event.AgentSilent,
		Timestamp:     now.UTC(),
		Device: event.Device{
			Serial: d.Serial, HardwareUUID: d.HardwareUUID, OSVersion: d.OSVersion,
			AgentVersion: d.AgentVersion, PrivilegesVersion: d.PrivilegesVersion,
		},
		Detail: detail,
	}
}

// Detail values are strings, as they would be after a JSON round trip, so the device
// reducer reads them the same from either store.
func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// namespace scopes the name-based UUIDs of raised events.
var namespace = [16]byte{0x6b, 0x1e, 0x2f, 0x9a, 0x3c, 0x4d, 0x4e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61}

// nameUUID is a version 5 (SHA-1, name-based) UUID: the same name always gives the same ID.
func nameUUID(name string) string {
	h := sha1.New()
	h.Write(namespace[:])
	h.Write([]byte(name))
	b := h.Sum(nil)[:16]
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Silence sweeps every tenant's devices for agent.silent alerts.
type Silence struct {
	Store store.Store
	Log   *slog.Logger
	Now   func() time.Time
}

// Run sweeps, then waits interval, until ctx is cancelled.
func (w *Silence) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := w.Sweep(ctx); err != nil && ctx.Err() == nil {
			w.Log.Warn("silence sweep failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Sweep raises the alerts that are due and returns how many were stored. An error with one
// device doesn't stop the others; the next sweep retries it.
func (w *Silence) Sweep(ctx context.Context) (raised int, err error) {
	now := w.Now()
	devices, err := w.Store.SilenceCandidates(ctx, now.Add(-store.MinSilentAfterHours*time.Hour))
	if err != nil {
		return 0, err
	}
	tenants := map[string]store.TenantSettings{}
	var errs []error
	for _, d := range devices {
		if ctx.Err() != nil {
			break
		}
		settings, ok := tenants[d.TenantID]
		if !ok {
			settings, err = w.Store.TenantSettings(ctx, d.TenantID)
			if err != nil {
				errs = append(errs, fmt.Errorf("tenant %s settings: %w", d.TenantID, err))
				continue
			}
			tenants[d.TenantID] = settings
		}
		e, ok := Check(d, now, settings.SilentAfter())
		if !ok {
			continue
		}
		if e.Detail["state"] == event.SilentStateSilent {
			if settings.SilentAlertsOff {
				continue // only a new silence; a resume still closes an earlier alert
			}
			retired, err := w.retired(ctx, d)
			if err != nil {
				errs = append(errs, fmt.Errorf("device %s/%s credentials: %w", d.TenantID, d.Serial, err))
				continue
			}
			if retired {
				continue
			}
		}
		if err := e.Validate(now); err != nil {
			errs = append(errs, fmt.Errorf("device %s/%s: raised an invalid event: %w", d.TenantID, d.Serial, err))
			continue
		}
		res, err := w.Store.Ingest(ctx, d.TenantID, []event.Event{e}, now)
		if err != nil {
			errs = append(errs, fmt.Errorf("device %s/%s: %w", d.TenantID, d.Serial, err))
			continue
		}
		if len(res.Accepted) > 0 {
			raised++
			w.Log.Info("agent silence", "tenant", d.TenantID, "device", d.Serial, "state", e.Detail["state"],
				"last_seen_at", d.CheckedInAt())
		}
	}
	return raised, errors.Join(errs...)
}

// retired reports whether every credential the Mac enrolled with was revoked, which is how
// a Mac is taken out of service: it is expected to go quiet.
func (w *Silence) retired(ctx context.Context, d session.Device) (bool, error) {
	creds, err := w.Store.ListCredentials(ctx, d.TenantID, store.CredentialFilter{Serial: d.Serial})
	if err != nil || len(creds) == 0 {
		return false, err
	}
	for _, c := range creds {
		if c.Status != store.CredentialRevoked {
			return false, nil
		}
	}
	return true, nil
}
