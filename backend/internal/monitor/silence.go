// Package monitor raises the events only the backend can notice. A Mac whose agent was
// removed can't report anything, so the backend watches for the silence and raises
// agent.silent itself, then agent.silent with state resumed when the Mac checks in again.
//
// Raised events go through Store.Ingest like the agent's, so they reach the timeline, the
// device record and the export outbox in one transaction. Their event IDs are derived from
// what they report, so several API replicas sweeping at once store each alert only once.
package monitor

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/release"
	"github.com/Altiward/altiward/backend/internal/session"
	"github.com/Altiward/altiward/backend/internal/store"
)

// MDMGrace is how much later than a Mac's last check-in the MDM must have heard from it for
// its silence to be raised early. A running agent checks in at least hourly, so it would
// have checked in twice since.
const MDMGrace = 2 * time.Hour

// MDMStartGrace is how long after the server starts the early basis waits: after an outage,
// the MDM's check-ins from during it would otherwise trip every Mac.
const MDMStartGrace = MDMGrace + 10*time.Minute

// MDMMinAgent is the first agent release that checks in at least hourly. An older one can
// be set to check in less often than MDMGrace, so its silence is never raised early.
const MDMMinAgent = "1.2"

// MDMPendingGrace is how long a key waiting for approval keeps its Mac from the early basis.
// A pending key can't check in, but anyone with the enrolment token can make one, so it
// mustn't hold the alert back for longer.
const MDMPendingGrace = 24 * time.Hour

// Macs that checked in within mdmHoldWindow count towards holding the early basis back, so
// a few stopped agents can't hold it back for the tenant's whole limit.
const mdmHoldWindow = 24 * time.Hour

// MDMSeen is what the MDM says of a Mac, for Check.
type MDMSeen struct {
	// LastCheckIn is when the MDM last heard from the Mac, zero when unknown. It goes in the
	// alert on either basis.
	LastCheckIn time.Time
	// MayRaise says the guards allow raising the silence early, on LastCheckIn.
	MayRaise bool
	// PendingDeviceID is a key enrolled since the Mac's last check-in that has waited for
	// approval for longer than MDMPendingGrace. It goes in the alert.
	PendingDeviceID string
}

// checkIn is LastCheckIn, no later than now: the MDM times it by its own clock.
func (m MDMSeen) checkIn(now time.Time) time.Time {
	if m.LastCheckIn.After(now) {
		return now
	}
	return m.LastCheckIn
}

// early reports whether the MDM heard from a Mac at least MDMGrace after its last check-in.
func early(seen, mdmCheckIn time.Time) bool {
	return !mdmCheckIn.IsZero() && mdmCheckIn.Sub(seen) >= MDMGrace
}

// Check returns the agent.silent event device d is owed at now, if any: silent once it has
// gone silentAfter without checking in, or earlier when mdm.MayRaise and the MDM heard from
// it MDMGrace after that; resumed once it checks in again after that. Both bases report the
// same silence, with the same event ID, so it is raised once.
//
// Check-ins are timed by the server's clock (Device.CheckedInAt), so a Mac whose clock is
// days behind isn't reported silent, and one running ahead isn't left unreported.
func Check(d session.Device, now time.Time, silentAfter time.Duration, mdm MDMSeen) (event.Event, bool) {
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
	if seen.IsZero() {
		return event.Event{}, false
	}
	mdmCheckIn := mdm.checkIn(now)
	basis := event.SilentBasisNoContact
	if now.Sub(seen) < silentAfter {
		if !mdm.MayRaise || !early(seen, mdmCheckIn) {
			return event.Event{}, false
		}
		basis = event.SilentBasisMDMCheckIn
	}
	detail := map[string]any{
		"state":                event.SilentStateSilent,
		"basis":                basis,
		"last_seen_at":         timestamp(seen),
		"silent_after_seconds": int(silentAfter.Seconds()),
		"admin_members":        append([]string{}, d.AdminMembers...),
	}
	if !mdmCheckIn.IsZero() {
		detail["mdm_last_check_in"] = timestamp(mdmCheckIn)
	}
	if mdm.PendingDeviceID != "" {
		detail["pending_device_id"] = mdm.PendingDeviceID
	}
	return raise(d, now, "silent/"+timestamp(seen), detail), true
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
		EventID:       event.RaisedID(d.TenantID + "/" + d.Serial + "/" + key),
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

// Silence sweeps every tenant's devices for agent.silent alerts.
type Silence struct {
	Store store.Store
	Log   *slog.Logger
	Now   func() time.Time
	// MDMSource is the MDM whose check-ins can raise a silence early (store.MDMIntune), for
	// the Macs of MDMTenant; empty turns the early basis off. It waits MDMStartGrace after
	// Started, when the server started.
	MDMSource string
	MDMTenant string
	Started   time.Time

	warnedAt time.Time // when holding the early basis back was last logged
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
	settingsOf := func(tenantID string) (store.TenantSettings, bool) {
		if settings, ok := tenants[tenantID]; ok {
			return settings, true
		}
		settings, err := w.Store.TenantSettings(ctx, tenantID)
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s settings: %w", tenantID, err))
			return settings, false
		}
		tenants[tenantID] = settings
		return settings, true
	}
	var mdm map[string]MDMSeen
	if w.MDMSource != "" {
		if settings, ok := settingsOf(w.MDMTenant); ok {
			// Without the MDM's copy, every Mac still has the tenant's limit.
			if mdm, err = w.mdmSeen(ctx, now, devices, settings); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, d := range devices {
		if ctx.Err() != nil {
			break
		}
		settings, ok := settingsOf(d.TenantID)
		if !ok {
			continue
		}
		var seen MDMSeen
		if d.TenantID == w.MDMTenant {
			seen = mdm[d.Serial]
		}
		e, ok := Check(d.Device, now, settings.SilentAfter(), seen)
		if !ok {
			continue
		}
		if e.Detail["state"] == event.SilentStateSilent {
			if settings.SilentAlertsOff {
				continue // only a new silence; a resume still closes an earlier alert
			}
			if d.RetiredAt != nil {
				continue // an admin took the Mac out of service: it is expected to go quiet
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
				"basis", e.Detail["basis"], "last_seen_at", d.CheckedInAt())
		}
	}
	return raised, errors.Join(errs...)
}

// mdmSeen returns what the MDM says of each of MDMTenant's devices it lists, by serial, with
// the guards on the early basis applied:
//   - not until MDMStartGrace after the server started;
//   - not for a retired Mac, or one whose agent never reported MDMMinAgent or later;
//   - not for MDMPendingGrace after the oldest key the Mac enrolled since its last check-in
//     that waits for approval;
//   - not for any Mac while more than the larger of 5 and a fifth of the MDM's Macs would
//     trip, counting those raised early already: Altiward is then probably what they can't
//     reach. The hold is recorded for Settings and logged at most hourly.
//
// It returns nil when the tenant's silence alerts are off.
func (w *Silence) mdmSeen(ctx context.Context, now time.Time, devices []store.Device, settings store.TenantSettings) (map[string]MDMSeen, error) {
	if settings.SilentAlertsOff || !slices.ContainsFunc(devices, func(d store.Device) bool { return d.TenantID == w.MDMTenant }) {
		return nil, nil
	}
	records, err := w.Store.MDMDevices(ctx, w.MDMTenant, w.MDMSource)
	if err != nil {
		return nil, fmt.Errorf("tenant %s: %s devices: %w", w.MDMTenant, w.MDMSource, err)
	}
	// An MDM can list a serial more than once: the newest check-in counts.
	newest := map[string]time.Time{}
	for _, r := range records {
		serial := store.MDMSerial(r.Serial)
		if at, ok := newest[serial]; serial != "" && (!ok || r.LastCheckIn.After(at)) {
			newest[serial] = r.LastCheckIn
		}
	}
	keys, err := w.Store.ListCredentials(ctx, w.MDMTenant, store.CredentialFilter{Status: store.CredentialPending})
	if err != nil {
		return nil, fmt.Errorf("tenant %s: pending keys: %w", w.MDMTenant, err)
	}
	pending := map[string][]store.DeviceCredential{}
	for _, k := range keys {
		pending[k.Serial] = append(pending[k.Serial], k)
	}

	started := !now.Before(w.Started.Add(MDMStartGrace))
	out := map[string]MDMSeen{}
	trip := 0
	for _, d := range devices {
		at, ok := newest[store.MDMSerial(d.Serial)]
		if d.TenantID != w.MDMTenant || !ok {
			continue
		}
		seen := d.CheckedInAt()
		m := MDMSeen{LastCheckIn: at, MayRaise: started && d.RetiredAt == nil &&
			release.AgentAtLeast(cmp.Or(d.HighestAgentVersion, d.AgentVersion), MDMMinAgent)}
		if k := oldestSince(pending[d.Serial], seen); k != nil {
			if now.Before(k.CreatedAt.Add(MDMPendingGrace)) {
				m.MayRaise = false
			} else {
				m.PendingDeviceID = k.DeviceID
			}
		}
		if m.MayRaise && now.Sub(seen) < mdmHoldWindow && early(seen, m.checkIn(now)) {
			trip++
		}
		out[d.Serial] = m
	}
	if limit := max(5, len(newest)/5); trip > limit {
		for serial, m := range out {
			m.MayRaise = false
			out[serial] = m
		}
		if now.Sub(w.warnedAt) >= time.Hour {
			w.warnedAt = now
			w.Log.Warn("holding back early silence alerts: too many Macs stopped checking in while the MDM still hears from them, "+
				"so Altiward is probably unreachable (check the agent hostname, its certificate and any proxy)",
				"tenant", w.MDMTenant, "source", w.MDMSource, "macs", trip, "limit", limit)
		}
		if err := w.Store.RecordSilenceHeld(ctx, w.MDMTenant, w.MDMSource, trip, now); err != nil {
			return out, fmt.Errorf("tenant %s: record the hold: %w", w.MDMTenant, err)
		}
	}
	return out, nil
}

// oldestSince returns the oldest of keys created after since, or nil.
func oldestSince(keys []store.DeviceCredential, since time.Time) *store.DeviceCredential {
	var oldest *store.DeviceCredential
	for i, k := range keys {
		if k.CreatedAt.After(since) && (oldest == nil || k.CreatedAt.Before(oldest.CreatedAt)) {
			oldest = &keys[i]
		}
	}
	return oldest
}
