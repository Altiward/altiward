package monitor_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/monitor"
	"github.com/Altiward/altiward/backend/internal/session"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

const tenant = "t1"

func quietDevice(t *testing.T) (session.Device, time.Time) {
	health := testfixture.Event(t, "agent-health")
	d := session.NewDevice(tenant, health.Device.Serial)
	d.Apply(health)
	return d, health.Timestamp
}

func TestCheckRaisesSilentOnceTheLimitPasses(t *testing.T) {
	d, seen := quietDevice(t)
	if _, ok := monitor.Check(d, seen.Add(72*time.Hour-time.Second), 72*time.Hour); ok {
		t.Fatal("raised before the limit")
	}
	now := seen.Add(72 * time.Hour)
	e, ok := monitor.Check(d, now, 72*time.Hour)
	if !ok {
		t.Fatal("not raised at the limit")
	}
	if err := e.Validate(now); err != nil {
		t.Fatal(err)
	}
	if e.Type != event.AgentSilent || e.Detail["state"] != "silent" || !e.Timestamp.Equal(now) ||
		e.Detail["last_seen_at"] != seen.UTC().Format(time.RFC3339Nano) || e.Detail["silent_after_seconds"] != 259200 {
		t.Fatalf("event = %+v", e)
	}
	if e.Device.HardwareUUID != d.HardwareUUID || e.Device.AgentVersion != d.AgentVersion {
		t.Fatalf("device = %+v", e.Device)
	}
	again, _ := monitor.Check(d, now.Add(time.Hour), 72*time.Hour)
	if again.EventID != e.EventID {
		t.Fatal("a later sweep for the same silence must raise the same event ID")
	}
}

func TestCheckRaisesResumedWhenTheMacChecksInAgain(t *testing.T) {
	d, seen := quietDevice(t)
	silent, _ := monitor.Check(d, seen.Add(80*time.Hour), 72*time.Hour)
	d.Apply(silent)
	if _, ok := monitor.Check(d, seen.Add(90*time.Hour), 72*time.Hour); ok {
		t.Fatal("raised twice while still silent")
	}

	back := testfixture.Event(t, "agent-health")
	back.EventID = "0b5e0f3a-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	back.Timestamp = seen.Add(91 * time.Hour)
	d.Apply(back)
	resumed, ok := monitor.Check(d, seen.Add(91*time.Hour+time.Minute), 72*time.Hour)
	if !ok || resumed.Detail["state"] != "resumed" || resumed.Detail["alert_event_id"] != silent.EventID ||
		resumed.Detail["silent_since"] != silent.Detail["last_seen_at"] {
		t.Fatalf("resumed = %+v", resumed)
	}
	d.Apply(resumed)
	if d.Silent() {
		t.Fatal("still silent after resuming")
	}
	if _, ok := monitor.Check(d, seen.Add(92*time.Hour), 72*time.Hour); ok {
		t.Fatal("raised again right after resuming")
	}
	// Going quiet again is a new silence with its own ID.
	next, ok := monitor.Check(d, back.Timestamp.Add(72*time.Hour), 72*time.Hour)
	if !ok || next.Detail["state"] != "silent" || next.EventID == silent.EventID {
		t.Fatalf("next = %+v", next)
	}
}

func TestCheckTimesCheckInsByTheServersClock(t *testing.T) {
	// The Mac's clock is three days behind: its health says 10:05 on the 16th, but the
	// server received it on the 19th.
	health := testfixture.Event(t, "agent-health")
	received := health.Timestamp.Add(72 * time.Hour)
	d := session.NewDevice(tenant, health.Device.Serial)
	d.Apply(health)
	d.Received(health, received)
	if _, ok := monitor.Check(d, received.Add(time.Hour), 72*time.Hour); ok {
		t.Fatal("silent by the Mac's clock, but it checked in an hour ago")
	}
	silent, ok := monitor.Check(d, received.Add(72*time.Hour), 72*time.Hour)
	if !ok || silent.Detail["last_seen_at"] != received.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("silent = %+v", silent)
	}

	// Back with its clock still behind: still before the silence by its own clock, after
	// the alert by the server's.
	d.Apply(silent)
	back := testfixture.Event(t, "agent-health")
	back.EventID = "0b5e0f3a-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	back.Timestamp = health.Timestamp.Add(80 * time.Hour)
	d.Apply(back)
	if _, ok := monitor.Check(d, received.Add(80*time.Hour), 72*time.Hour); ok {
		t.Fatal("resumed with no event received since the alert")
	}
	d.Received(back, received.Add(81*time.Hour))
	resumed, ok := monitor.Check(d, received.Add(81*time.Hour+time.Minute), 72*time.Hour)
	if !ok || resumed.Detail["state"] != "resumed" ||
		resumed.Detail["last_seen_at"] != received.Add(81*time.Hour).UTC().Format(time.RFC3339Nano) {
		t.Fatalf("resumed = %+v", resumed)
	}
}

func TestCheckDoesntLeaveAMacRunningAheadUnreported(t *testing.T) {
	health := testfixture.Event(t, "agent-health")
	health.Timestamp = health.Timestamp.Add(30 * 24 * time.Hour) // a month ahead
	received := testfixture.Time(t, "2026-10-16T10:05:00Z")
	d := session.NewDevice(tenant, health.Device.Serial)
	d.Apply(health)
	d.Received(health, received)
	if _, ok := monitor.Check(d, received.Add(72*time.Hour), 72*time.Hour); !ok {
		t.Fatal("not raised: the Mac's clock hid the silence")
	}
}

func TestEventIDsDependOnTenantAndDevice(t *testing.T) {
	d, seen := quietDevice(t)
	now := seen.Add(100 * time.Hour)
	a, _ := monitor.Check(d, now, time.Hour)
	d.TenantID = "t2"
	b, _ := monitor.Check(d, now, time.Hour)
	if a.EventID == b.EventID {
		t.Fatal("two tenants share an event ID")
	}
}

func audit(tenant string) store.AuditEntry {
	return store.AuditEntry{ID: "7d2c1b0a-9e8f-4a6b-8c5d-4e3f2a1b0c9d", TenantID: tenant, Actor: "test"}
}

func newWorker(t *testing.T, now time.Time) (*monitor.Silence, *store.Memory) {
	st := store.NewMemory([]string{"splunk"})
	health := testfixture.Event(t, "agent-health")
	if _, err := st.Ingest(context.Background(), tenant, []event.Event{health}, health.Timestamp); err != nil {
		t.Fatal(err)
	}
	return &monitor.Silence{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}, st
}

func TestSweepStoresTheAlertOnceAndQueuesItForExport(t *testing.T) {
	ctx := context.Background()
	_, seen := quietDevice(t)
	now := seen.Add(73 * time.Hour)
	w, st := newWorker(t, now)

	for i, want := range []int{1, 0} {
		raised, err := w.Sweep(ctx)
		if err != nil || raised != want {
			t.Fatalf("sweep %d: raised = %d, err = %v", i, raised, err)
		}
	}
	devices, _ := st.ListDevices(ctx, tenant)
	if len(devices) != 1 || !devices[0].Silent() || !devices[0].LastSeenAt.Equal(seen) {
		t.Fatalf("devices = %+v", devices)
	}
	// The reading, the admin group it raised, then the alert.
	items, _ := st.ClaimExports(ctx, "splunk", 10, time.Minute, now)
	if len(items) != 3 || items[2].Event.Type != event.AgentSilent {
		t.Fatalf("exports = %+v", items)
	}
}

func TestSweepUsesTheTenantsLimit(t *testing.T) {
	ctx := context.Background()
	_, seen := quietDevice(t)
	w, st := newWorker(t, seen.Add(5*time.Hour))
	if raised, _ := w.Sweep(ctx); raised != 0 {
		t.Fatal("raised before the default limit")
	}
	if err := st.PutTenantSettings(ctx, tenant, store.TenantSettings{SilentAfterHours: 4}, audit(tenant)); err != nil {
		t.Fatal(err)
	}
	if raised, err := w.Sweep(ctx); raised != 1 || err != nil {
		t.Fatalf("raised = %d, err = %v", raised, err)
	}
}

// Turned off, the sweep raises no new silence, but a Mac already reported silent still
// sends "resumed" when it checks in, so its open SIEM finding closes.
func TestSweepRaisesNoSilenceWhenAlertsAreOffButStillResumes(t *testing.T) {
	ctx := context.Background()
	_, seen := quietDevice(t)
	now := seen.Add(73 * time.Hour)
	w, st := newWorker(t, now)
	off := store.TenantSettings{SilentAlertsOff: true}
	if err := st.PutTenantSettings(ctx, tenant, off, audit(tenant)); err != nil {
		t.Fatal(err)
	}
	if raised, err := w.Sweep(ctx); raised != 0 || err != nil {
		t.Fatalf("raised = %d, err = %v with alerts off", raised, err)
	}

	if err := st.PutTenantSettings(ctx, tenant, store.TenantSettings{}, audit(tenant)); err != nil {
		t.Fatal(err)
	}
	if raised, err := w.Sweep(ctx); raised != 1 || err != nil {
		t.Fatalf("raised = %d, err = %v with alerts back on", raised, err)
	}
	if err := st.PutTenantSettings(ctx, tenant, off, audit(tenant)); err != nil {
		t.Fatal(err)
	}
	back := testfixture.Event(t, "agent-health")
	back.EventID = "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e"
	back.Timestamp = now.Add(time.Hour)
	if _, err := st.Ingest(ctx, tenant, []event.Event{back}, back.Timestamp); err != nil {
		t.Fatal(err)
	}
	w.Now = func() time.Time { return back.Timestamp.Add(time.Minute) }
	if raised, err := w.Sweep(ctx); raised != 1 || err != nil {
		t.Fatalf("raised = %d, err = %v: a Mac checking in again must still resume", raised, err)
	}
}

// An admin revoking a Mac's last key retires it, and a retired Mac is expected to go quiet.
func TestSweepSkipsRetiredMacs(t *testing.T) {
	ctx := context.Background()
	d, seen := quietDevice(t)
	now := seen.Add(100 * time.Hour)
	w, st := newWorker(t, now)
	res, err := st.Enroll(ctx, store.DeviceCredential{
		DeviceID: "5f0c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f", TenantID: tenant, Serial: d.Serial,
		HardwareUUID: d.HardwareUUID, PublicKey: []byte("key"), CreatedAt: seen,
	}, store.EnrollLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RevokeCredential(ctx, tenant, res.Credential.DeviceID, seen, audit(tenant)); err != nil {
		t.Fatal(err)
	}
	devices, _ := st.ListDevices(ctx, tenant)
	if len(devices) != 1 || devices[0].RetiredAt == nil {
		t.Fatalf("devices = %+v: revoking the last key must retire the Mac", devices)
	}
	if raised, err := w.Sweep(ctx); raised != 0 || err != nil {
		t.Fatalf("raised = %d, err = %v for a retired Mac", raised, err)
	}
}

// A stale-key contest revokes the active key, so every key the Mac has is revoked, but no
// admin retired it: it is probably still running and has gone quiet, so it is reported.
func TestSweepReportsAContestedMac(t *testing.T) {
	ctx := context.Background()
	d, seen := quietDevice(t)
	now := seen.Add(100 * time.Hour)
	w, st := newWorker(t, now)
	first, err := st.Enroll(ctx, store.DeviceCredential{
		DeviceID: "5f0c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f", TenantID: tenant, Serial: d.Serial,
		HardwareUUID: d.HardwareUUID, PublicKey: []byte("key"), CreatedAt: seen,
	}, store.EnrollLimits{})
	if err != nil {
		t.Fatal(err)
	}
	rotatedAt := seen.Add(25 * time.Hour)
	next, err := st.Rotate(ctx, store.RotateRequest{
		TenantID: tenant, FromDeviceID: first.Credential.DeviceID,
		DeviceID: "6a1d2e3f-4b5c-4d6e-8f7a-8b9c0d1e2f3a", PublicKey: []byte("key2"),
		SignedAt: rotatedAt, Now: rotatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The old key is used again after the rotation: a contest, which revokes the new key.
	contest, err := st.StaleKeyUsed(ctx, first.Credential.DeviceID, rotatedAt.Add(time.Hour), rotatedAt.Add(time.Hour), nil)
	if err != nil || contest == nil || contest.Revoked == nil || contest.Revoked.DeviceID != next.Credential.DeviceID {
		t.Fatalf("contest = %+v, err = %v", contest, err)
	}
	creds, _ := st.ListCredentials(ctx, tenant, store.CredentialFilter{Serial: d.Serial})
	for _, c := range creds {
		if c.Status != store.CredentialRevoked {
			t.Fatalf("credential %s is %s, want every key revoked", c.DeviceID, c.Status)
		}
	}
	devices, _ := st.ListDevices(ctx, tenant)
	if len(devices) != 1 || devices[0].RetiredAt != nil {
		t.Fatalf("devices = %+v: a contest must not retire the Mac", devices)
	}
	if raised, err := w.Sweep(ctx); raised != 1 || err != nil {
		t.Fatalf("raised = %d, err = %v for a Mac a contest left without a key", raised, err)
	}
}

// The export outbox and the SIEM dedupe an alert by its event ID, so how the ID is derived
// must not change.
func TestRaisedEventIDsAreStable(t *testing.T) {
	d, seen := quietDevice(t)
	silent, _ := monitor.Check(d, seen.Add(100*time.Hour), time.Hour)
	if want := "3d87c4bd-d502-50eb-8f02-c12fdd45687f"; silent.EventID != want {
		t.Fatalf("silent event ID = %s, want %s", silent.EventID, want)
	}
}
