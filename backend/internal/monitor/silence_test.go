package monitor_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
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
	if _, ok := monitor.Check(d, seen.Add(72*time.Hour-time.Second), 72*time.Hour, monitor.MDMSeen{}); ok {
		t.Fatal("raised before the limit")
	}
	now := seen.Add(72 * time.Hour)
	e, ok := monitor.Check(d, now, 72*time.Hour, monitor.MDMSeen{})
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
	again, _ := monitor.Check(d, now.Add(time.Hour), 72*time.Hour, monitor.MDMSeen{})
	if again.EventID != e.EventID {
		t.Fatal("a later sweep for the same silence must raise the same event ID")
	}
}

func TestCheckRaisesResumedWhenTheMacChecksInAgain(t *testing.T) {
	d, seen := quietDevice(t)
	silent, _ := monitor.Check(d, seen.Add(80*time.Hour), 72*time.Hour, monitor.MDMSeen{})
	d.Apply(silent)
	if _, ok := monitor.Check(d, seen.Add(90*time.Hour), 72*time.Hour, monitor.MDMSeen{}); ok {
		t.Fatal("raised twice while still silent")
	}

	back := testfixture.Event(t, "agent-health")
	back.EventID = "0b5e0f3a-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	back.Timestamp = seen.Add(91 * time.Hour)
	d.Apply(back)
	resumed, ok := monitor.Check(d, seen.Add(91*time.Hour+time.Minute), 72*time.Hour, monitor.MDMSeen{})
	if !ok || resumed.Detail["state"] != "resumed" || resumed.Detail["alert_event_id"] != silent.EventID ||
		resumed.Detail["silent_since"] != silent.Detail["last_seen_at"] {
		t.Fatalf("resumed = %+v", resumed)
	}
	d.Apply(resumed)
	if d.Silent() {
		t.Fatal("still silent after resuming")
	}
	if _, ok := monitor.Check(d, seen.Add(92*time.Hour), 72*time.Hour, monitor.MDMSeen{}); ok {
		t.Fatal("raised again right after resuming")
	}
	// Going quiet again is a new silence with its own ID.
	next, ok := monitor.Check(d, back.Timestamp.Add(72*time.Hour), 72*time.Hour, monitor.MDMSeen{})
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
	if _, ok := monitor.Check(d, received.Add(time.Hour), 72*time.Hour, monitor.MDMSeen{}); ok {
		t.Fatal("silent by the Mac's clock, but it checked in an hour ago")
	}
	silent, ok := monitor.Check(d, received.Add(72*time.Hour), 72*time.Hour, monitor.MDMSeen{})
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
	if _, ok := monitor.Check(d, received.Add(80*time.Hour), 72*time.Hour, monitor.MDMSeen{}); ok {
		t.Fatal("resumed with no event received since the alert")
	}
	d.Received(back, received.Add(81*time.Hour))
	resumed, ok := monitor.Check(d, received.Add(81*time.Hour+time.Minute), 72*time.Hour, monitor.MDMSeen{})
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
	if _, ok := monitor.Check(d, received.Add(72*time.Hour), 72*time.Hour, monitor.MDMSeen{}); !ok {
		t.Fatal("not raised: the Mac's clock hid the silence")
	}
}

func TestEventIDsDependOnTenantAndDevice(t *testing.T) {
	d, seen := quietDevice(t)
	now := seen.Add(100 * time.Hour)
	a, _ := monitor.Check(d, now, time.Hour, monitor.MDMSeen{})
	d.TenantID = "t2"
	b, _ := monitor.Check(d, now, time.Hour, monitor.MDMSeen{})
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
	silent, _ := monitor.Check(d, seen.Add(100*time.Hour), time.Hour, monitor.MDMSeen{})
	if want := "3d87c4bd-d502-50eb-8f02-c12fdd45687f"; silent.EventID != want {
		t.Fatalf("silent event ID = %s, want %s", silent.EventID, want)
	}
}

// newAgent is a Mac running an agent with the hourly heartbeat cap, quiet since seen.
func newAgent(t *testing.T) (session.Device, time.Time) {
	health := testfixture.Event(t, "agent-health")
	health.Device.AgentVersion = "1.2.0"
	d := session.NewDevice(tenant, health.Device.Serial)
	d.Apply(health)
	return d, health.Timestamp
}

func TestMDMSilenceNeedsTwoHours(t *testing.T) {
	d, seen := newAgent(t)
	now := seen.Add(3 * time.Hour)
	if _, ok := monitor.Check(d, now, 72*time.Hour, monitor.MDMSeen{LastCheckIn: seen.Add(monitor.MDMGrace - time.Minute), MayRaise: true}); ok {
		t.Fatal("raised with Intune's check-in under two hours after Altiward's")
	}
	at := seen.Add(monitor.MDMGrace)
	if _, ok := monitor.Check(d, now, 72*time.Hour, monitor.MDMSeen{LastCheckIn: at}); ok {
		t.Fatal("raised early when the guards don't allow it")
	}
	e, ok := monitor.Check(d, now, 72*time.Hour, monitor.MDMSeen{LastCheckIn: at, MayRaise: true})
	if !ok {
		t.Fatal("not raised at two hours")
	}
	if err := e.Validate(now); err != nil {
		t.Fatal(err)
	}
	if e.Detail["state"] != "silent" || e.Detail["basis"] != "mdm_check_in" ||
		e.Detail["last_seen_at"] != seen.UTC().Format(time.RFC3339Nano) ||
		e.Detail["mdm_last_check_in"] != at.UTC().Format(time.RFC3339Nano) || e.Detail["silent_after_seconds"] != 259200 {
		t.Fatalf("event = %+v", e)
	}
	if _, ok := e.Detail["pending_device_id"]; ok {
		t.Fatalf("event = %+v: no key is waiting", e)
	}
}

// An early alert and the 72-hour one report the same silence, so they share an event ID,
// and once one is raised the other isn't.
func TestMDMSilenceAndTheSeventyTwoHourRuleRaiseOnce(t *testing.T) {
	d, seen := newAgent(t)
	mdm := monitor.MDMSeen{LastCheckIn: seen.Add(3 * time.Hour), MayRaise: true}
	early, ok := monitor.Check(d, seen.Add(4*time.Hour), 72*time.Hour, mdm)
	if !ok {
		t.Fatal("not raised early")
	}
	late, _ := monitor.Check(d, seen.Add(72*time.Hour), 72*time.Hour, monitor.MDMSeen{})
	if late.EventID != early.EventID {
		t.Fatal("the two bases raised different event IDs for one silence")
	}
	d.Apply(early)
	if _, ok := monitor.Check(d, seen.Add(72*time.Hour), 72*time.Hour, mdm); ok {
		t.Fatal("raised again at 72 hours")
	}
}

func TestNoContactCarriesIntunesCheckIn(t *testing.T) {
	d, seen := newAgent(t)
	at := seen.Add(-time.Hour) // Intune hasn't heard from it either: a closed laptop
	e, ok := monitor.Check(d, seen.Add(72*time.Hour), 72*time.Hour, monitor.MDMSeen{LastCheckIn: at})
	if !ok || e.Detail["basis"] != "no_contact" || e.Detail["mdm_last_check_in"] != at.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("event = %+v", e)
	}
	e, _ = monitor.Check(d, seen.Add(72*time.Hour), 72*time.Hour, monitor.MDMSeen{})
	if _, ok := e.Detail["mdm_last_check_in"]; ok {
		t.Fatalf("event = %+v: Intune's check-in isn't known", e)
	}
}

// The alert names the admins by admingroup.FromHealth's rules, sorted and capped, so a
// forged reading can't make it too large to raise.
func TestSilenceNamesTheAdmins(t *testing.T) {
	d, seen := newAgent(t)
	now := seen.Add(72 * time.Hour)
	e, _ := monitor.Check(d, now, 72*time.Hour, monitor.MDMSeen{})
	if got, _ := e.Detail["admin_members"].([]string); !slices.Equal(got, []string{"backdoor", "itadmin"}) {
		t.Fatalf("admin_members = %#v", e.Detail["admin_members"])
	}
	if _, ok := e.Detail["admin_members_truncated"]; ok {
		t.Fatalf("event = %+v: nothing was cut", e)
	}
	d.AdminMembers = []string{"zed", "", strings.Repeat("x", 256), "amy", "amy"}
	e, _ = monitor.Check(d, now, 72*time.Hour, monitor.MDMSeen{})
	if got, _ := e.Detail["admin_members"].([]string); !slices.Equal(got, []string{"amy", "zed"}) {
		t.Fatalf("admin_members = %#v", e.Detail["admin_members"])
	}
	d.AdminMembers = nil
	for i := range 60 {
		d.AdminMembers = append(d.AdminMembers, fmt.Sprintf("user%02d", i))
	}
	e, _ = monitor.Check(d, now, 72*time.Hour, monitor.MDMSeen{})
	if got, _ := e.Detail["admin_members"].([]string); len(got) != 50 || got[0] != "user00" || e.Detail["admin_members_truncated"] != 10 {
		t.Fatalf("admin_members = %d names, truncated = %v", len(got), e.Detail["admin_members_truncated"])
	}
	d.AdminMembers = nil
	e, _ = monitor.Check(d, now, 72*time.Hour, monitor.MDMSeen{})
	if got, ok := e.Detail["admin_members"].([]string); !ok || got == nil || len(got) != 0 {
		t.Fatalf("admin_members = %#v, want an empty list", e.Detail["admin_members"])
	}
}

// A forged health reading at the detail limit, all admin names, still lets the alert be
// raised.
func TestSilenceFitsAReadingAtTheDetailLimit(t *testing.T) {
	ctx := context.Background()
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(73 * time.Hour)
	w, st := intuneWorker(t, now, nil)
	health := testfixture.Event(t, "agent-health")
	health.Timestamp = seen
	names := []any{}
	for i := 0; ; i++ {
		next := append(names, fmt.Sprintf("u%07d", i))
		if b, _ := json.Marshal(map[string]any{"admin_members": next}); len(b) > event.MaxDetailBytes {
			break
		}
		names = next
	}
	health.Detail = map[string]any{"admin_members": names}
	if err := health.Validate(seen); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Ingest(ctx, tenant, []event.Event{health}, seen); err != nil {
		t.Fatal(err)
	}
	sweep(t, w, 1)
	items, _ := st.ClaimExports(ctx, "splunk", 100, time.Minute, now)
	e := items[len(items)-1].Event
	var got struct {
		Admins    []string `json:"admin_members"`
		Truncated int      `json:"admin_members_truncated"`
	}
	b, _ := json.Marshal(e.Detail)
	if err := json.Unmarshal(b, &got); err != nil || e.Type != event.AgentSilent ||
		len(got.Admins) != 50 || got.Truncated != len(names)-50 {
		t.Fatalf("detail: %d names, truncated = %d, err = %v", len(got.Admins), got.Truncated, err)
	}
}

// An alert too large to store is raised without its optional fields: it fails towards
// alerting.
func TestSilenceDropsTheExtrasRatherThanFail(t *testing.T) {
	d, seen := newAgent(t)
	now := seen.Add(3 * time.Hour)
	mdm := monitor.MDMSeen{LastCheckIn: seen.Add(150 * time.Minute), MayRaise: true, PendingDeviceID: strings.Repeat("x", 70<<10)}
	e, ok := monitor.Check(d, now, 72*time.Hour, mdm)
	if !ok {
		t.Fatal("not raised")
	}
	if err := e.Validate(now); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"admin_members", "pending_device_id", "mdm_last_check_in"} {
		if _, ok := e.Detail[key]; ok {
			t.Fatalf("detail keeps %s: %v", key, e.Detail)
		}
	}
	if e.Detail["basis"] != "mdm_check_in" || e.Detail["state"] != "silent" {
		t.Fatalf("detail = %v", e.Detail)
	}
}

// Intune's check-in is by Microsoft's clock: one the server's clock puts in the future
// counts as now.
func TestMDMSilenceCountsAFutureCheckInAsNow(t *testing.T) {
	d, seen := newAgent(t)
	ahead := monitor.MDMSeen{LastCheckIn: seen.Add(10 * time.Hour), MayRaise: true}
	if _, ok := monitor.Check(d, seen.Add(time.Hour), 72*time.Hour, ahead); ok {
		t.Fatal("raised an hour after the last check-in")
	}
	now := seen.Add(monitor.MDMGrace)
	e, ok := monitor.Check(d, now, 72*time.Hour, ahead)
	if !ok || e.Detail["mdm_last_check_in"] != now.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("event = %+v", e)
	}
}

func TestMDMSilenceNamesAWaitingKey(t *testing.T) {
	d, seen := newAgent(t)
	mdm := monitor.MDMSeen{LastCheckIn: seen.Add(3 * time.Hour), MayRaise: true, PendingDeviceID: "6a1d2e3f-4b5c-4d6e-8f7a-8b9c0d1e2f3a"}
	e, ok := monitor.Check(d, seen.Add(26*time.Hour), 72*time.Hour, mdm)
	if !ok || e.Detail["pending_device_id"] != mdm.PendingDeviceID {
		t.Fatalf("event = %+v", e)
	}
}

// mac is one Mac for an Intune sweep: its serial, agent version, when it last checked in
// with Altiward, and with Intune (zero: not in Intune).
type mac struct {
	serial, version string
	seen, mdmAt     time.Time
}

func macs(n int, version string, seen, mdmAt time.Time) []mac {
	out := make([]mac, n)
	for i := range out {
		out[i] = mac{serial: fmt.Sprintf("C02XK0AAJ%03d", i), version: version, seen: seen, mdmAt: mdmAt}
	}
	return out
}

var healthSeq = 0

// checkIn stores an agent.health from serial, received at at.
func checkIn(t *testing.T, st store.Store, tenantID, serial, version string, at time.Time) {
	t.Helper()
	healthSeq++
	e := testfixture.Event(t, "agent-health")
	e.EventID = fmt.Sprintf("3e9c9d85-9d3b-4a6b-8c8b-%012d", healthSeq)
	e.Device.Serial, e.Device.AgentVersion, e.Timestamp = serial, version, at
	if _, err := st.Ingest(context.Background(), tenantID, []event.Event{e}, at); err != nil {
		t.Fatal(err)
	}
}

// syncIntune replaces the tenant's Intune copy with the Macs that have an Intune check-in.
func syncIntune(t *testing.T, st store.Store, fleet []mac) {
	t.Helper()
	var copy []store.MDMDevice
	for i, m := range fleet {
		if !m.mdmAt.IsZero() {
			copy = append(copy, store.MDMDevice{TenantID: tenant, Source: store.MDMIntune,
				DeviceID: fmt.Sprintf("0d1e2f3a-4b5c-4d6e-8f7a-%012d", i), Serial: m.serial, Name: "Mac " + m.serial, LastCheckIn: m.mdmAt})
		}
	}
	if err := st.ReplaceMDMDevices(context.Background(), tenant, store.MDMIntune, copy, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// intuneWorker sweeps at now with Intune connected, started long ago, over fleet.
func intuneWorker(t *testing.T, now time.Time, fleet []mac) (*monitor.Silence, *store.Memory) {
	st := store.NewMemory([]string{"splunk"})
	for _, m := range fleet {
		checkIn(t, st, tenant, m.serial, m.version, m.seen)
	}
	syncIntune(t, st, fleet)
	return &monitor.Silence{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now },
		MDMSource: store.MDMIntune, MDMTenant: tenant, Started: now.Add(-24 * time.Hour)}, st
}

// silences returns each Mac's open silence basis, by serial.
func silences(t *testing.T, st store.Store) map[string]string {
	t.Helper()
	devices, err := st.ListDevices(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, d := range devices {
		if d.Silent() {
			out[d.Serial] = d.Silence.Basis
		}
	}
	return out
}

func sweep(t *testing.T, w *monitor.Silence, want int) {
	t.Helper()
	if raised, err := w.Sweep(context.Background()); raised != want || err != nil {
		t.Fatalf("raised = %d, err = %v, want %d", raised, err, want)
	}
}

func TestMDMSilenceRaisesEarlyInASweep(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(3 * time.Hour)
	fleet := append(macs(1, "1.2.0", seen, seen.Add(150*time.Minute)), macs(9, "1.2.0", now.Add(-time.Minute), now)[1:]...)
	w, st := intuneWorker(t, now, fleet)
	sweep(t, w, 1)
	sweep(t, w, 0)
	if got := silences(t, st); len(got) != 1 || got[fleet[0].serial] != "mdm_check_in" {
		t.Fatalf("silences = %v", got)
	}
	items, _ := st.ClaimExports(context.Background(), "splunk", 100, time.Minute, now)
	last := items[len(items)-1].Event
	if last.Type != event.AgentSilent || last.Detail["basis"] != "mdm_check_in" {
		t.Fatalf("exported = %+v", last)
	}
}

// Intune can list a serial more than once, in another case or with spaces: the newest
// check-in counts.
func TestMDMSilenceUsesTheNewestRecord(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	w, st := intuneWorker(t, now, macs(1, "1.2.0", seen, time.Time{}))
	serial := macs(1, "", seen, seen)[0].serial
	err := st.ReplaceMDMDevices(context.Background(), tenant, store.MDMIntune, []store.MDMDevice{
		{DeviceID: "0d1e2f3a-4b5c-4d6e-8f7a-000000000001", Serial: serial, LastCheckIn: seen.Add(time.Hour)},
		{DeviceID: "0d1e2f3a-4b5c-4d6e-8f7a-000000000002", Serial: " " + strings.ToLower(serial) + " ", LastCheckIn: seen.Add(3 * time.Hour)},
		{DeviceID: "0d1e2f3a-4b5c-4d6e-8f7a-000000000003", Serial: serial, LastCheckIn: seen.Add(90 * time.Minute)},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	sweep(t, w, 1)
	items, _ := st.ClaimExports(context.Background(), "splunk", 100, time.Minute, now)
	if e := items[len(items)-1].Event; e.Detail["mdm_last_check_in"] != seen.Add(3*time.Hour).UTC().Format(time.RFC3339Nano) {
		t.Fatalf("event = %+v", e)
	}
}

// A Mac is matched to Intune's record by serial only, never by the device name.
func TestMDMSilenceMatchesBySerialNotName(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	w, st := intuneWorker(t, now, macs(1, "1.2.0", seen, time.Time{}))
	serial := macs(1, "", seen, seen)[0].serial
	err := st.ReplaceMDMDevices(context.Background(), tenant, store.MDMIntune, []store.MDMDevice{
		{DeviceID: "0d1e2f3a-4b5c-4d6e-8f7a-000000000001", Serial: "OTHERSERIAL1", Name: serial, LastCheckIn: seen.Add(3 * time.Hour)},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	sweep(t, w, 0)
}

func TestMDMSilenceWaitsAfterAStart(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	w, _ := intuneWorker(t, now, macs(1, "1.2.0", seen, seen.Add(3*time.Hour)))
	w.Started = now.Add(-monitor.MDMStartGrace + time.Minute)
	sweep(t, w, 0)
	w.Started = now.Add(-monitor.MDMStartGrace)
	sweep(t, w, 1)
}

func TestMDMSilenceSkipsPendingKeys(t *testing.T) {
	ctx := context.Background()
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	fleet := macs(1, "1.2.0", seen, seen.Add(3*time.Hour))
	w, st := intuneWorker(t, seen.Add(4*time.Hour), fleet)
	enroll := func(id string, at time.Time) {
		t.Helper()
		if _, err := st.Enroll(ctx, store.DeviceCredential{DeviceID: id, TenantID: tenant, Serial: fleet[0].serial,
			HardwareUUID: "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D", PublicKey: []byte(id), CreatedAt: at}, store.EnrollLimits{}); err != nil {
			t.Fatal(err)
		}
	}
	enroll("5f0c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f", seen.Add(-time.Hour)) // active
	enroll("6a1d2e3f-4b5c-4d6e-8f7a-8b9c0d1e2f3a", seen.Add(-time.Minute))
	sweep(t, w, 1) // the Mac checked in after this key: it is still running on the active one
	w, st = intuneWorker(t, seen.Add(4*time.Hour), fleet)
	pending := "7b2e3f4a-5c6d-4e7f-8a9b-9c0d1e2f3a4b"
	enroll("5f0c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f", seen.Add(-time.Hour))
	created := seen.Add(30 * time.Minute)
	enroll(pending, created)
	sweep(t, w, 0)
	// A newer key doesn't extend the wait.
	enroll("8c3f4a5b-6d7e-4f80-9b0c-0d1e2f3a4b5c", seen.Add(2*time.Hour))
	w.Now = func() time.Time { return created.Add(monitor.MDMPendingGrace - time.Minute) }
	sweep(t, w, 0)
	w.Now = func() time.Time { return created.Add(monitor.MDMPendingGrace) }
	sweep(t, w, 1)
	items, _ := st.ClaimExports(ctx, "splunk", 100, time.Minute, w.Now())
	if e := items[len(items)-1].Event; e.Detail["basis"] != "mdm_check_in" || e.Detail["pending_device_id"] != pending {
		t.Fatalf("event = %+v", e)
	}
}

// A key made late in a silence keeps the Mac waiting past the first day, when the early
// basis ends: the Mac waits for the tenant's limit.
func TestMDMSilenceLatePendingKeyOutlastsTheEarlyBasis(t *testing.T) {
	ctx := context.Background()
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	fleet := macs(1, "1.2.0", seen, seen.Add(21*time.Hour))
	w, st := intuneWorker(t, seen.Add(22*time.Hour), fleet)
	for _, k := range []struct {
		id string
		at time.Time
	}{{"5f0c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f", seen.Add(-time.Hour)}, {"7b2e3f4a-5c6d-4e7f-8a9b-9c0d1e2f3a4b", seen.Add(22 * time.Hour)}} {
		if _, err := st.Enroll(ctx, store.DeviceCredential{DeviceID: k.id, TenantID: tenant, Serial: fleet[0].serial,
			HardwareUUID: "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D", PublicKey: []byte(k.id), CreatedAt: k.at}, store.EnrollLimits{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, at := range []time.Duration{22 * time.Hour, 24 * time.Hour, 26 * time.Hour} {
		w.Now = func() time.Time { return seen.Add(at) }
		sweep(t, w, 0)
	}
}

func TestMDMSilenceHoldsWhenManyTrip(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	tripping := macs(10, "1.2.0", seen, seen.Add(3*time.Hour))
	for i := 6; i < 10; i++ {
		tripping[i].seen = now.Add(-time.Minute)
	}
	w, st := intuneWorker(t, now, tripping)
	sweep(t, w, 0)
	status, _ := st.MDMSyncStatus(context.Background(), tenant, store.MDMIntune)
	if status.SilenceHeldAt == nil || !status.SilenceHeldAt.Equal(now) || status.SilenceHeld != 6 {
		t.Fatalf("status = %+v", status)
	}

	one := macs(10, "1.2.0", now.Add(-time.Minute), now)
	one[0].seen = seen
	w, st = intuneWorker(t, now, one)
	sweep(t, w, 1)
	if status, _ := st.MDMSyncStatus(context.Background(), tenant, store.MDMIntune); status.SilenceHeldAt != nil {
		t.Fatalf("status = %+v", status)
	}
}

// A slow outage trips a few Macs at a time: those raised already still count.
func TestMDMSilenceHoldsWhenTheyTripAcrossSweeps(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	fleet := macs(10, "1.2.0", now.Add(-time.Minute), now)
	for i := range 6 {
		fleet[i].seen, fleet[i].mdmAt = seen, seen.Add(3*time.Hour)
		if i >= 3 {
			fleet[i].mdmAt = seen.Add(time.Hour) // Intune hasn't heard from these yet either
		}
	}
	w, st := intuneWorker(t, now, fleet)
	sweep(t, w, 3)
	for i := 3; i < 6; i++ {
		fleet[i].mdmAt = now
	}
	syncIntune(t, st, fleet)
	w.Now = func() time.Time { return now.Add(time.Minute) }
	sweep(t, w, 0)
	if got := silences(t, st); len(got) != 3 {
		t.Fatalf("silences = %v", got)
	}
	status, _ := st.MDMSyncStatus(context.Background(), tenant, store.MDMIntune)
	if status.SilenceHeld != 6 {
		t.Fatalf("status = %+v", status)
	}
}

// The hold is for the early basis only: a Mac quiet past the tenant's limit is raised.
func TestMDMSilenceNeverHoldsNoContact(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	fleet := macs(10, "1.2.0", now.Add(-time.Minute), now)
	for i := range 6 {
		fleet[i].seen = seen
	}
	fleet[9].seen = now.Add(-73 * time.Hour)
	w, st := intuneWorker(t, now, fleet)
	sweep(t, w, 1)
	if got := silences(t, st); len(got) != 1 || got[fleet[9].serial] != "no_contact" {
		t.Fatalf("silences = %v", got)
	}
}

// The early basis is for silences under a day: a longer one waits for the tenant's limit, and
// doesn't count towards a hold.
func TestMDMSilenceOnlyForTheFirstDay(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(30 * time.Hour)
	fleet := macs(10, "1.2.0", now.Add(-time.Minute), now)
	for i := range 6 {
		fleet[i].seen = seen // 30 hours ago
	}
	fleet[6].seen = now.Add(-3 * time.Hour)
	w, st := intuneWorker(t, now, fleet)
	sweep(t, w, 1)
	if got := silences(t, st); len(got) != 1 || got[fleet[6].serial] == "" {
		t.Fatalf("silences = %v", got)
	}
}

// Once a hold is recorded, a Mac Altiward last heard from before it is never raised early:
// it waits for the tenant's limit, as Settings says. Through a long outage nothing is
// raised early, even as more Macs trip and after a restart.
func TestMDMSilenceRaisesNothingEarlyThroughAnOutage(t *testing.T) {
	ctx := context.Background()
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(3 * time.Hour)
	fleet := macs(10, "1.2.0", seen, now)
	for i := 6; i < 10; i++ {
		fleet[i].mdmAt = seen.Add(time.Hour) // Intune hasn't heard from these since either
	}
	w, st := intuneWorker(t, now, fleet)
	sweep(t, w, 0)
	for i := 6; i < 10; i++ {
		fleet[i].mdmAt = now.Add(2 * time.Hour)
	}
	syncIntune(t, st, fleet)
	for _, at := range []time.Duration{time.Minute, 2 * time.Hour, 23 * time.Hour, 25 * time.Hour} {
		w.Now = func() time.Time { return now.Add(at) }
		sweep(t, w, 0)
	}
	// A restart: the hold is read from the store.
	restarted := &monitor.Silence{Store: st, Log: w.Log, Now: func() time.Time { return now.Add(5 * time.Hour) },
		MDMSource: store.MDMIntune, MDMTenant: tenant, Started: now.Add(-24 * time.Hour)}
	sweep(t, restarted, 0)
	restarted.Now = func() time.Time { return seen.Add(72 * time.Hour) }
	sweep(t, restarted, 10)
	for serial, basis := range silences(t, st) {
		if basis != "no_contact" {
			t.Fatalf("%s raised on %s", serial, basis)
		}
	}
	if status, _ := st.MDMSyncStatus(ctx, tenant, store.MDMIntune); !status.SilenceHeldAt.Equal(now) || status.SilenceHeld != 6 {
		t.Fatalf("status = %+v", status)
	}
}

// When half the held Macs come back, the rest still aren't raised early.
func TestMDMSilenceRecoveryTailStaysHeld(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(3 * time.Hour)
	fleet := macs(10, "1.2.0", seen, now)
	w, st := intuneWorker(t, now, fleet)
	sweep(t, w, 0)
	for i := range 5 {
		checkIn(t, st, tenant, fleet[i].serial, "1.2.0", now.Add(time.Minute))
	}
	w.Now = func() time.Time { return now.Add(2 * time.Minute) }
	sweep(t, w, 0)
	w.Now = func() time.Time { return now.Add(time.Hour) }
	sweep(t, w, 0)
}

// A Mac that checked in after the hold, then went quiet, is raised early as normal.
func TestMDMSilenceAfterAHoldRaisesNewSilences(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(3 * time.Hour)
	fleet := macs(10, "1.2.0", now.Add(-time.Minute), now)
	for i := range 6 {
		fleet[i].seen = seen
	}
	w, st := intuneWorker(t, now, fleet)
	sweep(t, w, 0)
	checkIn(t, st, tenant, fleet[9].serial, "1.2.0", now.Add(time.Minute))
	fleet[9].mdmAt = now.Add(time.Minute + 150*time.Minute)
	syncIntune(t, st, fleet)
	w.Now = func() time.Time { return now.Add(3 * time.Hour) }
	sweep(t, w, 1)
	if got := silences(t, st); len(got) != 1 || got[fleet[9].serial] != "mdm_check_in" {
		t.Fatalf("silences = %v", got)
	}
}

// Agents before the hourly heartbeat cap may check in less often than every two hours.
// The gate is on the newest version a Mac ever reported, so a downgrade doesn't escape it,
// and a version that can't be read counts as new enough.
func TestMDMSilenceSkipsOldAgents(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	fleet := macs(10, "1.2.0", now.Add(-time.Minute), now)
	for i := range 6 {
		fleet[i].seen, fleet[i].version = seen, "1.1.0" // old agents don't count towards a hold either
	}
	fleet[6].seen, fleet[6].version = seen, "dev"
	fleet[7].seen, fleet[7].version = seen, "1.2.0-rc.4"
	fleet[8].seen, fleet[8].version = seen, "1.1.0"
	w, st := intuneWorker(t, now, fleet)
	downgraded := fleet[8].serial
	checkIn(t, st, tenant, downgraded, "1.2.0", seen.Add(-time.Hour)) // before the downgrade
	sweep(t, w, 3)
	got := silences(t, st)
	if len(got) != 3 || got[fleet[6].serial] == "" || got[fleet[7].serial] == "" || got[downgraded] == "" {
		t.Fatalf("silences = %v", got)
	}
}

// Intune serves one tenant: a Mac with the same serial in another tenant isn't raised early.
func TestMDMSilenceOnlyForTheIntuneTenant(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	fleet := macs(1, "1.2.0", seen, seen.Add(3*time.Hour))
	w, st := intuneWorker(t, now, fleet)
	checkIn(t, st, "t2", fleet[0].serial, "1.2.0", seen)
	sweep(t, w, 1)
	if devices, _ := st.ListDevices(context.Background(), "t2"); len(devices) != 1 || devices[0].Silent() {
		t.Fatalf("devices = %+v", devices)
	}
}

// A hold is logged once: the Macs it held don't count again.
func TestMDMSilenceWarnsOnce(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	fleet := macs(10, "1.2.0", now.Add(-time.Minute), now)
	for i := range 6 {
		fleet[i].seen = seen
	}
	w, _ := intuneWorker(t, now, fleet)
	var logs bytes.Buffer
	w.Log = slog.New(slog.NewTextHandler(&logs, nil))
	for _, at := range []time.Duration{0, time.Minute, time.Hour, 3 * time.Hour} {
		w.Now = func() time.Time { return now.Add(at) }
		sweep(t, w, 0)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Fatalf("%d warnings:\n%s", n, logs.String())
	}
}

// A serial that isn't already normalised (padded, or lower-case) is never raised early and
// doesn't count towards a hold: a few forged Macs mustn't hold back the real ones.
func TestMDMSilenceSkipsUnnormalisedSerials(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	fleet := macs(10, "1.2.0", now.Add(-time.Minute), now)
	fleet[0].seen = seen
	w, st := intuneWorker(t, now, fleet)
	real := fleet[0].serial
	for _, serial := range []string{" " + real, real + " ", strings.ToLower(real), " " + fleet[1].serial, strings.ToLower(fleet[2].serial), fleet[3].serial + " "} {
		checkIn(t, st, tenant, serial, "1.2.0", seen)
	}
	sweep(t, w, 1)
	if got := silences(t, st); len(got) != 1 || got[real] != "mdm_check_in" {
		t.Fatalf("silences = %v", got)
	}
}

// A pending key is matched on the normalised serial.
func TestMDMSilenceMatchesPendingKeysOnTheNormalisedSerial(t *testing.T) {
	ctx := context.Background()
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	fleet := macs(1, "1.2.0", seen, seen.Add(3*time.Hour))
	w, st := intuneWorker(t, seen.Add(4*time.Hour), fleet)
	if err := st.PutTenantSettings(ctx, tenant, store.TenantSettings{ReenrollmentRequiresApproval: true, NewMacRequiresApproval: true}, audit(tenant)); err != nil {
		t.Fatal(err)
	}
	res, err := st.Enroll(ctx, store.DeviceCredential{DeviceID: "7b2e3f4a-5c6d-4e7f-8a9b-9c0d1e2f3a4b", TenantID: tenant,
		Serial: " " + strings.ToLower(fleet[0].serial), HardwareUUID: "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D",
		PublicKey: []byte("key"), CreatedAt: seen.Add(30 * time.Minute)}, store.EnrollLimits{})
	if err != nil || res.Credential.Status != store.CredentialPending {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	sweep(t, w, 0)
}

// Turned off, no silence is raised on either basis, and none is held.
func TestMDMSilenceRespectsSilentAlertsOff(t *testing.T) {
	ctx := context.Background()
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	fleet := macs(10, "1.2.0", now.Add(-time.Minute), now)
	for i := range 7 {
		fleet[i].seen = seen
	}
	w, st := intuneWorker(t, now, fleet)
	if err := st.PutTenantSettings(ctx, tenant, store.TenantSettings{SilentAlertsOff: true}, audit(tenant)); err != nil {
		t.Fatal(err)
	}
	sweep(t, w, 0)
	if status, _ := st.MDMSyncStatus(ctx, tenant, store.MDMIntune); status.SilenceHeldAt != nil {
		t.Fatalf("status = %+v", status)
	}
}

func TestMDMSilenceSkipsRetiredMacs(t *testing.T) {
	ctx := context.Background()
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	now := seen.Add(4 * time.Hour)
	fleet := macs(10, "1.2.0", now.Add(-time.Minute), now)
	for i := range 6 {
		fleet[i].seen = seen
	}
	w, st := intuneWorker(t, now, fleet)
	// Retire one: five left trip, which isn't over the threshold, so they are raised.
	res, err := st.Enroll(ctx, store.DeviceCredential{
		DeviceID: "5f0c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f", TenantID: tenant, Serial: fleet[0].serial,
		HardwareUUID: "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D", PublicKey: []byte("key"), CreatedAt: seen.Add(-time.Hour),
	}, store.EnrollLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RevokeCredential(ctx, tenant, res.Credential.DeviceID, seen, audit(tenant)); err != nil {
		t.Fatal(err)
	}
	sweep(t, w, 5)
	if got := silences(t, st); got[fleet[0].serial] != "" {
		t.Fatalf("silences = %v", got)
	}
}

// brokenSettings is a store whose tenant settings can't be read.
type brokenSettings struct{ store.Store }

func (brokenSettings) TenantSettings(context.Context, string) (store.TenantSettings, error) {
	return store.TenantSettings{}, errors.New("settings unavailable")
}

// One tenant's settings error is reported once a sweep, however many of its Macs are quiet.
func TestSweepReportsASettingsErrorOnce(t *testing.T) {
	seen := testfixture.Time(t, "2026-10-16T09:00:00Z")
	w, st := intuneWorker(t, seen.Add(80*time.Hour), macs(3, "1.2.0", seen, seen.Add(3*time.Hour)))
	w.Store = brokenSettings{st}
	_, err := w.Sweep(context.Background())
	if err == nil || strings.Count(err.Error(), "settings unavailable") != 1 {
		t.Fatalf("err = %v", err)
	}
}
