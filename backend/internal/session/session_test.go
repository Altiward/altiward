package session_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/session"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func TestGrantThenRevoke(t *testing.T) {
	granted := testfixture.Event(t, "elevation-granted")
	revoked := testfixture.Event(t, "elevation-revoked")
	s := session.New("t1", *granted.SessionID)
	s.Apply(granted)
	if !s.Open() || *s.Reason != "Installing Xcode command line tools" || *s.UPN != "jane.doe@example.com" {
		t.Fatalf("after grant: %+v", s)
	}
	if got := *s.AllowedDuration(); got != 20*time.Minute {
		t.Fatalf("allowed = %v", got)
	}
	s.Apply(revoked)
	if s.Open() || *s.EndReason != session.EndRevoked {
		t.Fatalf("after revoke: %+v", s)
	}
	actual := *s.ActualDuration(time.Now())
	if actual != revoked.Timestamp.Sub(granted.Timestamp) {
		t.Fatalf("actual = %v", actual)
	}
	if !s.Verified || len(s.Flags) != 0 || s.EventCount != 2 {
		t.Fatalf("flags = %v verified = %v count = %d", s.Flags, s.Verified, s.EventCount)
	}
}

func TestNewestGrantSetsTheExpiryInAnyOrder(t *testing.T) {
	first := testfixture.Event(t, "elevation-granted")
	shortened := first
	shortened.EventID = "0b6f6a52-6a0e-4d3e-9f5e-3f2a1c9d7e03"
	shortened.Timestamp = first.Timestamp.Add(5 * time.Minute)
	sooner := first.Elevation.Expires.Add(-10 * time.Minute)
	shortened.Elevation = &event.Elevation{Source: event.SourcePrivileges, Expires: &sooner}
	shortened.Detail = map[string]any{"renewed": true}
	unlimited := shortened
	unlimited.EventID = "0b6f6a52-6a0e-4d3e-9f5e-3f2a1c9d7e04"
	unlimited.Timestamp = first.Timestamp.Add(10 * time.Minute)
	unlimited.Elevation = &event.Elevation{Source: event.SourcePrivileges}

	// A renewal that shortens the expiry is what the agent enforces, so the session shows it.
	for _, order := range [][]event.Event{{first, shortened}, {shortened, first}} {
		s := session.New("t1", *first.SessionID)
		for _, e := range order {
			s.Apply(e)
		}
		if !s.ExpiresAt.Equal(sooner) {
			t.Fatalf("expires = %v, want %v", s.ExpiresAt, sooner)
		}
	}
	// A newer grant with no expiry clears it.
	for _, order := range [][]event.Event{{first, shortened, unlimited}, {unlimited, first, shortened}} {
		s := session.New("t1", *first.SessionID)
		for _, e := range order {
			s.Apply(e)
		}
		if s.ExpiresAt != nil {
			t.Fatalf("expires = %v, want none", s.ExpiresAt)
		}
	}
}

func TestOutOfOrderDeliveryGivesSameResult(t *testing.T) {
	granted := testfixture.Event(t, "elevation-granted")
	revoked := testfixture.Event(t, "elevation-revoked")
	a := session.New("t1", *granted.SessionID)
	a.Apply(granted)
	a.Apply(revoked)
	b := session.New("t1", *granted.SessionID)
	b.Apply(revoked)
	b.Apply(granted)
	if *a.StartedAt != *b.StartedAt || *a.EndedAt != *b.EndedAt || *a.Reason != *b.Reason || a.LastEventAt != b.LastEventAt {
		t.Fatalf("a = %+v\nb = %+v", a, b)
	}
}

func TestRenewalExtendsExpiry(t *testing.T) {
	first := testfixture.Event(t, "elevation-granted")
	second := first
	second.EventID = "0b6f6a52-6a0e-4d3e-9f5e-3f2a1c9d7e02"
	second.Timestamp = first.Timestamp.Add(15 * time.Minute)
	later := first.Elevation.Expires.Add(15 * time.Minute)
	second.Elevation = &event.Elevation{Source: event.SourcePrivileges, Expires: &later}
	second.Detail = map[string]any{"renewed": true}

	s := session.New("t1", *first.SessionID)
	s.Apply(first)
	s.Apply(second)
	if s.Renewals != 1 || !s.ExpiresAt.Equal(later) || !s.StartedAt.Equal(first.Timestamp) {
		t.Fatalf("session = %+v", s)
	}
}

func TestFlags(t *testing.T) {
	revoked := testfixture.Event(t, "elevation-revoked")
	revoked.Detail = map[string]any{"verified": false, "orphan": true, "inferred": true}
	s := session.New("t1", *revoked.SessionID)
	s.Apply(revoked)
	want := []string{session.FlagInferredEnd, session.FlagOrphanRevoke, session.FlagUnverifiedClaim}
	if !slices.Equal(s.Flags, want) || s.Verified || *s.EndReason != session.EndInferred {
		t.Fatalf("flags = %v verified = %v end = %v", s.Flags, s.Verified, *s.EndReason)
	}
	if s.StartedAt != nil || s.ActualDuration(time.Now()) != nil {
		t.Fatal("a revoke alone must not invent a start")
	}
}

func TestOutOfBand(t *testing.T) {
	oob := testfixture.Event(t, "admin-out-of-band")
	s := session.New("t1", *oob.SessionID)
	s.Apply(oob)
	if s.Source != event.SourceOutOfBand || !slices.Contains(s.Flags, session.FlagOutOfBand) || !s.Open() {
		t.Fatalf("session = %+v", s)
	}
}

func TestEnforcedExpiryWinsTieWithRevoke(t *testing.T) {
	revoked := testfixture.Event(t, "elevation-revoked")
	enforced := revoked
	enforced.Type = event.ElevationExpiredEnforced
	s := session.New("t1", *revoked.SessionID)
	s.Apply(revoked)
	s.Apply(enforced)
	if *s.EndReason != session.EndExpiredEnforced {
		t.Fatalf("end = %v", *s.EndReason)
	}
}

func TestOverdueFlagsOpenSessionThenEnforcedExpiryEndsIt(t *testing.T) {
	granted := testfixture.Event(t, "elevation-granted")
	overdue := testfixture.Event(t, "elevation-overdue")
	enforced := testfixture.Event(t, "elevation-expired-enforced")

	s := session.New("t1", *granted.SessionID)
	s.Apply(granted)
	s.Apply(overdue)
	if !s.Open() || !slices.Equal(s.Flags, []string{session.FlagOverdue}) {
		t.Fatalf("after overdue: open = %v flags = %v", s.Open(), s.Flags)
	}
	s.Apply(enforced)
	if s.Open() || *s.EndReason != session.EndExpiredEnforced || !s.EndedAt.Equal(enforced.Timestamp) {
		t.Fatalf("after enforcement: %+v", s)
	}

	reordered := session.New("t1", *granted.SessionID)
	for _, e := range []event.Event{enforced, overdue, granted} {
		reordered.Apply(e)
	}
	if reordered.Open() || *reordered.EndReason != session.EndExpiredEnforced ||
		!slices.Equal(reordered.Flags, s.Flags) || !reordered.StartedAt.Equal(*s.StartedAt) {
		t.Fatalf("out of order: %+v", reordered)
	}
}

func TestRemoteRevokeEndsSessionWithItsOwnReason(t *testing.T) {
	granted := testfixture.Event(t, "elevation-granted")
	revoked := testfixture.Event(t, "elevation-revoked")
	revoked.Detail = map[string]any{"trigger": "command", "command_id": "8c1d2e3f-4a5b-4c6d-9e7f-0a1b2c3d4e5f",
		"observed_admin": false, "verified": true}
	s := session.New("t1", *granted.SessionID)
	s.Apply(granted)
	s.Apply(revoked)
	if s.Open() || *s.EndReason != session.EndRemoteRevoke {
		t.Fatalf("end = %v", s.EndReason)
	}
}

func TestDeviceRecordsPermanentAdmins(t *testing.T) {
	health := testfixture.Event(t, "agent-health")
	d := session.NewDevice("t1", health.Device.Serial)
	if d.PermanentAdmins == nil || len(d.PermanentAdmins) != 0 {
		t.Fatalf("new device permanent admins = %v, want empty list", d.PermanentAdmins)
	}
	d.Apply(health)
	if !slices.Equal(d.PermanentAdmins, []string{"itadmin"}) {
		t.Fatalf("permanent admins = %v", d.PermanentAdmins)
	}
}

func TestDeviceKeepsNewestHealth(t *testing.T) {
	health := testfixture.Event(t, "agent-health")
	older := health
	older.Timestamp = health.Timestamp.Add(-time.Hour)
	older.Detail = map[string]any{"admin_members": []any{"stale"}}

	d := session.NewDevice("t1", health.Device.Serial)
	d.Apply(health)
	d.Apply(older)
	if !slices.Equal(d.AdminMembers, []string{"backdoor", "itadmin"}) {
		t.Fatalf("admins = %v", d.AdminMembers)
	}
	if !d.FirstSeenAt.Equal(older.Timestamp) || !d.LastSeenAt.Equal(health.Timestamp) {
		t.Fatalf("seen = %v .. %v", d.FirstSeenAt, d.LastSeenAt)
	}
}

func TestPermanentAdminEndsAnOutOfBandSession(t *testing.T) {
	found := testfixture.Event(t, "admin-out-of-band")
	ended := testfixture.Event(t, "elevation-revoked-permanent-admin")
	// Either order: the reducers are order-independent.
	for _, events := range [][]event.Event{{found, ended}, {ended, found}} {
		s := session.New("t1", *found.SessionID)
		for _, e := range events {
			s.Apply(e)
		}
		if s.Open() || *s.EndReason != session.EndPermanentAdmin || s.Source != event.SourceOutOfBand ||
			!s.Verified {
			t.Fatalf("session = %+v", s)
		}
	}
}

func TestOutOfBandRemovedEndsTheSession(t *testing.T) {
	found := testfixture.Event(t, "admin-out-of-band")
	removed := testfixture.Event(t, "admin-out-of-band-removed")
	for _, events := range [][]event.Event{{found, removed}, {removed, found}} {
		s := session.New("t1", *found.SessionID)
		for _, e := range events {
			s.Apply(e)
		}
		if s.Open() || *s.EndReason != session.EndOutOfBandRemoved ||
			!s.EndedAt.Equal(time.Date(2026, 10, 16, 10, 5, 0, 0, time.UTC)) ||
			s.Source != event.SourceOutOfBand || !slices.Contains(s.Flags, session.FlagOutOfBand) {
			t.Fatalf("session = %+v", s)
		}
	}
}

func TestOutOfBandRemovedEndReasonValue(t *testing.T) {
	if session.EndOutOfBandRemoved != "out_of_band_removed" {
		t.Fatalf("end reason = %q", session.EndOutOfBandRemoved)
	}
}

func TestOutOfBandRemovedWinsTieWithRevoke(t *testing.T) {
	removed := testfixture.Event(t, "admin-out-of-band-removed")
	revoked := testfixture.Event(t, "elevation-revoked")
	revoked.SessionID = removed.SessionID
	revoked.User = removed.User
	revoked.Timestamp = removed.Timestamp
	revoked.Detail = map[string]any{"inferred": true}
	for _, events := range [][]event.Event{{removed, revoked}, {revoked, removed}} {
		s := session.New("t1", *removed.SessionID)
		for _, e := range events {
			s.Apply(e)
		}
		if *s.EndReason != session.EndOutOfBandRemoved {
			t.Fatalf("end = %v", *s.EndReason)
		}
	}
}

func TestPrivilegesGrantEndsAnOutOfBandSession(t *testing.T) {
	found := testfixture.Event(t, "admin-out-of-band")
	ended := testfixture.Event(t, "elevation-revoked-privileges-grant")
	for _, events := range [][]event.Event{{found, ended}, {ended, found}} {
		s := session.New("t1", *found.SessionID)
		for _, e := range events {
			s.Apply(e)
		}
		if s.Open() || *s.EndReason != session.EndPrivilegesGrant || s.Source != event.SourceOutOfBand ||
			!s.Verified || slices.Contains(s.Flags, session.FlagInferredEnd) {
			t.Fatalf("session = %+v", s)
		}
	}
}

func TestGrantThatReplacedAnOutOfBandSessionIsFlagged(t *testing.T) {
	granted := testfixture.Event(t, "elevation-granted")
	granted.Detail["replaced_out_of_band"] = true
	revoked := testfixture.Event(t, "elevation-revoked")
	for _, events := range [][]event.Event{{granted, revoked}, {revoked, granted}} {
		s := session.New("t1", *granted.SessionID)
		for _, e := range events {
			s.Apply(e)
		}
		if !slices.Equal(s.Flags, []string{session.FlagAfterOutOfBand}) || *s.EndReason != session.EndRevoked {
			t.Fatalf("session = %+v", s)
		}
	}
}

// tamperAlerts makes n agent.tamper events a minute apart, with distinct IDs.
func tamperAlerts(t *testing.T, n int) []event.Event {
	base := testfixture.Event(t, "agent-tamper")
	out := make([]event.Event, n)
	for i := range out {
		e := base
		e.EventID = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		e.Timestamp = base.Timestamp.Add(time.Duration(i) * time.Minute)
		out[i] = e
	}
	return out
}

func TestDeviceTamperAlertsAreNewestFirstCappedAndOrderIndependent(t *testing.T) {
	events := tamperAlerts(t, session.MaxRecentAlerts+5)
	forward := session.NewDevice("t1", events[0].Device.Serial)
	for _, e := range events {
		forward.Apply(e)
	}
	backward := session.NewDevice("t1", events[0].Device.Serial)
	for i := len(events) - 1; i >= 0; i-- {
		backward.Apply(events[i])
	}
	if len(forward.RecentTamper) != session.MaxRecentAlerts {
		t.Fatalf("kept %d", len(forward.RecentTamper))
	}
	if forward.RecentTamper[0].EventID != events[len(events)-1].EventID {
		t.Fatalf("newest first: got %s", forward.RecentTamper[0].EventID)
	}
	if !slices.EqualFunc(forward.RecentTamper, backward.RecentTamper, func(a, b session.TamperAlert) bool {
		return a.EventID == b.EventID
	}) {
		t.Fatal("delivery order changed the kept alerts")
	}
}

func TestDeviceKeepsIntegrityFromNewestHealth(t *testing.T) {
	health := testfixture.Event(t, "agent-health")
	d := session.NewDevice("t1", health.Device.Serial)
	if d.Integrity != nil {
		t.Fatalf("new device integrity = %v, want nil until reported", d.Integrity)
	}
	d.Apply(health)
	if d.Integrity["settings_managed"] != false || d.Integrity["code_signature"] != true || len(d.Integrity) != 9 {
		t.Fatalf("integrity = %v", d.Integrity)
	}
	older := health
	older.Timestamp = health.Timestamp.Add(-time.Hour)
	older.Detail = map[string]any{"integrity": map[string]any{"settings_managed": true}}
	d.Apply(older)
	if d.Integrity["settings_managed"] != false {
		t.Fatal("an older reading replaced the newest")
	}
}

func TestDeviceKeepsPersistenceBlindSpotsFromNewestHealth(t *testing.T) {
	health := testfixture.Event(t, "agent-health")
	d := session.NewDevice("t1", health.Device.Serial)
	if d.PersistenceUnreadable != nil {
		t.Fatalf("new device = %v, want nil until reported", d.PersistenceUnreadable)
	}
	d.Apply(health)
	if d.PersistenceUnreadable == nil || len(d.PersistenceUnreadable) != 0 {
		t.Fatalf("fixture reads everything: got %#v, want empty", d.PersistenceUnreadable)
	}

	blind := health
	blind.Timestamp = health.Timestamp.Add(time.Minute)
	blind.Detail = map[string]any{"persistence_unreadable": []any{"/Users/jdoe/.ssh/authorized_keys"}}
	d.Apply(blind)
	if !slices.Equal(d.PersistenceUnreadable, []string{"/Users/jdoe/.ssh/authorized_keys"}) {
		t.Fatalf("unreadable = %v", d.PersistenceUnreadable)
	}

	older := health
	older.Timestamp = health.Timestamp.Add(-time.Hour)
	d.Apply(older)
	if len(d.PersistenceUnreadable) != 1 {
		t.Fatal("an older reading replaced the newest")
	}

	// An agent without the check (older, or downgraded) makes it unknown again.
	before := health
	before.Timestamp = blind.Timestamp.Add(time.Minute)
	before.Detail = map[string]any{"admin_members": []any{}}
	d.Apply(before)
	if d.PersistenceUnreadable != nil {
		t.Fatalf("unreadable = %#v, want nil", d.PersistenceUnreadable)
	}
}

func TestDeviceRecordsTheLatestReceiveTime(t *testing.T) {
	health := testfixture.Event(t, "agent-health")
	d := session.NewDevice("t1", health.Device.Serial)
	d.Apply(health)
	if !d.CheckedInAt().Equal(health.Timestamp) {
		t.Fatal("without a receive time, the Mac's timestamp stands")
	}
	later, earlier := health.Timestamp.Add(time.Hour), health.Timestamp.Add(time.Minute)
	d.Received(health, later)
	d.Received(health, earlier) // a batch handled out of order
	if !d.LastReceivedAt.Equal(later) || !d.CheckedInAt().Equal(later) {
		t.Fatalf("received = %v", d.LastReceivedAt)
	}
	d.Received(testfixture.Event(t, "agent-silent"), later.Add(time.Hour))
	if !d.LastReceivedAt.Equal(later) {
		t.Fatal("an event the server raised counted as a check-in")
	}
}

func TestDeviceStoredBeforeReceiveTimesStillDecodes(t *testing.T) {
	var d session.Device
	if err := json.Unmarshal([]byte(`{"serial":"C02XK0AAJGH5","last_seen_at":"2026-10-16T10:05:00Z"}`), &d); err != nil {
		t.Fatal(err)
	}
	if !d.LastReceivedAt.IsZero() || !d.CheckedInAt().Equal(testfixture.Time(t, "2026-10-16T10:05:00Z")) {
		t.Fatalf("device = %+v", d)
	}
	b, _ := json.Marshal(session.NewDevice("t1", "C02XK0AAJGH5"))
	if strings.Contains(string(b), "last_received_at") {
		t.Fatalf("an unknown receive time was written: %s", b)
	}
}

func TestDeviceKeepsRecentTamperAlerts(t *testing.T) {
	tamper := testfixture.Event(t, "agent-tamper")
	d := session.NewDevice("t1", tamper.Device.Serial)
	d.Apply(tamper)
	d.Apply(tamper)
	if len(d.RecentTamper) != 1 {
		t.Fatalf("alerts = %+v", d.RecentTamper)
	}
	a := d.RecentTamper[0]
	if a.Check != "settings_managed" || a.State != "failed" || a.Problem == nil ||
		*a.Problem != "set outside MDM: PermanentAdmins" || !a.At.Equal(tamper.Timestamp) {
		t.Fatalf("alert = %+v", a)
	}
}

func TestDeviceSilenceIsNotACheckIn(t *testing.T) {
	health := testfixture.Event(t, "agent-health")
	silent := testfixture.Event(t, "agent-silent")
	silent.Device.AgentVersion = "0.0.1"

	d := session.NewDevice("t1", health.Device.Serial)
	d.Apply(health)
	d.Apply(silent)
	if !d.LastSeenAt.Equal(health.Timestamp) || d.AgentVersion != health.Device.AgentVersion {
		t.Fatalf("last seen = %v, agent = %s: a backend event moved them", d.LastSeenAt, d.AgentVersion)
	}
	if !d.Silent() || d.Silence.EventID != silent.EventID ||
		!d.Silence.LastSeenAt.Equal(testfixture.Time(t, "2026-10-13T09:00:00Z")) {
		t.Fatalf("silence = %+v", d.Silence)
	}
}

func TestDeviceSilenceKeepsNewestStateInAnyOrder(t *testing.T) {
	silent := testfixture.Event(t, "agent-silent")
	resumed := silent
	resumed.EventID = "4a7e2d3b-9c5f-5b80-8d1e-2f3a4b5c6d7e"
	resumed.Timestamp = silent.Timestamp.Add(time.Hour)
	resumed.Detail = map[string]any{"state": "resumed", "last_seen_at": "2026-10-16T11:55:00Z"}

	for _, order := range [][]event.Event{{silent, resumed}, {resumed, silent}} {
		d := session.NewDevice("t1", silent.Device.Serial)
		for _, e := range order {
			d.Apply(e)
		}
		if d.Silent() || d.Silence.EventID != resumed.EventID {
			t.Fatalf("silence = %+v", d.Silence)
		}
	}
}

func TestDeviceSilenceKeepsItsBasis(t *testing.T) {
	early := testfixture.Event(t, "agent-silent-mdm")
	d := session.NewDevice("t1", early.Device.Serial)
	d.Apply(early)
	if !d.Silent() || d.Silence.Basis != "mdm_check_in" {
		t.Fatalf("silence = %+v", d.Silence)
	}
	d = session.NewDevice("t1", early.Device.Serial)
	d.Apply(testfixture.Event(t, "agent-silent"))
	if d.Silence.Basis != "no_contact" {
		t.Fatalf("silence = %+v", d.Silence)
	}
	// Stored before the basis was recorded: empty, which means no_contact.
	var old session.Device
	if err := json.Unmarshal([]byte(`{"serial":"C02XK0AAJGH5","silence":{"event_id":"x","state":"silent"}}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.Silence.Basis != "" {
		t.Fatalf("silence = %+v", old.Silence)
	}
}

// A downgrade doesn't lower the version the Mac is known to have run, in any order.
func TestDeviceKeepsTheHighestAgentVersion(t *testing.T) {
	newer := testfixture.Event(t, "agent-health")
	newer.Device.AgentVersion = "1.2.0"
	older := testfixture.Event(t, "agent-health")
	older.EventID = "0b5e0f3a-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	older.Timestamp = newer.Timestamp.Add(time.Hour)
	older.Device.AgentVersion = "1.1.0"
	unreadable := testfixture.Event(t, "agent-health")
	unreadable.EventID = "1c6f1a4b-2d3e-4f5a-9b0c-1d2e3f4a5b6c"
	unreadable.Timestamp = newer.Timestamp.Add(2 * time.Hour)
	unreadable.Device.AgentVersion = "dev"
	silent := testfixture.Event(t, "agent-silent")
	silent.Device.AgentVersion = "9.0.0"

	for _, order := range [][]event.Event{{newer, older, unreadable, silent}, {silent, unreadable, older, newer}} {
		d := session.NewDevice("t1", newer.Device.Serial)
		for _, e := range order {
			d.Apply(e)
		}
		if d.AgentVersion != "dev" || d.HighestAgentVersion != "1.2.0" {
			t.Fatalf("agent = %s, highest = %s", d.AgentVersion, d.HighestAgentVersion)
		}
	}
}

// Versions that read the same are ordered by their text, and an over-long one is ignored,
// so the highest doesn't depend on the order events arrive in.
func TestDeviceHighestAgentVersionIgnoresLongAndTiedVersions(t *testing.T) {
	a := testfixture.Event(t, "agent-health")
	a.Device.AgentVersion = "1.2.0+a"
	b := testfixture.Event(t, "agent-health")
	b.EventID = "0b5e0f3a-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	b.Device.AgentVersion = "1.2.0+b"
	long := testfixture.Event(t, "agent-health")
	long.EventID = "1c6f1a4b-2d3e-4f5a-9b0c-1d2e3f4a5b6c"
	long.Device.AgentVersion = "9.0.0+" + strings.Repeat("x", 59) // 65 bytes
	for _, order := range [][]event.Event{{a, b, long}, {long, b, a}} {
		d := session.NewDevice("t1", a.Device.Serial)
		for _, e := range order {
			d.Apply(e)
		}
		if d.HighestAgentVersion != "1.2.0+b" {
			t.Fatalf("highest = %s", d.HighestAgentVersion)
		}
	}
}
