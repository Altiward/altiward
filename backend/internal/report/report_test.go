package report_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/report"
	"github.com/Altiward/altiward/backend/internal/session"
	"github.com/Altiward/altiward/backend/internal/store"
)

var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) *time.Time {
	t := now.Add(-d)
	return &t
}

const day = 24 * time.Hour

// elevation is a session that started `start` ago, was allowed `allowed` (0: no expiry)
// and ended after `held` (0: still open).
func elevation(id, user, upn, serial string, source event.Source, start, allowed, held time.Duration) session.Session {
	s := session.New("acme", id)
	s.LocalUser, s.DeviceSerial, s.Source = user, serial, source
	if upn != "" {
		s.UPN = &upn
	}
	s.StartedAt = ago(start)
	if allowed > 0 {
		s.ExpiresAt = ago(start - allowed)
	}
	if held > 0 {
		s.EndedAt = ago(start - held)
	}
	return s
}

func build(t *testing.T, in report.Input) report.Overview {
	t.Helper()
	if in.Now.IsZero() {
		in.Now = now
	}
	if in.Days == 0 {
		in.Days = 30
	}
	return report.Build(in)
}

func TestNowCountsOpenSessionsBySourceAndAlerts(t *testing.T) {
	sessions := []session.Session{
		elevation("a", "jdoe", "", "MAC1", event.SourcePrivileges, 10*time.Minute, 20*time.Minute, 0),
		elevation("b", "mia", "", "MAC2", event.SourcePrivileges, 30*time.Minute, 20*time.Minute, 0), // past its expiry
		elevation("c", "sam", "", "MAC2", event.SourcePrivileges, 40*time.Minute, 30*time.Minute, 0), // past its expiry
		elevation("d", "backdoor", "", "MAC3", event.SourceOutOfBand, time.Hour, 0, 0),
		elevation("e", "old", "", "MAC1", event.SourcePrivileges, 2*day, 20*time.Minute, 10*time.Minute), // ended
	}
	failing := session.NewDevice("acme", "MAC1")
	failing.Integrity = map[string]bool{"code_signature": true, "settings_managed": false}
	silent := session.NewDevice("acme", "MAC2")
	silent.Silence = &session.Silence{State: event.SilentStateSilent, At: now}
	resumed := session.NewDevice("acme", "MAC3")
	resumed.Silence = &session.Silence{State: event.SilentStateResumed, At: now}
	resumed.Integrity = map[string]bool{"code_signature": true}

	o := build(t, report.Input{Sessions: sessions, Devices: []session.Device{failing, silent, resumed}})
	want := report.Now{Admins: 4, Privileges: 3, WithoutGrant: 1, PastExpiry: 2, MacsFailingChecks: 1, MacsSilent: 1}
	if o.Now != want {
		t.Fatalf("now = %+v, want %+v", o.Now, want)
	}
}

func TestPeriodBucketsElevationsBySource(t *testing.T) {
	sessions := []session.Session{
		elevation("a", "jdoe", "", "MAC1", event.SourcePrivileges, 10*time.Minute, 20*time.Minute, 0),
		elevation("b", "jdoe", "", "MAC1", event.SourcePrivileges, 2*time.Hour, 20*time.Minute, 5*time.Minute),
		elevation("c", "sam", "", "MAC2", event.SourcePrivileges, 3*day+time.Hour, 30*time.Minute, 30*time.Minute),
		elevation("d", "backdoor", "", "MAC3", event.SourceOutOfBand, 29*day+12*time.Hour, 0, 0),
		// Open but started before the period: counted now, not in the period.
		elevation("e", "admin", "", "MAC3", event.SourceOutOfBand, 40*day, 0, 0),
	}
	o := build(t, report.Input{Sessions: sessions})
	p := o.Period
	if p.Elevations != 4 || p.WithoutGrant != 1 || p.BucketDays != 1 || len(p.Buckets) != 30 {
		t.Fatalf("period = %d elevations, %d without a grant, %d-day buckets × %d", p.Elevations, p.WithoutGrant, p.BucketDays, len(p.Buckets))
	}
	if !o.Since.Equal(now.Add(-30*day)) || !p.Buckets[0].Start.Equal(o.Since) {
		t.Fatalf("since %v, first bucket %v", o.Since, p.Buckets[0].Start)
	}
	last := p.Buckets[29]
	if last.Privileges != 2 || last.WithoutGrant != 0 {
		t.Fatalf("last bucket = %+v", last)
	}
	if b := p.Buckets[26]; b.Privileges != 1 || b.WithoutGrant != 0 {
		t.Fatalf("bucket 26 = %+v", b)
	}
	if b := p.Buckets[0]; b.WithoutGrant != 1 {
		t.Fatalf("first bucket = %+v", b)
	}
}

func TestLongPeriodsUseWeeks(t *testing.T) {
	o := build(t, report.Input{Days: 90})
	if o.Period.BucketDays != 7 || len(o.Period.Buckets) != 13 {
		t.Fatalf("%d-day buckets × %d", o.Period.BucketDays, len(o.Period.Buckets))
	}
	if o.Days != 90 || o.Period.Buckets[12].Start.After(now) {
		t.Fatalf("days %d, last bucket %v", o.Days, o.Period.Buckets[12].Start)
	}
}

func TestDurationsComeFromEndedGrantsWithAnExpiry(t *testing.T) {
	sessions := []session.Session{
		elevation("a", "u1", "", "M", event.SourcePrivileges, 3*time.Hour, 20*time.Minute, 5*time.Minute),                 // back early
		elevation("b", "u2", "", "M", event.SourcePrivileges, 4*time.Hour, 20*time.Minute, 20*time.Minute),                // ran to expiry
		elevation("c", "u3", "", "M", event.SourcePrivileges, 5*time.Hour, 20*time.Minute, 19*time.Minute+30*time.Second), // under a minute early
		elevation("d", "u4", "", "M", event.SourcePrivileges, 10*time.Minute, 20*time.Minute, 0),                          // open: not counted
		elevation("f", "u6", "", "M", event.SourceOutOfBand, 2*time.Hour, 0, time.Hour),
	}
	o := build(t, report.Input{Sessions: sessions})
	if len(o.Period.Durations) != 1 {
		t.Fatalf("durations = %+v", o.Period.Durations)
	}
	p := o.Period.Durations[0]
	if p.Source != event.SourcePrivileges || p.Ended != 3 || p.GivenBackEarly != 1 {
		t.Fatalf("privileges = %+v", p)
	}
	if p.MedianHeldSeconds == nil || *p.MedianHeldSeconds != (19*time.Minute+30*time.Second).Seconds() ||
		p.MedianAllowedSeconds == nil || *p.MedianAllowedSeconds != 1200 {
		t.Fatalf("privileges medians = %v / %v", p.MedianHeldSeconds, p.MedianAllowedSeconds)
	}
	empty := build(t, report.Input{}).Period.Durations
	if len(empty) != 1 || empty[0].MedianHeldSeconds != nil || empty[0].Ended != 0 {
		t.Fatalf("no sessions = %+v", empty)
	}
}

func TestTopUsersAndMacs(t *testing.T) {
	var sessions []session.Session
	add := func(n int, user, upn, serial string) {
		for range n {
			id := user + serial + string(rune('a'+len(sessions)))
			sessions = append(sessions, elevation(id, user, upn, serial, event.SourcePrivileges, time.Hour, 20*time.Minute, 10*time.Minute))
		}
	}
	add(3, "jdoe", "jane@example.com", "MAC1")
	add(2, "jdoe", "jane@example.com", "MAC2")
	add(4, "admin", "", "MAC3")
	add(1, "admin", "", "MAC4")
	for i := range 6 {
		add(1, "u"+string(rune('a'+i)), "", "MAC9")
	}
	o := build(t, report.Input{Sessions: sessions})
	users, macs := o.Period.TopUsers, o.Period.TopMacs
	if len(users) != report.TopN || users[0] != (report.UserCount{Name: "jane@example.com", Elevations: 5, Macs: 2}) {
		t.Fatalf("top users = %+v", users)
	}
	// A local name without a UPN is one person per Mac, so it carries the Mac.
	if users[1] != (report.UserCount{Name: "admin", Serial: "MAC3", Elevations: 4, Macs: 1}) {
		t.Fatalf("second user = %+v", users[1])
	}
	if len(macs) != report.TopN || macs[0] != (report.MacCount{Serial: "MAC9", Elevations: 6, People: 6}) ||
		macs[1] != (report.MacCount{Serial: "MAC3", Elevations: 4, People: 1}) {
		t.Fatalf("top macs = %+v", macs)
	}
}

func TestHealthCountsVersionsAndSinks(t *testing.T) {
	mac := func(serial, version string) session.Device {
		d := session.NewDevice("acme", serial)
		d.AgentVersion = version
		return d
	}
	devices := []session.Device{mac("A", "0.9.2"), mac("B", "0.9.2"), mac("C", "0.10.0"), mac("D", "0.0.4"), mac("E", "")}
	delivered := now.Add(-time.Minute)
	sinks := []store.ExportBacklog{
		{Sink: "sentinel", LastDeliveredAt: &delivered},
		{Sink: "splunk", Pending: 40, OldestAt: ago(20 * time.Minute), LastDeliveredAt: &delivered},
		{Sink: "syslog", Pending: 3, Failing: 3, LastError: "connection refused", OldestAt: ago(time.Minute)},
		{Sink: "fresh", Pending: 2, OldestAt: ago(time.Minute)},
		{Sink: "unused"},
	}
	o := build(t, report.Input{Devices: devices, Sinks: sinks})
	h := o.Health
	if h.Macs != 5 || h.AgentsOutdated != 1 {
		t.Fatalf("macs %d, outdated %d", h.Macs, h.AgentsOutdated)
	}
	got, _ := json.Marshal(h.AgentVersions)
	want := `[{"version":"0.10.0","macs":1,"supported":true},{"version":"0.9.2","macs":2,"supported":true},` +
		`{"version":"0.0.4","macs":1,"supported":false},{"version":"","macs":1,"supported":true}]`
	if string(got) != want {
		t.Fatalf("versions = %s", got)
	}
	states := map[string]string{}
	for _, s := range h.Sinks {
		states[s.Sink] = s.State
	}
	wantStates := map[string]string{"sentinel": "delivering", "splunk": "behind", "syslog": "failing", "fresh": "delivering", "unused": "idle"}
	for sink, state := range wantStates {
		if states[sink] != state {
			t.Errorf("%s: %q, want %q", sink, states[sink], state)
		}
	}
}

func TestPeriodIsOneOfTheOffered(t *testing.T) {
	for _, d := range []int{7, 30, 90} {
		if !report.ValidDays(d) {
			t.Errorf("%d refused", d)
		}
	}
	for _, d := range []int{0, 1, 31, 365} {
		if report.ValidDays(d) {
			t.Errorf("%d accepted", d)
		}
	}
}
