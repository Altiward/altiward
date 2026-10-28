package admingroup_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/admingroup"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

const tenant = "acme"

var secret = []byte("0123456789abcdef0123456789abcdef")

// reading is the agent-health fixture with another event ID, a time five minutes on per
// step and the given admin group.
func reading(t *testing.T, step int, members ...string) event.Event {
	t.Helper()
	e := testfixture.Event(t, "agent-health")
	e.EventID = fmt.Sprintf("3e9c9d85-9d3b-4a6b-8c8b-%012d", step)
	e.Timestamp = e.Timestamp.Add(time.Duration(step) * 5 * time.Minute)
	list := make([]any, len(members))
	for i, m := range members {
		list[i] = m
	}
	e.Detail["admin_members"] = list
	return e
}

// raised checks that e is a valid agent.admin_group event and returns its detail.
func raised(t *testing.T, e event.Event, now time.Time) map[string]any {
	t.Helper()
	if e.Type != event.AgentAdminGroup {
		t.Fatalf("type = %q", e.Type)
	}
	if err := e.Validate(now); err != nil {
		t.Fatalf("raised an invalid event: %v\n%+v", err, e)
	}
	return e.Detail
}

func names(t *testing.T, v any) []string {
	t.Helper()
	list, ok := v.([]any)
	if !ok {
		t.Fatalf("not a JSON list: %#v", v)
	}
	out := []string{}
	for _, item := range list {
		out = append(out, item.(string))
	}
	return out
}

func TestOnHealthFirstReadingIsASnapshot(t *testing.T) {
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	health := testfixture.Event(t, "agent-health")
	e, next, ok := admingroup.OnHealth(nil, health, tenant, secret, now)
	if !ok {
		t.Fatal("the first reading raised nothing")
	}
	d := raised(t, e, now)
	if e.EventID != admingroup.ID(secret, tenant, health.Device.Serial, "first/"+health.EventID) {
		t.Fatalf("event ID %s isn't keyed by the reading", e.EventID)
	}
	if !e.Timestamp.Equal(now) || e.Device != health.Device || e.SessionID != nil || e.User != nil {
		t.Fatalf("event = %+v, want the server's time and the reading's device", e)
	}
	if d["state"] != event.AdminGroupSnapshot || !slices.Equal(names(t, d["members"]), []string{"backdoor", "itadmin"}) ||
		!slices.Equal(names(t, d["permanent_admins"]), []string{"itadmin"}) || d["health_event_id"] != health.EventID ||
		d["as_of"] != "2026-10-16T10:05:00Z" || d["truncated"] != float64(0) {
		t.Fatalf("detail = %v", d)
	}
	if _, has := d["added"]; has {
		t.Fatalf("a snapshot lists who was added: %v", d)
	}
	want := admingroup.Report{Members: []string{"backdoor", "itadmin"}, PermanentAdmins: []string{"itadmin"},
		HealthEventID: health.EventID, AsOf: health.Timestamp}
	if !reportsEqual(next, want) {
		t.Fatalf("next = %+v, want %+v", next, want)
	}
}

func TestOnHealthSameMembersRaiseNothing(t *testing.T) {
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	_, prev, _ := admingroup.OnHealth(nil, reading(t, 0, "itadmin", "backdoor"), tenant, secret, now)
	// The order, a repeat and a change to the standing admins alone are no change.
	again := reading(t, 1, "itadmin", "backdoor", "itadmin")
	again.Detail["permanent_admins"] = []any{}
	e, next, ok := admingroup.OnHealth(&prev, again, tenant, secret, now)
	if ok || e.EventID != "" {
		t.Fatalf("raised %+v", e)
	}
	if !reportsEqual(next, prev) {
		t.Fatalf("next = %+v, want the group last reported, %+v", next, prev)
	}
}

func TestRefreshedKeepsTheMembersAndTakesTheReading(t *testing.T) {
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	first := reading(t, 0, "itadmin", "backdoor")
	_, prev, _ := admingroup.OnHealth(nil, first, tenant, secret, now)
	again := reading(t, 1, "itadmin", "backdoor", "itadmin")
	again.Detail["permanent_admins"] = []any{"itadmin"}
	got := admingroup.Refreshed(prev, again)
	if !slices.Equal(got.Members, prev.Members) || !slices.Equal(got.PermanentAdmins, []string{"itadmin"}) ||
		got.HealthEventID != again.EventID || !got.AsOf.Equal(again.Timestamp) || got.Truncated != 0 {
		t.Fatalf("refreshed = %+v, from %+v", got, prev)
	}
}

func TestOnHealthAddedAndRemovedGiveChanged(t *testing.T) {
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	_, prev, _ := admingroup.OnHealth(nil, reading(t, 0, "backdoor", "itadmin"), tenant, secret, now)
	health := reading(t, 1, "itadmin", "jdoe")
	e, next, ok := admingroup.OnHealth(&prev, health, tenant, secret, now)
	if !ok {
		t.Fatal("a changed group raised nothing")
	}
	d := raised(t, e, now)
	if e.EventID != admingroup.ID(secret, tenant, health.Device.Serial, "changed/"+health.EventID) {
		t.Fatalf("event ID %s isn't keyed by the reading", e.EventID)
	}
	if d["state"] != event.AdminGroupChanged || !slices.Equal(names(t, d["members"]), []string{"itadmin", "jdoe"}) ||
		!slices.Equal(names(t, d["removed"]), []string{"backdoor"}) || d["health_event_id"] != health.EventID {
		t.Fatalf("detail = %v", d)
	}
	// jdoe has no open session in the reading, so only the name.
	added, _ := d["added"].([]any)
	if len(added) != 1 || fmt.Sprint(added[0]) != fmt.Sprint(map[string]any{"name": "jdoe"}) {
		t.Fatalf("added = %#v", d["added"])
	}
	if !slices.Equal(next.Members, []string{"itadmin", "jdoe"}) || next.HealthEventID != health.EventID {
		t.Fatalf("next = %+v", next)
	}

	// Nobody added: added is an empty list, not missing.
	later := reading(t, 2, "jdoe")
	e, _, _ = admingroup.OnHealth(&next, later, tenant, secret, now)
	d = raised(t, e, now)
	if a, ok := d["added"].([]any); !ok || len(a) != 0 || !slices.Equal(names(t, d["removed"]), []string{"itadmin"}) {
		t.Fatalf("detail = %v", d)
	}
}

func TestOnHealthLinksAnAddedUserToTheirOpenSession(t *testing.T) {
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	_, prev, _ := admingroup.OnHealth(nil, reading(t, 0, "itadmin"), tenant, secret, now)
	health := reading(t, 1, "itadmin", "jdoe", "msmith", "oob")
	health.Detail["open_sessions"] = []any{
		map[string]any{"user": "jdoe", "session_id": "5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d", "source": "privileges"},
		map[string]any{"user": "oob", "session_id": "7f3a9c2e-1d4b-4e8a-9b60-5c2d8e1f4a37", "source": "out_of_band"},
		// Not a session ID, so not linked.
		map[string]any{"user": "msmith", "session_id": "not-a-session", "source": "privileges"},
		map[string]any{"user": "itadmin", "session_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d", "source": "privileges"},
	}
	e, _, _ := admingroup.OnHealth(&prev, health, tenant, secret, now)
	d := raised(t, e, now)
	added, _ := d["added"].([]any)
	got, _ := json.Marshal(added)
	want := `[{"name":"jdoe","session_id":"5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d","source":"privileges"},` +
		`{"name":"msmith"},{"name":"oob","session_id":"7f3a9c2e-1d4b-4e8a-9b60-5c2d8e1f4a37","source":"out_of_band"}]`
	if string(got) != want {
		t.Fatalf("added = %s\nwant    %s", got, want)
	}
}

// An oversized group is capped and never fails ingest (the pure half: what is raised is
// within the limits Validate sets).
func TestFromHealthCapsAnOversizedGroup(t *testing.T) {
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	many := make([]string, 0, 10_000)
	for i := range 10_000 {
		many = append(many, fmt.Sprintf("u%05d", i))
	}
	// Duplicates, empty and over-long names are dropped, not counted as left out.
	health := reading(t, 0, append(many, "u00001", "", strings.Repeat("x", event.MaxNameLength+1))...)
	r, truncated := admingroup.FromHealth(health)
	if len(r.Members) != event.MaxAdminGroupPeople || truncated != 10_000-event.MaxAdminGroupPeople ||
		r.Members[0] != "u00000" || r.Members[199] != "u00199" {
		t.Fatalf("members = %d (%v...), truncated = %d", len(r.Members), r.Members[:3], truncated)
	}
	e, next, ok := admingroup.OnHealth(nil, health, tenant, secret, now)
	d := raised(t, e, now)
	if !ok || len(d["members"].([]any)) != 200 || d["truncated"] != float64(9_800) || next.Truncated != 9_800 {
		t.Fatalf("members = %d, truncated = %v, next.Truncated = %d", len(d["members"].([]any)), d["truncated"], next.Truncated)
	}
}

// Names near the length limit, in three lists of 200, are more than an event may hold:
// people are left out and counted until it fits.
func TestOnHealthFitsAChangeOfLongNames(t *testing.T) {
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	long := func(prefix string) []string {
		out := []string{}
		for i := range event.MaxAdminGroupPeople {
			out = append(out, fmt.Sprintf("%s%03d%s", prefix, i, strings.Repeat("x", event.MaxNameLength-4)))
		}
		return out
	}
	_, prev, _ := admingroup.OnHealth(nil, reading(t, 0, long("a")...), tenant, secret, now)
	e, next, ok := admingroup.OnHealth(&prev, reading(t, 1, long("b")...), tenant, secret, now)
	if !ok {
		t.Fatal("raised nothing")
	}
	d := raised(t, e, now)
	left := 3*200 - len(d["members"].([]any)) - len(d["added"].([]any)) - len(d["removed"].([]any))
	if left == 0 || d["truncated"] != float64(left) {
		t.Fatalf("truncated = %v, want the %d people left out", d["truncated"], left)
	}
	// What is reported as the group stays the whole reading.
	if len(next.Members) != 200 || next.Truncated != 0 {
		t.Fatalf("next = %d members, truncated %d", len(next.Members), next.Truncated)
	}
}

func TestIDIsStableAndKeyedBySecret(t *testing.T) {
	id := admingroup.ID(secret, tenant, "C02XK0AAJGH5", "first/3e9c9d85-9d3b-4a6b-8c8b-6c5d4f2a0b34")
	if again := admingroup.ID(secret, tenant, "C02XK0AAJGH5", "first/3e9c9d85-9d3b-4a6b-8c8b-6c5d4f2a0b34"); again != id {
		t.Fatalf("the same inputs gave %s and %s", id, again)
	}
	want := event.RaisedID(hex.EncodeToString(secret) + "/acme/C02XK0AAJGH5/admin_group/first/3e9c9d85-9d3b-4a6b-8c8b-6c5d4f2a0b34")
	if id != want {
		t.Fatalf("ID = %s, want %s", id, want)
	}
	other := []byte("fedcba9876543210fedcba9876543210")
	if admingroup.ID(other, tenant, "C02XK0AAJGH5", "first/3e9c9d85-9d3b-4a6b-8c8b-6c5d4f2a0b34") == id {
		t.Fatal("a different secret gave the same ID")
	}
}

func TestSnapshotRepeatsTheGroupLastReported(t *testing.T) {
	now := testfixture.Time(t, "2026-10-17T00:30:00Z")
	health := testfixture.Event(t, "agent-health")
	r, _ := admingroup.FromHealth(health)
	r.Truncated = 3
	e := admingroup.Snapshot(r, health.Device, tenant, "2026-10-17", secret, now)
	d := raised(t, e, now)
	if e.EventID != admingroup.ID(secret, tenant, health.Device.Serial, "snapshot/2026-10-17") || !e.Timestamp.Equal(now) ||
		e.Device != health.Device {
		t.Fatalf("event = %+v", e)
	}
	if d["state"] != event.AdminGroupSnapshot || !slices.Equal(names(t, d["members"]), []string{"backdoor", "itadmin"}) ||
		d["health_event_id"] != health.EventID || d["as_of"] != "2026-10-16T10:05:00Z" || d["truncated"] != float64(3) {
		t.Fatalf("detail = %v", d)
	}
}

func reportsEqual(a, b admingroup.Report) bool {
	return slices.Equal(a.Members, b.Members) && slices.Equal(a.PermanentAdmins, b.PermanentAdmins) &&
		a.HealthEventID == b.HealthEventID && a.AsOf.Equal(b.AsOf) && a.Truncated == b.Truncated
}
