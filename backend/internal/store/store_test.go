package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/admingroup"
	"github.com/Altiward/altiward/backend/internal/command"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/session"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// suite runs the same behavioural tests against every Store implementation.
// newStore must return a store that queues exports for the given sink.
func suite(t *testing.T, newStore func(t *testing.T, sink string) Store) {
	ctx := context.Background()
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")

	setup := func(t *testing.T) (Store, string, string) {
		sink := "sink-" + randomHex(t)
		return newStore(t, sink), "tenant-" + randomHex(t), sink
	}
	fixtures := func(t *testing.T) (granted, revoked, oob, health event.Event) {
		return testfixture.Event(t, "elevation-granted"), testfixture.Event(t, "elevation-revoked"),
			testfixture.Event(t, "admin-out-of-band"), testfixture.Event(t, "agent-health")
	}

	t.Run("coverage", func(t *testing.T) {
		s, _, _ := setup(t)
		first, second := "sink-a-"+randomHex(t), "sink-b-"+randomHex(t)
		t1 := now
		t2 := now.Add(time.Hour)
		if got, err := s.SinkCoverage(ctx, []string{first, second}); err != nil || got != nil {
			t.Fatalf("coverage before anything is recorded = %v, %v", got, err)
		}
		if got, err := s.SinkCoverage(ctx, nil); err != nil || got != nil {
			t.Fatalf("coverage of no sinks = %v, %v", got, err)
		}
		if err := s.RecordSinks(ctx, []string{first}, t1); err != nil {
			t.Fatal(err)
		}
		// A second start keeps the first time, and a new sink gets its own.
		if err := s.RecordSinks(ctx, []string{first, second}, t2); err != nil {
			t.Fatal(err)
		}
		coverage := func(sinks ...string) time.Time {
			t.Helper()
			got, err := s.SinkCoverage(ctx, sinks)
			if err != nil || got == nil {
				t.Fatalf("coverage of %v = %v, %v", sinks, got, err)
			}
			return *got
		}
		if got := coverage(first); !got.Equal(t1) {
			t.Fatalf("coverage after a second RecordSinks = %v, want %v", got, t1)
		}
		if got := coverage(first, second); !got.Equal(t2) {
			t.Fatalf("coverage of two sinks = %v, want the later %v", got, t2)
		}
		// Replaying from earlier moves the sink's coverage back; replaying from later doesn't.
		if r, ok := s.(interface {
			ReplayExports(ctx context.Context, sink string, since, now time.Time) (int64, error)
		}); ok {
			if _, err := r.ReplayExports(ctx, second, t1.Add(-24*time.Hour), t2); err != nil {
				t.Fatal(err)
			}
			if got := coverage(second); !got.Equal(t1.Add(-24 * time.Hour)) {
				t.Fatalf("coverage after replaying from earlier = %v", got)
			}
			if got := coverage(first, second); !got.Equal(t1) {
				t.Fatalf("coverage of two sinks after the replay = %v, want %v", got, t1)
			}
			if _, err := r.ReplayExports(ctx, second, t2, t2); err != nil {
				t.Fatal(err)
			}
			if got := coverage(second); !got.Equal(t1.Add(-24 * time.Hour)) {
				t.Fatalf("replaying from later moved the coverage to %v", got)
			}
		}
	})

	t.Run("builds a session from grant and revoke", func(t *testing.T) {
		s, tenant, _ := setup(t)
		granted, revoked, _, _ := fixtures(t)
		res, err := s.Ingest(ctx, tenant, []event.Event{granted, revoked}, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Accepted) != 2 || len(res.Duplicate) != 0 {
			t.Fatalf("result = %+v", res)
		}
		got, evs, err := s.GetSession(ctx, tenant, *granted.SessionID)
		if err != nil {
			t.Fatal(err)
		}
		if got.LocalUser != "jdoe" || got.Source != event.SourcePrivileges || got.Open() || !got.Verified {
			t.Fatalf("session = %+v", got)
		}
		if *got.EndReason != session.EndRevoked || got.EventCount != 2 {
			t.Fatalf("end = %v count = %d", *got.EndReason, got.EventCount)
		}
		if len(evs) != 2 || evs[0].EventID != granted.EventID || evs[1].EventID != revoked.EventID {
			t.Fatalf("timeline = %+v", evs)
		}
		if !evs[0].ReceivedAt.Equal(now) {
			t.Fatalf("received_at = %v", evs[0].ReceivedAt)
		}
	})

	t.Run("duplicates are reported and not re-applied", func(t *testing.T) {
		s, tenant, _ := setup(t)
		granted, _, _, _ := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted}, now); err != nil {
			t.Fatal(err)
		}
		res, err := s.Ingest(ctx, tenant, []event.Event{granted}, now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Duplicate) != 1 || len(res.Accepted) != 0 {
			t.Fatalf("result = %+v", res)
		}
		got, _, _ := s.GetSession(ctx, tenant, *granted.SessionID)
		if got.EventCount != 1 {
			t.Fatalf("event applied twice: count = %d", got.EventCount)
		}
	})

	t.Run("tenants are isolated", func(t *testing.T) {
		s, tenant, _ := setup(t)
		granted, _, _, _ := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted}, now); err != nil {
			t.Fatal(err)
		}
		other := tenant + "-other"
		if _, _, err := s.GetSession(ctx, other, *granted.SessionID); err != ErrNotFound {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
		// The same event ID in another tenant is a different event.
		res, err := s.Ingest(ctx, other, []event.Event{granted}, now)
		if err != nil || len(res.Accepted) != 1 {
			t.Fatalf("res = %+v err = %v", res, err)
		}
	})

	t.Run("lists sessions newest first with filters", func(t *testing.T) {
		s, tenant, _ := setup(t)
		granted, revoked, oob, _ := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted, revoked, oob}, now); err != nil {
			t.Fatal(err)
		}
		all, err := s.ListSessions(ctx, tenant, SessionFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 2 || all[0].SessionID != *oob.SessionID || all[1].SessionID != *granted.SessionID {
			t.Fatalf("order = %v", ids(all))
		}
		open, _ := s.ListSessions(ctx, tenant, SessionFilter{OpenOnly: true})
		if len(open) != 1 || open[0].Source != event.SourceOutOfBand {
			t.Fatalf("open = %v", ids(open))
		}
		byUser, _ := s.ListSessions(ctx, tenant, SessionFilter{LocalUser: "jdoe"})
		if len(byUser) != 1 {
			t.Fatalf("by user = %v", ids(byUser))
		}
		since := testfixture.Time(t, "2026-10-16T09:30:00Z")
		recent, _ := s.ListSessions(ctx, tenant, SessionFilter{Since: &since})
		if len(recent) != 1 || recent[0].SessionID != *oob.SessionID {
			t.Fatalf("since = %v", ids(recent))
		}
		limited, _ := s.ListSessions(ctx, tenant, SessionFilter{Limit: 1})
		if len(limited) != 1 {
			t.Fatalf("limit = %v", ids(limited))
		}
	})

	t.Run("report sessions are open or recent, with no page limit", func(t *testing.T) {
		s, tenant, _ := setup(t)
		granted, revoked, oob, _ := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted, revoked, oob}, now); err != nil {
			t.Fatal(err)
		}
		// The ended grant started at 09:14 and the open out-of-band session at 10:00.
		got, err := s.ReportSessions(ctx, tenant, testfixture.Time(t, "2026-10-16T11:00:00Z"))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].SessionID != *oob.SessionID {
			t.Fatalf("after both started = %v", ids(got))
		}
		if got, _ = s.ReportSessions(ctx, tenant, testfixture.Time(t, "2026-10-16T09:00:00Z")); len(got) != 2 {
			t.Fatalf("since 09:00 = %v", ids(got))
		}

		many := make([]event.Event, 0, MaxSessionPage+1)
		for i := range MaxSessionPage + 1 {
			e := granted
			e.EventID = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
			sid := fmt.Sprintf("00000000-0000-4000-9000-%012d", i)
			e.SessionID = &sid
			many = append(many, e)
		}
		if _, err := s.Ingest(ctx, tenant, many, now); err != nil {
			t.Fatal(err)
		}
		if got, _ = s.ReportSessions(ctx, tenant, testfixture.Time(t, "2026-10-16T09:00:00Z")); len(got) != MaxSessionPage+3 {
			t.Fatalf("got %d sessions, want %d", len(got), MaxSessionPage+3)
		}
	})

	t.Run("health updates the device", func(t *testing.T) {
		s, tenant, _ := setup(t)
		granted, _, _, health := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted, health}, now); err != nil {
			t.Fatal(err)
		}
		devices, err := s.ListDevices(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if len(devices) != 1 {
			t.Fatalf("devices = %+v", devices)
		}
		d := devices[0]
		if d.Serial != "C02XK0AAJGH5" || len(d.AdminMembers) != 2 || d.AdminMembers[0] != "backdoor" {
			t.Fatalf("device = %+v", d)
		}
		if d.QueueDepth == nil || *d.QueueDepth != 0 || d.Privileges["installed"] != true {
			t.Fatalf("health fields = %+v", d)
		}
	})

	t.Run("silence candidates are quiet Macs and open alerts, across tenants", func(t *testing.T) {
		s, tenant, _ := setup(t)
		_, _, _, health := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{health}, now); err != nil {
			t.Fatal(err)
		}
		mine := func(seenBefore time.Time) []Device {
			t.Helper()
			all, err := s.SilenceCandidates(ctx, seenBefore)
			if err != nil {
				t.Fatal(err)
			}
			out := []Device{}
			for _, d := range all {
				if d.TenantID == tenant {
					out = append(out, d)
				}
			}
			return out
		}
		// Judged by when the server received the event (now), not the Mac's timestamp,
		// which is two hours earlier: a Mac whose clock is behind isn't quiet.
		if got := mine(health.Timestamp.Add(time.Hour)); len(got) != 0 {
			t.Fatalf("received since, yet a candidate: %+v", got)
		}
		if got := mine(now); len(got) != 1 || got[0].Serial != health.Device.Serial || !got[0].LastReceivedAt.Equal(now) {
			t.Fatalf("quiet Mac missing: %+v", got)
		}
		if _, err := s.Ingest(ctx, tenant, []event.Event{testfixture.Event(t, "agent-silent")}, now); err != nil {
			t.Fatal(err)
		}
		got := mine(health.Timestamp.Add(-time.Hour))
		if len(got) != 1 || !got[0].Silent() || !got[0].LastSeenAt.Equal(health.Timestamp) {
			t.Fatalf("open alert missing: %+v", got)
		}
	})

	t.Run("a server-raised event does not create a device", func(t *testing.T) {
		s, tenant, sink := setup(t)
		enrolled := testfixture.Event(t, "agent-enrollment-enrolled")
		res, err := s.Ingest(ctx, tenant, []event.Event{enrolled}, now)
		if err != nil || len(res.Accepted) != 1 {
			t.Fatalf("res = %+v err = %v", res, err)
		}
		if devices, err := s.ListDevices(ctx, tenant); err != nil || len(devices) != 0 {
			t.Fatalf("a Mac the server hasn't heard from got a device: %+v, %v", devices, err)
		}
		queued, err := s.ClaimExports(ctx, sink, 10, time.Minute, now)
		if err != nil || len(queued) != 1 || queued[0].Event.EventID != enrolled.EventID || queued[0].Event.Type != event.AgentEnrollment {
			t.Fatalf("not queued for export: %+v, %v", queued, err)
		}

		// A Mac that has checked in keeps its device exactly as it was.
		_, _, _, health := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{health}, now); err != nil {
			t.Fatal(err)
		}
		before, _ := s.ListDevices(ctx, tenant)
		pending := testfixture.Event(t, "agent-enrollment-pending")
		if res, err = s.Ingest(ctx, tenant, []event.Event{pending}, now.Add(time.Hour)); err != nil || len(res.Accepted) != 1 {
			t.Fatalf("res = %+v err = %v", res, err)
		}
		after, _ := s.ListDevices(ctx, tenant)
		beforeJSON, _ := json.Marshal(before)
		afterJSON, _ := json.Marshal(after)
		if len(before) != 1 || string(beforeJSON) != string(afterJSON) {
			t.Fatalf("device changed:\n%s\n%s", beforeJSON, afterJSON)
		}
		// The first claim's lease has run out by now, so the whole queue comes back: the
		// enrolment, the health event, the admin group it raised and the pending enrolment,
		// in the order they arrived.
		queued, _ = s.ClaimExports(ctx, sink, 10, time.Minute, now.Add(time.Hour))
		if len(queued) != 4 || queued[2].Event.Type != event.AgentAdminGroup || queued[3].Event.EventID != pending.EventID {
			t.Fatalf("pending enrolment not queued for export: %d items", len(queued))
		}
	})

	t.Run("admin group", func(t *testing.T) {
		// queued returns the agent.admin_group events queued for sink, oldest first, and
		// checks each is valid. It leases what it claims, so a second call returns only what
		// was queued since.
		queued := func(t *testing.T, s Store, sink string) []event.Event {
			t.Helper()
			items, err := s.ClaimExports(ctx, sink, 100, time.Minute, now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			out := []event.Event{}
			for _, it := range items {
				if e := it.Event.Event; e.Type == event.AgentAdminGroup {
					if err := e.Validate(now); err != nil {
						t.Fatalf("queued an invalid event: %v", err)
					}
					out = append(out, e)
				}
			}
			return out
		}
		idFor := func(t *testing.T, s Store, tenant, key string) string {
			t.Helper()
			in, err := s.Installation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			return admingroup.ID(in.RaisedIDSecret, tenant, "C02XK0AAJGH5", key)
		}
		// reading is the agent-health fixture with another event ID, Mac time and group.
		reading := func(t *testing.T, id string, at time.Time, members ...string) event.Event {
			t.Helper()
			e := testfixture.Event(t, "agent-health")
			e.EventID, e.Timestamp = id, at
			list := []any{}
			for _, m := range members {
				list = append(list, m)
			}
			e.Detail["admin_members"] = list
			return e
		}
		state := func(e event.Event) string { s, _ := e.Detail["state"].(string); return s }

		t.Run("raises the admin group when it changes", func(t *testing.T) {
			s, tenant, sink := setup(t)
			_, _, _, health := fixtures(t)
			res, err := s.Ingest(ctx, tenant, []event.Event{health}, now)
			if err != nil || !slices.Equal(res.Accepted, []string{health.EventID}) || len(res.RaisedIDTaken) != 0 {
				t.Fatalf("res = %+v err = %v", res, err)
			}
			added := reading(t, "3e9c9d85-9d3b-4a6b-8c8b-000000000001", health.Timestamp.Add(5*time.Minute),
				"backdoor", "itadmin", "jdoe")
			added.Detail["open_sessions"] = []any{map[string]any{
				"user": "jdoe", "session_id": "5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d", "source": "privileges"}}
			later := now.Add(5 * time.Minute)
			if res, err = s.Ingest(ctx, tenant, []event.Event{added}, later); err != nil ||
				!slices.Equal(res.Accepted, []string{added.EventID}) || len(res.Duplicate) != 0 {
				t.Fatalf("res = %+v err = %v", res, err)
			}

			got := queued(t, s, sink)
			if len(got) != 2 || state(got[0]) != event.AdminGroupSnapshot || state(got[1]) != event.AdminGroupChanged {
				t.Fatalf("queued %+v, want a snapshot and a change", got)
			}
			if got[0].EventID != idFor(t, s, tenant, "first/"+health.EventID) || !got[0].Timestamp.Equal(now) ||
				got[0].Detail["health_event_id"] != health.EventID {
				t.Fatalf("snapshot = %+v", got[0])
			}
			change := got[1]
			if change.EventID != idFor(t, s, tenant, "changed/"+added.EventID) || !change.Timestamp.Equal(later) ||
				change.Device.Serial != "C02XK0AAJGH5" || change.SessionID != nil {
				t.Fatalf("change = %+v", change)
			}
			detail, _ := json.Marshal(change.Detail)
			for _, want := range []string{
				`"added":[{"name":"jdoe","session_id":"5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d","source":"privileges"}]`,
				`"removed":[]`, `"members":["backdoor","itadmin","jdoe"]`, `"truncated":0`,
			} {
				if !strings.Contains(string(detail), want) {
					t.Fatalf("detail %s has no %s", detail, want)
				}
			}
			// The raised events aren't sessions, and aren't a check-in.
			if open, _ := s.ListSessions(ctx, tenant, SessionFilter{}); len(open) != 0 {
				t.Fatalf("sessions = %v", ids(open))
			}
			devices, _ := s.ListDevices(ctx, tenant)
			if len(devices) != 1 || !devices[0].LastReceivedAt.Equal(later) || len(devices[0].AdminMembers) != 3 {
				t.Fatalf("devices = %+v", devices)
			}
		})

		t.Run("an oversized group is capped and never fails ingest", func(t *testing.T) {
			s, tenant, sink := setup(t)
			granted, _, _, _ := fixtures(t)
			// 10,000 names that still fit in a reading the API accepts.
			many := make([]string, 0, 10_000)
			for i := range 10_000 {
				many = append(many, strconv.FormatInt(int64(i), 36))
			}
			big := reading(t, "3e9c9d85-9d3b-4a6b-8c8b-000000000002", testfixture.Time(t, "2026-10-16T10:05:00Z"), many...)
			if err := big.Validate(now); err != nil {
				t.Fatalf("the API would refuse the reading: %v", err)
			}
			res, err := s.Ingest(ctx, tenant, []event.Event{big, granted}, now)
			if err != nil || !slices.Equal(res.Accepted, []string{big.EventID, granted.EventID}) {
				t.Fatalf("res = %+v err = %v", res, err)
			}
			got := queued(t, s, sink)
			if len(got) != 1 || state(got[0]) != event.AdminGroupSnapshot {
				t.Fatalf("queued %+v, want one snapshot", got)
			}
			if members, _ := got[0].Detail["members"].([]any); len(members) != event.MaxAdminGroupPeople ||
				got[0].Detail["truncated"] != float64(9_800) {
				t.Fatalf("snapshot of %d people, truncated %v", len(members), got[0].Detail["truncated"])
			}
			if _, _, err := s.GetSession(ctx, tenant, *granted.SessionID); err != nil {
				t.Fatalf("the grant after it wasn't stored: %v", err)
			}
		})

		t.Run("a late older reading is compared in arrival order", func(t *testing.T) {
			s, tenant, sink := setup(t)
			_, _, _, health := fixtures(t)
			if _, err := s.Ingest(ctx, tenant, []event.Event{health}, now); err != nil {
				t.Fatal(err)
			}
			// Sent later but stamped earlier by the Mac: the device keeps the newer reading's
			// group, yet the change is still reported, against the group last reported.
			late := reading(t, "3e9c9d85-9d3b-4a6b-8c8b-000000000003", health.Timestamp.Add(-time.Hour), "itadmin")
			if _, err := s.Ingest(ctx, tenant, []event.Event{late}, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			back := reading(t, "3e9c9d85-9d3b-4a6b-8c8b-000000000004", health.Timestamp.Add(-30*time.Minute),
				"backdoor", "itadmin")
			if _, err := s.Ingest(ctx, tenant, []event.Event{back}, now.Add(2*time.Minute)); err != nil {
				t.Fatal(err)
			}
			got := queued(t, s, sink)
			if len(got) != 3 || state(got[1]) != event.AdminGroupChanged || state(got[2]) != event.AdminGroupChanged {
				t.Fatalf("queued %+v, want a snapshot and two changes", got)
			}
			removed, _ := json.Marshal(got[1].Detail["removed"])
			added, _ := json.Marshal(got[2].Detail["added"])
			if string(removed) != `["backdoor"]` || string(added) != `[{"name":"backdoor"}]` {
				t.Fatalf("removed %s, then added %s", removed, added)
			}
			if devices, _ := s.ListDevices(ctx, tenant); len(devices) != 1 || len(devices[0].AdminMembers) != 2 {
				t.Fatalf("devices = %+v", devices)
			}
		})

		t.Run("a resent reading raises nothing", func(t *testing.T) {
			s, tenant, sink := setup(t)
			_, _, _, health := fixtures(t)
			if _, err := s.Ingest(ctx, tenant, []event.Event{health}, now); err != nil {
				t.Fatal(err)
			}
			res, err := s.Ingest(ctx, tenant, []event.Event{health}, now.Add(time.Minute))
			if err != nil || !slices.Equal(res.Duplicate, []string{health.EventID}) || len(res.Accepted) != 0 ||
				len(res.RaisedIDTaken) != 0 {
				t.Fatalf("res = %+v err = %v", res, err)
			}
			if got := queued(t, s, sink); len(got) != 1 {
				t.Fatalf("queued %+v, want the one snapshot", got)
			}
		})

		t.Run("a raised ID already taken is reported, and the reading still stored", func(t *testing.T) {
			s, tenant, sink := setup(t)
			granted, _, _, health := fixtures(t)
			// Only someone with the installation's secret could do this.
			granted.EventID = idFor(t, s, tenant, "first/"+health.EventID)
			if _, err := s.Ingest(ctx, tenant, []event.Event{granted}, now); err != nil {
				t.Fatal(err)
			}
			res, err := s.Ingest(ctx, tenant, []event.Event{health}, now)
			if err != nil || !slices.Equal(res.Accepted, []string{health.EventID}) ||
				!slices.Equal(res.RaisedIDTaken, []string{granted.EventID}) {
				t.Fatalf("res = %+v err = %v", res, err)
			}
			if got := queued(t, s, sink); len(got) != 0 {
				t.Fatalf("queued %+v", got)
			}
			// Nothing was reported, so the next reading reports the whole group.
			next := reading(t, "3e9c9d85-9d3b-4a6b-8c8b-000000000005", health.Timestamp.Add(5*time.Minute),
				"backdoor", "itadmin")
			if res, err = s.Ingest(ctx, tenant, []event.Event{next}, now.Add(5*time.Minute)); err != nil || len(res.RaisedIDTaken) != 0 {
				t.Fatalf("res = %+v err = %v", res, err)
			}
			got := queued(t, s, sink)
			if len(got) != 1 || state(got[0]) != event.AdminGroupSnapshot || got[0].EventID != idFor(t, s, tenant, "first/"+next.EventID) {
				t.Fatalf("queued %+v, want a snapshot of the next reading", got)
			}
		})

		t.Run("a reading in the same batch is compared with the one before it", func(t *testing.T) {
			s, tenant, sink := setup(t)
			_, _, _, health := fixtures(t)
			first := reading(t, "3e9c9d85-9d3b-4a6b-8c8b-000000000006", health.Timestamp, "itadmin")
			second := reading(t, "3e9c9d85-9d3b-4a6b-8c8b-000000000007", health.Timestamp.Add(time.Minute),
				"backdoor", "itadmin")
			res, err := s.Ingest(ctx, tenant, []event.Event{first, second}, now)
			if err != nil || !slices.Equal(res.Accepted, []string{first.EventID, second.EventID}) {
				t.Fatalf("res = %+v err = %v", res, err)
			}
			got := queued(t, s, sink)
			if len(got) != 2 || state(got[0]) != event.AdminGroupSnapshot || state(got[1]) != event.AdminGroupChanged ||
				got[0].EventID != idFor(t, s, tenant, "first/"+first.EventID) ||
				got[1].EventID != idFor(t, s, tenant, "changed/"+second.EventID) {
				t.Fatalf("queued %+v, want a snapshot of the first and a change for the second", got)
			}
			added, _ := json.Marshal(got[1].Detail["added"])
			removed, _ := json.Marshal(got[1].Detail["removed"])
			if string(added) != `[{"name":"backdoor"}]` || string(removed) != `[]` {
				t.Fatalf("added %s, removed %s", added, removed)
			}
		})

		t.Run("snapshots once a day", func(t *testing.T) {
			s, tenant, sink := setup(t)
			_, _, _, health := fixtures(t)
			serial := health.Device.Serial
			if ok, err := s.RaiseAdminGroupSnapshot(ctx, tenant, serial, now); err != nil || ok {
				t.Fatalf("snapshot of a Mac with no group = %v, %v", ok, err)
			}
			if _, err := s.Ingest(ctx, tenant, []event.Event{health}, now); err != nil {
				t.Fatal(err)
			}
			if got := queued(t, s, sink); len(got) != 1 {
				t.Fatalf("queued %+v, want the first reading's snapshot", got)
			}
			refs, err := s.AdminGroupSnapshotCandidates(ctx, now.Add(-24*time.Hour))
			if err != nil || !slices.Contains(refs, DeviceRef{TenantID: tenant, Serial: serial}) {
				t.Fatalf("candidates = %v, %v", refs, err)
			}
			if refs, _ = s.AdminGroupSnapshotCandidates(ctx, now.Add(time.Minute)); slices.Contains(refs, DeviceRef{TenantID: tenant, Serial: serial}) {
				t.Fatalf("candidates = %v, but the Mac hasn't checked in since", refs)
			}

			ok, err := s.RaiseAdminGroupSnapshot(ctx, tenant, serial, now.Add(time.Hour))
			if err != nil || !ok {
				t.Fatalf("snapshot = %v, %v", ok, err)
			}
			got := queued(t, s, sink)
			day := time.Now().UTC().Format("2006-01-02")
			if len(got) != 1 || state(got[0]) != event.AdminGroupSnapshot || got[0].EventID != idFor(t, s, tenant, "snapshot/"+day) ||
				!got[0].Timestamp.Equal(now.Add(time.Hour)) || got[0].Device.Serial != serial ||
				got[0].Device.HardwareUUID != health.Device.HardwareUUID || got[0].Detail["health_event_id"] != health.EventID {
				t.Fatalf("queued %+v, want the day's snapshot of the reading", got)
			}
			if ok, err = s.RaiseAdminGroupSnapshot(ctx, tenant, serial, now.Add(2*time.Hour)); err != nil || ok {
				t.Fatalf("second snapshot = %v, %v", ok, err)
			}
			if got = queued(t, s, sink); len(got) != 0 {
				t.Fatalf("queued %+v, want nothing", got)
			}
			// Raising it isn't a check-in, and doesn't change the group reported.
			devices, _ := s.ListDevices(ctx, tenant)
			if len(devices) != 1 || !devices[0].LastReceivedAt.Equal(now) {
				t.Fatalf("devices = %+v", devices)
			}
		})

		t.Run("a retired Mac gets no snapshot", func(t *testing.T) {
			s, tenant, sink := setup(t)
			_, _, _, health := fixtures(t)
			serial := health.Device.Serial
			key := enrolFirst(t, s, tenant, serial, health.Device.HardwareUUID, now)
			if _, err := s.Ingest(ctx, tenant, []event.Event{health}, now); err != nil {
				t.Fatal(err)
			}
			queued(t, s, sink)
			ref := DeviceRef{TenantID: tenant, Serial: serial}
			if refs, _ := s.AdminGroupSnapshotCandidates(ctx, now.Add(-24*time.Hour)); !slices.Contains(refs, ref) {
				t.Fatalf("candidates = %v, want the Mac before it is retired", refs)
			}
			if _, err := s.RevokeCredential(ctx, tenant, key.DeviceID, now.Add(time.Minute), auditFor(t, tenant, AuditRevokeEnrollment)); err != nil {
				t.Fatal(err)
			}
			if refs, _ := s.AdminGroupSnapshotCandidates(ctx, now.Add(-24*time.Hour)); slices.Contains(refs, ref) {
				t.Fatalf("candidates = %v, but the Mac is retired", refs)
			}
			if ok, err := s.RaiseAdminGroupSnapshot(ctx, tenant, serial, now.Add(time.Hour)); err != nil || ok {
				t.Fatalf("snapshot of a retired Mac = %v, %v", ok, err)
			}
			if got := queued(t, s, sink); len(got) != 0 {
				t.Fatalf("queued %+v", got)
			}
		})

		t.Run("every reading refreshes the group a snapshot carries", func(t *testing.T) {
			s, tenant, sink := setup(t)
			_, _, _, health := fixtures(t)
			first := reading(t, "3e9c9d85-9d3b-4a6b-8c8b-000000000008", health.Timestamp, "backdoor", "itadmin")
			first.Detail["permanent_admins"] = []any{"itadmin"}
			second := reading(t, "3e9c9d85-9d3b-4a6b-8c8b-000000000009", health.Timestamp.Add(5*time.Minute),
				"backdoor", "itadmin")
			second.Detail["permanent_admins"] = []any{"backdoor", "itadmin"}
			for i, e := range []event.Event{first, second} {
				if _, err := s.Ingest(ctx, tenant, []event.Event{e}, now.Add(time.Duration(i)*5*time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			if got := queued(t, s, sink); len(got) != 1 || state(got[0]) != event.AdminGroupSnapshot {
				t.Fatalf("queued %+v, want only the first reading's snapshot", got)
			}
			if ok, err := s.RaiseAdminGroupSnapshot(ctx, tenant, health.Device.Serial, now.Add(time.Hour)); err != nil || !ok {
				t.Fatalf("snapshot = %v, %v", ok, err)
			}
			got := queued(t, s, sink)
			if len(got) != 1 {
				t.Fatalf("queued %+v", got)
			}
			d := got[0].Detail
			permanent, _ := json.Marshal(d["permanent_admins"])
			members, _ := json.Marshal(d["members"])
			if d["health_event_id"] != second.EventID || d["as_of"] != second.Timestamp.UTC().Format(time.RFC3339Nano) ||
				string(permanent) != `["backdoor","itadmin"]` || string(members) != `["backdoor","itadmin"]` {
				t.Fatalf("snapshot detail = %v, want the second reading's", d)
			}
		})
	})

	// History expiry. Both stores refuse to remove anything received in the last 90 days by
	// the real clock, so these tests receive events in 2025.
	old := testfixture.Time(t, "2025-01-01T12:00:00Z")
	cutoff := testfixture.Time(t, "2025-06-01T00:00:00Z")
	// sendAll delivers everything queued for sink, as a SIEM that has had it all.
	sendAll := func(t *testing.T, s Store, sink string) {
		t.Helper()
		items, err := s.ClaimExports(ctx, sink, 1000, time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		delivered := []int64{}
		for _, it := range items {
			delivered = append(delivered, it.ID)
		}
		if err := s.CompleteExports(ctx, delivered, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	// expireAll calls ExpireHistory in small batches until it removes nothing, and adds up
	// what it removed.
	expireAll := func(t *testing.T, s Store, tenant string, c HistoryCutoff) ExpiryCounts {
		t.Helper()
		var total ExpiryCounts
		for range 100 {
			n, err := s.ExpireHistory(ctx, tenant, c, 2)
			if err != nil {
				t.Fatal(err)
			}
			if n == (ExpiryCounts{}) {
				return total
			}
			total.Add(n)
		}
		t.Fatal("ExpireHistory kept removing")
		return total
	}
	oldCommand := func(t *testing.T, s Store, tenant string, at time.Time) command.Command {
		t.Helper()
		c := command.Command{CommandID: newUUID(t), TenantID: tenant, Serial: "C02XK0AAJGH5", Type: command.TypeRevokeAdmin,
			IssuedBy: "token:test", CreatedAt: at, ExpiresAt: at.Add(command.Lifetime)}
		a := auditFor(t, tenant, AuditRevokeDevice)
		a.At = at
		if err := s.CreateCommand(ctx, c, a); err != nil {
			t.Fatal(err)
		}
		return c
	}

	t.Run("tenants", func(t *testing.T) {
		s, tenant, _ := setup(t)
		_, _, _, health := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{health}, now); err != nil {
			t.Fatal(err)
		}
		configured, quiet := "tenant-"+randomHex(t), "tenant-"+randomHex(t)
		for _, tn := range []string{tenant, configured} {
			if err := s.PutTenantSettings(ctx, tn, DefaultTenantSettings(), auditFor(t, tn, AuditChangeSettings)); err != nil {
				t.Fatal(err)
			}
		}
		// Ingesting into quiet only what the server raised gives it neither a device nor settings.
		if _, err := s.Ingest(ctx, quiet, []event.Event{testfixture.Event(t, "agent-enrollment-enrolled")}, now); err != nil {
			t.Fatal(err)
		}
		got, err := s.Tenants(ctx)
		if err != nil {
			t.Fatal(err)
		}
		count := func(tn string) int {
			n := 0
			for _, g := range got {
				if g == tn {
					n++
				}
			}
			return n
		}
		if count(tenant) != 1 || count(configured) != 1 || count(quiet) != 0 {
			t.Fatalf("tenants = %v, want %s and %s once each, and not %s", got, tenant, configured, quiet)
		}
	})

	t.Run("expires old history", func(t *testing.T) {
		s, tenant, sink := setup(t)
		granted, revoked, oob, health := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted, revoked, oob, health}, old); err != nil {
			t.Fatal(err)
		}
		cmd := oldCommand(t, s, tenant, old)
		// Another organisation with the same old history keeps it.
		other := "tenant-" + randomHex(t)
		if _, err := s.Ingest(ctx, other, []event.Event{granted, revoked}, old); err != nil {
			t.Fatal(err)
		}
		sendAll(t, s, sink)
		// As old, but the SIEM hasn't had it yet.
		tamper := testfixture.Event(t, "agent-tamper")
		if _, err := s.Ingest(ctx, tenant, []event.Event{tamper}, old); err != nil {
			t.Fatal(err)
		}

		// The ended session with its grant and revoke, the reading and the admin group it
		// raised, and the command.
		got := expireAll(t, s, tenant, HistoryCutoff{Before: cutoff})
		if want := (ExpiryCounts{Events: 4, Sessions: 1, Commands: 1}); got != want {
			t.Fatalf("removed %+v, want %+v", got, want)
		}
		if _, _, err := s.GetSession(ctx, tenant, *granted.SessionID); err != ErrNotFound {
			t.Fatalf("ended session: %v, want ErrNotFound", err)
		}
		if _, err := s.GetCommand(ctx, tenant, cmd.CommandID); err != ErrNotFound {
			t.Fatalf("command: %v, want ErrNotFound", err)
		}
		// An open session keeps its events, however old: someone may still hold admin rights.
		open, evs, err := s.GetSession(ctx, tenant, *oob.SessionID)
		if err != nil || !open.Open() || len(evs) != 1 {
			t.Fatalf("open session = %+v, %d events, %v", open, len(evs), err)
		}
		// The event the SIEM is waiting for is still there to send.
		queued, err := s.ClaimExports(ctx, sink, 10, time.Minute, time.Now())
		if err != nil || len(queued) != 1 || queued[0].Event.EventID != tamper.EventID {
			t.Fatalf("queued = %+v, %v", queued, err)
		}
		if _, evs, err := s.GetSession(ctx, other, *granted.SessionID); err != nil || len(evs) != 2 {
			t.Fatalf("the other organisation's session: %d events, %v", len(evs), err)
		}
		// The Mac itself stays.
		if devices, err := s.ListDevices(ctx, tenant); err != nil || len(devices) != 1 {
			t.Fatalf("devices = %+v, %v", devices, err)
		}
		// A resend says what is stored: the reading was removed, the others were kept.
		res, err := s.Ingest(ctx, tenant, []event.Event{health, tamper, oob}, time.Now())
		if err != nil || !slices.Equal(res.Accepted, []string{health.EventID}) ||
			!slices.Equal(res.Duplicate, []string{tamper.EventID, oob.EventID}) {
			t.Fatalf("resend = %+v, %v", res, err)
		}
	})

	t.Run("a session stays whole while any of its events waits", func(t *testing.T) {
		s, tenant, sink := setup(t)
		granted, revoked, _, _ := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted}, old); err != nil {
			t.Fatal(err)
		}
		sendAll(t, s, sink)
		if _, err := s.Ingest(ctx, tenant, []event.Event{revoked}, old); err != nil {
			t.Fatal(err)
		}
		if got := expireAll(t, s, tenant, HistoryCutoff{Before: cutoff}); got != (ExpiryCounts{}) {
			t.Fatalf("removed %+v", got)
		}
		if ended, evs, err := s.GetSession(ctx, tenant, *granted.SessionID); err != nil || ended.Open() || len(evs) != 2 {
			t.Fatalf("session = %+v, %d events, %v", ended, len(evs), err)
		}
	})

	t.Run("coverage holds old history", func(t *testing.T) {
		s, tenant, sink := setup(t)
		granted, revoked, _, health := fixtures(t)
		later := testfixture.Time(t, "2025-04-01T12:00:00Z")
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted}, old); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Ingest(ctx, tenant, []event.Event{revoked, health}, later); err != nil {
			t.Fatal(err)
		}
		sendAll(t, s, sink)
		// The SIEM has had everything received since March. The session ended after that,
		// but it began before, so it stays whole; the April reading and its admin group go.
		covered := testfixture.Time(t, "2025-03-01T00:00:00Z")
		got := expireAll(t, s, tenant, HistoryCutoff{Before: cutoff, NotBefore: &covered})
		if want := (ExpiryCounts{Events: 2}); got != want {
			t.Fatalf("removed %+v, want %+v", got, want)
		}
		if _, evs, err := s.GetSession(ctx, tenant, *granted.SessionID); err != nil || len(evs) != 2 {
			t.Fatalf("session: %d events, %v", len(evs), err)
		}
		// A reading on its own from before the coverage stays too.
		earlier := testfixture.Event(t, "agent-health")
		earlier.EventID = newUUID(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{earlier}, old); err != nil {
			t.Fatal(err)
		}
		sendAll(t, s, sink)
		if got := expireAll(t, s, tenant, HistoryCutoff{Before: cutoff, NotBefore: &covered}); got != (ExpiryCounts{}) {
			t.Fatalf("removed %+v from before the coverage", got)
		}
	})

	t.Run("never removes the last 90 days", func(t *testing.T) {
		s, tenant, sink := setup(t)
		granted, revoked, _, health := fixtures(t)
		recent := time.Now().AddDate(0, 0, -30)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted, revoked, health}, recent); err != nil {
			t.Fatal(err)
		}
		cmd := oldCommand(t, s, tenant, recent)
		sendAll(t, s, sink)
		// Asked for everything up to now, the stores keep the last 90 days all the same.
		if got := expireAll(t, s, tenant, HistoryCutoff{Before: time.Now()}); got != (ExpiryCounts{}) {
			t.Fatalf("removed %+v", got)
		}
		if _, evs, err := s.GetSession(ctx, tenant, *granted.SessionID); err != nil || len(evs) != 2 {
			t.Fatalf("session: %d events, %v", len(evs), err)
		}
		if _, err := s.GetCommand(ctx, tenant, cmd.CommandID); err != nil {
			t.Fatalf("command: %v", err)
		}
		if res, err := s.Ingest(ctx, tenant, []event.Event{health}, time.Now()); err != nil || len(res.Duplicate) != 1 {
			t.Fatalf("reading resent = %+v, %v; want a duplicate", res, err)
		}
	})

	t.Run("a resent event after expiry is stored again", func(t *testing.T) {
		s, tenant, sink := setup(t)
		granted, revoked, _, _ := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted, revoked}, old); err != nil {
			t.Fatal(err)
		}
		sendAll(t, s, sink)
		if got := expireAll(t, s, tenant, HistoryCutoff{Before: cutoff}); got != (ExpiryCounts{Events: 2, Sessions: 1}) {
			t.Fatalf("removed %+v", got)
		}
		// Nothing remembers the removed session, so a grant the agent sends again is a new
		// event, and its session looks open (accepted: see ExpireHistory).
		res, err := s.Ingest(ctx, tenant, []event.Event{granted}, time.Now())
		if err != nil || !slices.Equal(res.Accepted, []string{granted.EventID}) || len(res.Duplicate) != 0 {
			t.Fatalf("resend = %+v, %v", res, err)
		}
		again, evs, err := s.GetSession(ctx, tenant, *granted.SessionID)
		if err != nil || !again.Open() || again.EventCount != 1 || len(evs) != 1 {
			t.Fatalf("session after the resend = %+v, %d events, %v", again, len(evs), err)
		}
		if queued, _ := s.ClaimExports(ctx, sink, 10, time.Minute, time.Now()); len(queued) != 1 || queued[0].Event.EventID != granted.EventID {
			t.Fatalf("the resent grant isn't queued for the SIEM: %+v", queued)
		}
	})

	// Removing Macs that have stopped checking in. The fixtures are all one Mac's, received
	// in 2025 as above, and a run on 2026-06-01 that keeps a year has the cutoff above.
	mac := "C02XK0AAJGH5"
	runAt := testfixture.Time(t, "2026-06-01T00:00:00Z")
	later := testfixture.Time(t, "2025-07-01T12:00:00Z") // after the cutoff, and past the floor
	enrollAt := func(t *testing.T, s Store, tenant string, at time.Time) DeviceCredential {
		t.Helper()
		res, err := s.Enroll(ctx, DeviceCredential{DeviceID: newUUID(t), TenantID: tenant, Serial: mac,
			HardwareUUID: "HW-" + mac, PublicKey: newKey(t), CreatedAt: at}, EnrollLimits{})
		if err != nil {
			t.Fatal(err)
		}
		return res.Credential
	}
	// quietMac stores an ended session and a reading for the Mac, and a key it enrolled, all
	// in January 2025, and has the SIEM send everything.
	quietMac := func(t *testing.T, s Store, tenant, sink string) DeviceCredential {
		t.Helper()
		granted, revoked, _, health := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted, revoked, health}, old); err != nil {
			t.Fatal(err)
		}
		key := enrollAt(t, s, tenant, old)
		sendAll(t, s, sink)
		return key
	}
	removeMac := func(t *testing.T, s Store, tenant string, c HistoryCutoff) RemovedDevice {
		t.Helper()
		r, err := s.RemoveDevice(ctx, tenant, mac, c, runAt)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// serverEntries are the tenant's Activity entries the server wrote itself, oldest first.
	serverEntries := func(t *testing.T, s Store, tenant string) []AuditEntry {
		t.Helper()
		all, err := s.ListAudit(ctx, tenant, AuditFilter{})
		if err != nil {
			t.Fatal(err)
		}
		out := []AuditEntry{}
		for _, a := range slices.Backward(all) {
			if a.Actor == ServerActor {
				out = append(out, a)
			}
		}
		return out
	}
	// keptFor checks that RemoveDevice keeps the Mac, for why, and changes nothing.
	keptFor := func(t *testing.T, s Store, tenant string, c HistoryCutoff, why string) {
		t.Helper()
		if r := removeMac(t, s, tenant, c); r.Removed || r.Skipped != why || len(r.RevokedKeys) != 0 || r.Counts != (ExpiryCounts{}) {
			t.Fatalf("RemoveDevice = %+v, want the Mac kept for %s", r, why)
		}
		if devices, err := s.ListDevices(ctx, tenant); err != nil || len(devices) != 1 {
			t.Fatalf("devices = %+v, %v", devices, err)
		}
		if revoked, err := s.ListCredentials(ctx, tenant, CredentialFilter{Status: CredentialRevoked}); err != nil || len(revoked) != 0 {
			t.Fatalf("revoked keys = %+v, %v", revoked, err)
		}
		if got := serverEntries(t, s, tenant); len(got) != 0 {
			t.Fatalf("recorded %+v", got)
		}
	}
	// forgetReceived makes the Mac's row one stored before the server recorded when it
	// received each event, so only the Mac's own clock says when it last checked in.
	forgetReceived := func(t *testing.T, s Store, tenant string) {
		t.Helper()
		switch s := s.(type) {
		case *Memory:
			s.mu.Lock()
			defer s.mu.Unlock()
			d := s.devices[key{tenant, mac}]
			d.LastReceivedAt = time.Time{}
			s.devices[key{tenant, mac}] = d
		case *Postgres:
			if _, err := s.pool.Exec(ctx, `
				UPDATE devices SET state = state - 'last_received_at', last_seen_at = (state->>'last_seen_at')::timestamptz
				WHERE tenant_id = $1 AND serial = $2`, tenant, mac); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("no way to forget when %T received events", s)
		}
	}

	t.Run("removal candidates are the Macs quiet since the cutoff", func(t *testing.T) {
		s, tenant, _ := setup(t)
		_, _, _, health := fixtures(t)
		recent := health
		recent.EventID, recent.Device.Serial = newUUID(t), "C02RECENT001"
		if _, err := s.Ingest(ctx, tenant, []event.Event{health}, old); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Ingest(ctx, tenant, []event.Event{recent}, later); err != nil {
			t.Fatal(err)
		}
		// Another organisation's quiet Mac is that organisation's to remove.
		if _, err := s.Ingest(ctx, "tenant-"+randomHex(t), []event.Event{health}, old); err != nil {
			t.Fatal(err)
		}
		if got, err := s.RemovalCandidates(ctx, tenant, cutoff); err != nil || !slices.Equal(got, []string{mac}) {
			t.Fatalf("candidates = %v, %v", got, err)
		}
	})

	t.Run("removes a quiet Mac", func(t *testing.T) {
		s, tenant, sink := setup(t)
		key := quietMac(t, s, tenant, sink)
		granted, _, _, _ := fixtures(t)
		cmd := oldCommand(t, s, tenant, old)
		// A command from within the period stays until expiry reaches it.
		newer := oldCommand(t, s, tenant, later)
		// Its silence alert is still open.
		silent := testfixture.Event(t, "agent-silent")
		if _, err := s.Ingest(ctx, tenant, []event.Event{silent}, old); err != nil {
			t.Fatal(err)
		}
		sendAll(t, s, sink)

		r := removeMac(t, s, tenant, HistoryCutoff{Before: cutoff})
		// The session's grant and revoke, the reading, the admin group it raised, and the alert.
		want := ExpiryCounts{Events: 5, Sessions: 1, Commands: 1, Macs: 1}
		if !r.Removed || r.Skipped != "" || !slices.Equal(r.RevokedKeys, []string{key.DeviceID}) || r.Counts != want {
			t.Fatalf("RemoveDevice = %+v", r)
		}
		if devices, err := s.ListDevices(ctx, tenant); err != nil || len(devices) != 0 {
			t.Fatalf("devices = %+v, %v", devices, err)
		}
		if _, _, err := s.GetSession(ctx, tenant, *granted.SessionID); err != ErrNotFound {
			t.Fatalf("session: %v, want ErrNotFound", err)
		}
		if _, err := s.GetCommand(ctx, tenant, cmd.CommandID); err != ErrNotFound {
			t.Fatalf("command: %v, want ErrNotFound", err)
		}
		if _, err := s.GetCommand(ctx, tenant, newer.CommandID); err != nil {
			t.Fatalf("command from within the period: %v", err)
		}
		if c, err := s.Credential(ctx, key.DeviceID); err != nil || c.Status != CredentialRevoked || c.RevokedAt == nil || !c.RevokedAt.Equal(runAt) {
			t.Fatalf("key = %+v, %v", c, err)
		}
		entries := serverEntries(t, s, tenant)
		if len(entries) != 2 {
			t.Fatalf("entries = %+v", entries)
		}
		revoke, removed := entries[0], entries[1]
		if revoke.Action != AuditRevokeEnrollment || revoke.Target != key.DeviceID || !revoke.At.Equal(runAt) ||
			revoke.Detail["serial"] != mac || revoke.Detail["reason"] != RevokeReasonRemoved {
			t.Fatalf("revoke entry = %#v", revoke)
		}
		counts, _ := removed.Detail["counts"].(map[string]any)
		if removed.Action != AuditRemoveDevice || removed.Target != mac || !removed.At.Equal(runAt) ||
			removed.Detail["last_check_in"] != "2025-01-01T12:00:00Z" || removed.Detail["days"] != 365.0 ||
			removed.Detail["silent_event_id"] != silent.EventID ||
			counts["events"] != 5.0 || counts["sessions"] != 1.0 || counts["commands"] != 1.0 || counts["macs"] != 1.0 {
			t.Fatalf("remove entry = %#v", removed)
		}
		// Both go to the SIEM.
		queued, err := s.ClaimExports(ctx, sink, 10, time.Minute, time.Now())
		if err != nil || len(queued) != 2 || queued[0].Audit == nil || queued[0].Audit.ID != revoke.ID ||
			queued[1].Audit == nil || queued[1].Audit.ID != removed.ID {
			t.Fatalf("queued = %+v, %v", queued, err)
		}
		// The key's record stays, so the Mac's next key is a re-enrolment, which waits for approval.
		if again := enrollAt(t, s, tenant, time.Now()); again.Status != CredentialPending {
			t.Fatalf("enrolled again as %s, want pending", again.Status)
		}
	})

	t.Run("revokes a key waiting for approval too", func(t *testing.T) {
		s, tenant, sink := setup(t)
		active := quietMac(t, s, tenant, sink)
		pending := enrollAt(t, s, tenant, old.Add(time.Hour))
		if pending.Status != CredentialPending {
			t.Fatalf("second key %s, want pending", pending.Status)
		}
		want := []string{active.DeviceID, pending.DeviceID}
		slices.Sort(want)
		if r := removeMac(t, s, tenant, HistoryCutoff{Before: cutoff}); !r.Removed || !slices.Equal(r.RevokedKeys, want) {
			t.Fatalf("RemoveDevice = %+v, want %v revoked", r, want)
		}
		if c, err := s.Credential(ctx, pending.DeviceID); err != nil || c.Status != CredentialRevoked {
			t.Fatalf("pending key = %+v, %v", c, err)
		}
		entries := serverEntries(t, s, tenant)
		if len(entries) != 3 || entries[0].Action != AuditRevokeEnrollment || entries[1].Action != AuditRevokeEnrollment ||
			!slices.Equal([]string{entries[0].Target, entries[1].Target}, want) || entries[2].Action != AuditRemoveDevice {
			t.Fatalf("entries = %+v", entries)
		}
	})

	t.Run("a retired Mac goes with no key to revoke, and comes back afresh", func(t *testing.T) {
		s, tenant, sink := setup(t)
		key := quietMac(t, s, tenant, sink)
		if _, err := s.RevokeCredential(ctx, tenant, key.DeviceID, old, auditFor(t, tenant, AuditRevokeEnrollment)); err != nil {
			t.Fatal(err)
		}
		if devices, err := s.ListDevices(ctx, tenant); err != nil || len(devices) != 1 || devices[0].RetiredAt == nil {
			t.Fatalf("not retired: %+v, %v", devices, err)
		}
		if r := removeMac(t, s, tenant, HistoryCutoff{Before: cutoff}); !r.Removed || len(r.RevokedKeys) != 0 {
			t.Fatalf("RemoveDevice = %+v", r)
		}
		if entries := serverEntries(t, s, tenant); len(entries) != 1 || entries[0].Action != AuditRemoveDevice {
			t.Fatalf("entries = %+v", entries)
		}
		// Back with a reading, it is a Mac the server hasn't seen: in Fleet, and its whole
		// admin group goes to the SIEM again.
		sendAll(t, s, sink)
		_, _, _, health := fixtures(t)
		health.EventID = newUUID(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{health}, time.Now()); err != nil {
			t.Fatal(err)
		}
		devices, err := s.ListDevices(ctx, tenant)
		if err != nil || len(devices) != 1 || devices[0].RetiredAt != nil || !devices[0].FirstSeenAt.Equal(health.Timestamp) {
			t.Fatalf("devices = %+v, %v", devices, err)
		}
		queued, err := s.ClaimExports(ctx, sink, 10, time.Minute, time.Now())
		if err != nil || len(queued) != 2 || queued[1].Event.Type != event.AgentAdminGroup {
			t.Fatalf("queued = %+v, %v; want the reading and its admin group", queued, err)
		}
	})

	t.Run("a raised event can't bring it back", func(t *testing.T) {
		s, tenant, sink := setup(t)
		quietMac(t, s, tenant, sink)
		if r := removeMac(t, s, tenant, HistoryCutoff{Before: cutoff}); !r.Removed {
			t.Fatalf("RemoveDevice = %+v", r)
		}
		// The silence monitor read its candidates before the removal, and raises its alert after.
		res, err := s.Ingest(ctx, tenant, []event.Event{testfixture.Event(t, "agent-silent")}, time.Now())
		if err != nil || len(res.Accepted) != 1 {
			t.Fatalf("res = %+v, %v", res, err)
		}
		if devices, err := s.ListDevices(ctx, tenant); err != nil || len(devices) != 0 {
			t.Fatalf("devices = %+v, %v", devices, err)
		}
		// Nor can the day's admin group snapshot.
		if ok, err := s.RaiseAdminGroupSnapshot(ctx, tenant, mac, time.Now()); ok || err != nil {
			t.Fatalf("snapshot = %v, %v", ok, err)
		}
	})

	t.Run("a second removal finds nothing", func(t *testing.T) {
		s, tenant, sink := setup(t)
		quietMac(t, s, tenant, sink)
		if r := removeMac(t, s, tenant, HistoryCutoff{Before: cutoff}); !r.Removed {
			t.Fatalf("RemoveDevice = %+v", r)
		}
		if r := removeMac(t, s, tenant, HistoryCutoff{Before: cutoff}); r.Removed || r.Skipped != "" || len(r.RevokedKeys) != 0 || r.Counts != (ExpiryCounts{}) {
			t.Fatalf("second RemoveDevice = %+v", r)
		}
		if entries := serverEntries(t, s, tenant); len(entries) != 2 {
			t.Fatalf("entries = %+v", entries)
		}
	})

	t.Run("keeps a Mac known only by its own clock", func(t *testing.T) {
		s, tenant, sink := setup(t)
		quietMac(t, s, tenant, sink)
		forgetReceived(t, s, tenant)
		keptFor(t, s, tenant, HistoryCutoff{Before: cutoff}, SkippedOwnClock)
	})

	t.Run("keeps a Mac with any event since the cutoff", func(t *testing.T) {
		s, tenant, sink := setup(t)
		quietMac(t, s, tenant, sink)
		// A use of its rotated key after the cutoff, which the server raised: no check-in,
		// so still a candidate, but something is still happening.
		used := testfixture.Event(t, "agent-enrollment-rotated-key-used")
		if _, err := s.Ingest(ctx, tenant, []event.Event{used}, later); err != nil {
			t.Fatal(err)
		}
		sendAll(t, s, sink)
		if got, err := s.RemovalCandidates(ctx, tenant, cutoff); err != nil || !slices.Equal(got, []string{mac}) {
			t.Fatalf("candidates = %v, %v", got, err)
		}
		keptFor(t, s, tenant, HistoryCutoff{Before: cutoff}, SkippedRecentEvent)
	})

	t.Run("never removes a Mac heard from in the last 90 days", func(t *testing.T) {
		s, tenant, sink := setup(t)
		_, _, _, health := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{health}, time.Now().AddDate(0, 0, -30)); err != nil {
			t.Fatal(err)
		}
		sendAll(t, s, sink)
		// Asked to remove what is quiet since now, the stores keep the last 90 days all the same.
		keptFor(t, s, tenant, HistoryCutoff{Before: time.Now()}, SkippedRecentEvent)
	})

	t.Run("keeps a Mac with events the SIEM hasn't had", func(t *testing.T) {
		s, tenant, sink := setup(t)
		quietMac(t, s, tenant, sink)
		if _, err := s.Ingest(ctx, tenant, []event.Event{testfixture.Event(t, "agent-tamper")}, old); err != nil {
			t.Fatal(err)
		}
		keptFor(t, s, tenant, HistoryCutoff{Before: cutoff}, SkippedNotSent)
		// Sent, but received before the SIEM's coverage starts.
		sendAll(t, s, sink)
		covered := testfixture.Time(t, "2025-03-01T00:00:00Z")
		keptFor(t, s, tenant, HistoryCutoff{Before: cutoff, NotBefore: &covered}, SkippedNotSent)
		if r := removeMac(t, s, tenant, HistoryCutoff{Before: cutoff}); !r.Removed {
			t.Fatalf("once nothing holds it, RemoveDevice = %+v", r)
		}
	})

	t.Run("keeps a Mac with an open session", func(t *testing.T) {
		s, tenant, sink := setup(t)
		quietMac(t, s, tenant, sink)
		_, _, oob, _ := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{oob}, old); err != nil {
			t.Fatal(err)
		}
		sendAll(t, s, sink)
		keptFor(t, s, tenant, HistoryCutoff{Before: cutoff}, SkippedOpenSession)
	})

	t.Run("keeps a Mac with a key since the cutoff", func(t *testing.T) {
		s, tenant, sink := setup(t)
		quietMac(t, s, tenant, sink)
		// It is trying to come back: a new key, waiting for approval.
		if again := enrollAt(t, s, tenant, later); again.Status != CredentialPending {
			t.Fatalf("new key %s, want pending", again.Status)
		}
		keptFor(t, s, tenant, HistoryCutoff{Before: cutoff}, SkippedRecentKey)
	})

	t.Run("keeps a Mac whose key an admin approved since the cutoff", func(t *testing.T) {
		s, tenant, sink := setup(t)
		quietMac(t, s, tenant, sink)
		waiting := enrollAt(t, s, tenant, old.Add(time.Hour))
		a := auditFor(t, tenant, AuditApproveEnrollment)
		a.At = later
		if _, err := s.ApproveCredential(ctx, tenant, waiting.DeviceID, later, a); err != nil {
			t.Fatal(err)
		}
		sendAll(t, s, sink)
		// The approval revoked the key it replaced; removing now would revoke the new one.
		if r := removeMac(t, s, tenant, HistoryCutoff{Before: cutoff}); r.Removed || r.Skipped != SkippedRecentKey {
			t.Fatalf("RemoveDevice = %+v, want the Mac kept for %s", r, SkippedRecentKey)
		}
		if c, err := s.Credential(ctx, waiting.DeviceID); err != nil || c.Status != CredentialActive {
			t.Fatalf("approved key = %+v, %v", c, err)
		}
	})

	t.Run("export outbox claim, retry and complete", func(t *testing.T) {
		s, tenant, sink := setup(t)
		granted, revoked, _, _ := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted, revoked}, now); err != nil {
			t.Fatal(err)
		}
		items, err := s.ClaimExports(ctx, sink, 10, time.Minute, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 2 || items[0].Event.EventID != granted.EventID || items[0].TenantID != tenant {
			t.Fatalf("items = %+v", items)
		}
		// Leased items are not handed out twice.
		again, _ := s.ClaimExports(ctx, sink, 10, time.Minute, now)
		if len(again) != 0 {
			t.Fatalf("double claim: %+v", again)
		}
		if err := s.RetryExports(ctx, []int64{items[1].ID}, "boom", now.Add(30*time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := s.CompleteExports(ctx, []int64{items[0].ID}, now); err != nil {
			t.Fatal(err)
		}
		early, _ := s.ClaimExports(ctx, sink, 10, time.Minute, now.Add(10*time.Second))
		if len(early) != 0 {
			t.Fatalf("retry handed out before due: %+v", early)
		}
		due, _ := s.ClaimExports(ctx, sink, 10, time.Minute, now.Add(31*time.Second))
		if len(due) != 1 || due[0].Event.EventID != revoked.EventID || due[0].Attempts != 1 {
			t.Fatalf("due = %+v", due)
		}
		// An expired lease (worker died) makes the item claimable again.
		after, _ := s.ClaimExports(ctx, sink, 10, time.Minute, now.Add(2*time.Minute))
		if len(after) != 1 {
			t.Fatalf("expired lease not reclaimed: %+v", after)
		}
	})

	t.Run("console actions queue for export with the change, after earlier events", func(t *testing.T) {
		s, tenant, sink := setup(t)
		granted, _, _, _ := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted}, now); err != nil {
			t.Fatal(err)
		}
		a := auditFor(t, tenant, AuditChangeSettings)
		a.At = now
		a.Detail = map[string]any{"settings": TenantSettings{SilentAfterHours: 24}}
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{SilentAfterHours: 24}, a); err != nil {
			t.Fatal(err)
		}
		items, err := s.ClaimExports(ctx, sink, 10, time.Minute, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 2 || items[0].Audit != nil || items[0].Event.EventID != granted.EventID {
			t.Fatalf("items = %+v", items)
		}
		got := items[1].Audit
		if got == nil || got.ID != a.ID || got.Action != AuditChangeSettings || got.Actor != "token:test" ||
			!got.At.Equal(now) || got.Seq == 0 || items[1].TenantID != tenant {
			t.Fatalf("audit item = %+v", items[1])
		}
		// Both stores hand back the detail as JSON decodes it.
		if settings, _ := got.Detail["settings"].(map[string]any); settings["silent_after_hours"] != float64(24) {
			t.Fatalf("detail = %#v", got.Detail)
		}
		if err := s.CompleteExports(ctx, []int64{items[0].ID, items[1].ID}, now); err != nil {
			t.Fatal(err)
		}
		if left, _ := s.ClaimExports(ctx, sink, 10, time.Minute, now.Add(time.Hour)); len(left) != 0 {
			t.Fatalf("left = %+v", left)
		}
		// An old entry waiting for export survives a purge until it is sent.
		old := auditFor(t, tenant, AuditChangeSettings)
		old.At = time.Now().AddDate(-2, 0, 0)
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{}, old); err != nil {
			t.Fatal(err)
		}
		cutoff := time.Now().AddDate(-1, 0, -1)
		if _, err := s.PurgeAudit(ctx, cutoff); err != nil {
			t.Fatal(err)
		}
		queued, _ := s.ClaimExports(ctx, sink, 10, time.Minute, time.Now())
		if len(queued) != 1 || queued[0].Audit == nil || queued[0].Audit.ID != old.ID {
			t.Fatalf("queued = %+v", queued)
		}
		if err := s.CompleteExports(ctx, []int64{queued[0].ID}, now); err != nil {
			t.Fatal(err)
		}
		if _, err := s.PurgeAudit(ctx, cutoff); err != nil {
			t.Fatal(err)
		}
		if left, _ := s.ListAudit(ctx, tenant, AuditFilter{}); len(left) != 1 || left[0].ID != a.ID {
			t.Fatalf("after export and purge: %+v", left)
		}
		// A change that fails queues nothing.
		if _, err := s.ApproveCredential(ctx, tenant, newUUID(t), now, auditFor(t, tenant, AuditApproveEnrollment)); err == nil {
			t.Fatal("approved a missing enrollment")
		}
		if left, _ := s.ClaimExports(ctx, sink, 10, time.Minute, now.Add(time.Hour)); len(left) != 0 {
			t.Fatalf("failed change queued %+v", left)
		}
	})

	t.Run("export status per tenant, retry now and a test entry", func(t *testing.T) {
		s, tenant, sink := setup(t)
		granted, _, _, _ := fixtures(t)
		if _, err := s.Ingest(ctx, tenant, []event.Event{granted}, now); err != nil {
			t.Fatal(err)
		}
		items, _ := s.ClaimExports(ctx, sink, 10, time.Minute, now)
		if len(items) != 1 {
			t.Fatalf("claimed %+v", items)
		}
		if err := s.RetryExports(ctx, []int64{items[0].ID}, "SIEM said no", now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		got, err := s.ExportStatus(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Sink != sink || got[0].Pending != 1 || got[0].Failing != 1 ||
			got[0].MaxAttempts != 1 || got[0].LastError != "SIEM said no" || got[0].OldestAt == nil {
			t.Fatalf("status = %+v", got)
		}
		if other, err := s.ExportStatus(ctx, "tenant-"+randomHex(t)); err != nil || len(other) != 0 {
			t.Fatalf("another tenant's status = %+v, %v", other, err)
		}

		// Retry now makes the failed item due at once, and records who asked.
		retryAt := now.Add(time.Minute)
		retry := auditFor(t, tenant, AuditRetryExports)
		retry.At, retry.Target = retryAt, sink
		if n, err := s.RetryExportsNow(ctx, tenant, sink, retryAt, retry); err != nil || n != 1 {
			t.Fatalf("RetryExportsNow = %d, %v", n, err)
		}
		due, _ := s.ClaimExports(ctx, sink, 10, time.Minute, retryAt)
		if len(due) != 2 || due[0].Event.EventID != granted.EventID || due[1].Audit == nil || due[1].Audit.ID != retry.ID {
			t.Fatalf("due after retry now = %+v", due)
		}
		ids := []int64{due[0].ID, due[1].ID}
		deliveredAt := retryAt.Add(time.Second)
		if err := s.CompleteExports(ctx, ids, deliveredAt); err != nil {
			t.Fatal(err)
		}
		// Nothing waits now, but the sink stays listed with when it last delivered.
		got, _ = s.ExportStatus(ctx, tenant)
		if len(got) != 1 || got[0].Pending != 0 || got[0].LastDeliveredAt == nil || !got[0].LastDeliveredAt.Equal(deliveredAt) {
			t.Fatalf("status after delivery = %+v", got)
		}
		if other, _ := s.ExportStatus(ctx, "tenant-"+randomHex(t)); len(other) != 0 {
			t.Fatalf("another tenant sees the delivery: %+v", other)
		}

		// A test entry is queued for every sink, like any console action.
		test := auditFor(t, tenant, AuditTestExport)
		test.At, test.Target = retryAt, "exports"
		if err := s.RecordAudit(ctx, test); err != nil {
			t.Fatal(err)
		}
		queued, _ := s.ClaimExports(ctx, sink, 10, time.Minute, retryAt)
		if len(queued) != 1 || queued[0].Audit == nil || queued[0].Audit.Action != AuditTestExport {
			t.Fatalf("test entry queued %+v", queued)
		}
		// A delivery stamped earlier, from a worker that finished late, doesn't move it back.
		if err := s.CompleteExports(ctx, []int64{queued[0].ID}, deliveredAt.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.ExportStatus(ctx, tenant); len(got) != 1 || !got[0].LastDeliveredAt.Equal(deliveredAt) {
			t.Fatalf("status after a late delivery = %+v", got)
		}
		if listed, _ := s.ListAudit(ctx, tenant, AuditFilter{}); len(listed) != 2 {
			t.Fatalf("audit log = %+v", listed)
		}
	})
}

func ids(ss []session.Session) []string {
	out := []string{}
	for _, s := range ss {
		out = append(out, s.SessionID)
	}
	return out
}

// latestMigration is the newest migration this binary ships.
func latestMigration(t *testing.T) string {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil || len(names) == 0 {
		t.Fatal(names, err)
	}
	slices.Sort(names)
	return strings.TrimSuffix(strings.TrimPrefix(names[len(names)-1], "migrations/"), ".sql")
}

func randomHex(t *testing.T) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestMemory(t *testing.T) {
	withSink := func(t *testing.T, sink string) Store { return NewMemory([]string{sink}) }
	suite(t, withSink)
	credentialSuite(t, func(t *testing.T) Store { return NewMemory(nil) })
	contestAlertSuite(t, withSink)
	commandSuite(t, func(t *testing.T) Store { return NewMemory(nil) })
	auditSuite(t, func(t *testing.T) Store { return NewMemory(nil) })
	mdmSuite(t, func(t *testing.T) Store { return NewMemory(nil) })
}

// TestPostgres runs when ALTIWARD_TEST_DATABASE_URL is set (see dev/compose.yaml).
func TestPostgres(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	withSink := func(t *testing.T, sink string) Store {
		s, err := OpenPostgres(context.Background(), url, []string{sink})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	suite(t, withSink)
	openPlain := func(t *testing.T) Store {
		s, err := OpenPostgres(context.Background(), url, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	credentialSuite(t, openPlain)
	contestAlertSuite(t, withSink)
	commandSuite(t, openPlain)
	auditSuite(t, openPlain)
	mdmSuite(t, openPlain)
}

// TestPostgresStats checks the diagnosis counts. The test database is shared, so it checks
// what this test added rather than totals.
func TestPostgresStats(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	sink := "sink-" + randomHex(t)
	s, err := OpenPostgres(ctx, url, []string{sink})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	events := []event.Event{testfixture.Event(t, "elevation-granted"), testfixture.Event(t, "agent-health")}
	if _, err := s.Ingest(ctx, "tenant-"+randomHex(t), events, now); err != nil {
		t.Fatal(err)
	}
	items, _ := s.ClaimExports(ctx, sink, 1, time.Minute, now)
	if err := s.RetryExports(ctx, []int64{items[0].ID}, "SIEM said no", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	// A connect-only store reads without migrating.
	ro, err := ConnectPostgres(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	st, err := ro.Stats(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.MigrationsPending) != 0 || len(st.MigrationsUnknown) != 0 || st.CountsSkipped != "" ||
		st.MigrationsApplied[len(st.MigrationsApplied)-1] != latestMigration(t) {
		t.Fatalf("migrations = %+v", st)
	}
	if st.Events < 2 || st.Devices < 1 || st.NewestEventAt == nil || st.ServerVersion == "" {
		t.Fatalf("counts = %+v", st)
	}
	var mine *ExportBacklog
	for i := range st.Exports {
		if st.Exports[i].Sink == sink {
			mine = &st.Exports[i]
		}
	}
	// The grant, the reading and the admin group it raised.
	if mine == nil || mine.Pending != 3 || mine.Failing != 1 || mine.MaxAttempts != 1 || mine.LastError != "SIEM said no" {
		t.Fatalf("export backlog = %+v", mine)
	}

	// Dropping a removed sink's queue leaves the events and other sinks' queues alone.
	if n, err := ro.DropExports(ctx, sink); err != nil || n != 3 {
		t.Fatalf("DropExports = %d, %v", n, err)
	}
	if items, err := s.ClaimExports(ctx, sink, 10, time.Minute, now.Add(time.Hour)); err != nil || len(items) != 0 {
		t.Fatalf("after drop, claimed %d, %v", len(items), err)
	}
	if after, err := ro.Stats(ctx, now); err != nil || after.Events != st.Events {
		t.Fatalf("events after drop = %d, want %d (%v)", after.Events, st.Events, err)
	}
}

// TestPostgresRemoveDeviceOnce: two replicas removing the same Mac at once remove it once,
// revoke its key once and record it once, and neither fails.
func TestPostgresRemoveDeviceOnce(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	open := func() *Postgres {
		s, err := OpenPostgres(ctx, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	replicas := []*Postgres{open(), open()}
	tenant, serial := "tenant-"+randomHex(t), "C02XK0AAJGH5"
	old := testfixture.Time(t, "2025-01-01T12:00:00Z")
	events := []event.Event{testfixture.Event(t, "elevation-granted"), testfixture.Event(t, "elevation-revoked"),
		testfixture.Event(t, "agent-health")}
	if _, err := replicas[0].Ingest(ctx, tenant, events, old); err != nil {
		t.Fatal(err)
	}
	if _, err := replicas[0].Enroll(ctx, DeviceCredential{DeviceID: newUUID(t), TenantID: tenant, Serial: serial,
		HardwareUUID: "HW", PublicKey: newKey(t), CreatedAt: old}, EnrollLimits{}); err != nil {
		t.Fatal(err)
	}

	c := HistoryCutoff{Before: testfixture.Time(t, "2025-06-01T00:00:00Z")}
	results := make([]RemovedDevice, len(replicas))
	errs := make([]error, len(replicas))
	var wg sync.WaitGroup
	for i, s := range replicas {
		wg.Go(func() { results[i], errs[i] = s.RemoveDevice(ctx, tenant, serial, c, time.Now()) })
	}
	wg.Wait()
	removed := 0
	for i := range replicas {
		if errs[i] != nil {
			t.Fatalf("replica %d: %v", i, errs[i])
		}
		if results[i].Removed {
			removed++
		}
	}
	if removed != 1 {
		t.Fatalf("results = %+v, want the Mac removed once", results)
	}
	entries, err := replicas[0].ListAudit(ctx, tenant, AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, a := range entries {
		actions[a.Action]++
	}
	if len(entries) != 2 || actions[AuditRemoveDevice] != 1 || actions[AuditRevokeEnrollment] != 1 {
		t.Fatalf("entries = %+v", entries)
	}
}

// TestPostgresWakesWatchersOnOtherInstances: a command queued through one API instance
// wakes a Mac's request held by another sharing the database (long-polling).
func TestPostgresWakesWatchersOnOtherInstances(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	open := func() *Postgres {
		s, err := OpenPostgres(ctx, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	holding, queuing := open(), open()
	tenant, serial := "tenant-"+randomHex(t), "C02"+randomHex(t)
	// The listener wakes every watcher once it is listening; wait for that first.
	warm, stopWarm := holding.WatchCommands(tenant, "warm-up")
	defer stopWarm()
	select {
	case <-warm:
	case <-time.After(10 * time.Second):
		t.Fatal("listener never connected")
	}
	woken, stop := holding.WatchCommands(tenant, serial)
	defer stop()

	user := "jdoe"
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	c := command.Command{
		CommandID: newUUID(t), TenantID: tenant, Serial: serial, Type: command.TypeRevokeAdmin, User: &user,
		IssuedBy: "console", CreatedAt: now, ExpiresAt: now.Add(command.Lifetime),
	}
	if err := queuing.CreateCommand(ctx, c, auditFor(t, tenant, AuditRevokeDevice)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-woken:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher on the other instance not woken")
	}
}
