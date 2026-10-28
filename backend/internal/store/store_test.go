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
