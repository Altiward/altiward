package store

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/admingroup"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// backfillHarness is what the backfill tests need of a store beyond Store: ways to stand for
// readings that an older server stored, which raised nothing.
type backfillHarness struct {
	// open returns an empty store that queues every event for sink.
	open func(t *testing.T, sink string) Store
	// quietly runs f with ingest's admin group raising off, as in a server before the upgrade.
	quietly func(s Store, f func())
	// startAt moves the start of the admin group history to at.
	startAt func(t *testing.T, s Store, at time.Time)
	// reported says whether the Mac has a group last reported (what ingest keeps).
	reported func(t *testing.T, s Store, tenantID, serial string) bool
}

// backfillSuite checks BackfillAdminGroups. The installation record is one per database, so
// Postgres runs every case in a schema of its own.
func backfillSuite(t *testing.T, h backfillHarness) {
	ctx := context.Background()
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	const tenant = "acme"
	const serial = "C02XK0AAJGH5"

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
	// readings are members A, then A and B, then B, received five minutes apart from now.
	readings := func(t *testing.T) []event.Event {
		base := testfixture.Event(t, "agent-health").Timestamp
		return []event.Event{
			reading(t, "3e9c9d85-9d3b-4a6b-8c8b-0000000000a1", base, "itadmin"),
			reading(t, "3e9c9d85-9d3b-4a6b-8c8b-0000000000a2", base.Add(5*time.Minute), "backdoor", "itadmin"),
			reading(t, "3e9c9d85-9d3b-4a6b-8c8b-0000000000a3", base.Add(10*time.Minute), "backdoor"),
		}
	}
	ingest := func(t *testing.T, s Store, es []event.Event) {
		t.Helper()
		for i, e := range es {
			if _, err := s.Ingest(ctx, tenant, []event.Event{e}, now.Add(time.Duration(i)*5*time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// raisedBy is the admin group events due for the sink at at, oldest first.
	raisedBy := func(t *testing.T, s Store, sink string, at time.Time) []event.Event {
		t.Helper()
		items, err := s.ClaimExports(ctx, sink, 100, time.Minute, at)
		if err != nil {
			t.Fatal(err)
		}
		out := []event.Event{}
		for _, it := range items {
			if e := it.Event.Event; e.Type == event.AgentAdminGroup {
				if err := e.Validate(now.Add(time.Hour)); err != nil {
					t.Fatalf("queued an invalid event: %v", err)
				}
				out = append(out, e)
			}
		}
		return out
	}
	// raised is the admin group events queued, oldest first, once everything is due: the
	// backfill below runs at most three hours on, and holds what it stores for an hour.
	raised := func(t *testing.T, s Store, sink string) []event.Event {
		t.Helper()
		return raisedBy(t, s, sink, now.Add(5*time.Hour))
	}
	states := func(es []event.Event) []string {
		out := []string{}
		for _, e := range es {
			s, _ := e.Detail["state"].(string)
			out = append(out, s)
		}
		return out
	}
	backfilledAt := func(t *testing.T, s Store) *time.Time {
		t.Helper()
		in, err := s.Installation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return in.AdminGroupBackfilledAt
	}
	// stored readings the server before the upgrade took, with the upgrade after all of them.
	upgraded := func(t *testing.T) (Store, string) {
		t.Helper()
		sink := "sink-" + randomHex(t)
		s := h.open(t, sink)
		h.quietly(s, func() { ingest(t, s, readings(t)) })
		return s, sink
	}

	t.Run("backfills the admin group once", func(t *testing.T) {
		s, sink := upgraded(t)
		h.startAt(t, s, now.Add(time.Hour))
		if got := raised(t, s, sink); len(got) != 0 {
			t.Fatalf("queued before the backfill: %+v", got)
		}
		n, err := s.BackfillAdminGroups(ctx, now.Add(2*time.Hour))
		if err != nil || n != 3 {
			t.Fatalf("raised %d, %v", n, err)
		}
		got := raised(t, s, sink)
		if want := []string{event.AdminGroupSnapshot, event.AdminGroupChanged, event.AdminGroupChanged}; !slices.Equal(states(got), want) {
			t.Fatalf("states %v, want %v", states(got), want)
		}
		in, _ := s.Installation(ctx)
		rs := readings(t)
		if got[0].EventID != admingroup.ID(in.RaisedIDSecret, tenant, serial, "first/"+rs[0].EventID) ||
			got[1].EventID != admingroup.ID(in.RaisedIDSecret, tenant, serial, "changed/"+rs[1].EventID) ||
			got[2].EventID != admingroup.ID(in.RaisedIDSecret, tenant, serial, "changed/"+rs[2].EventID) {
			t.Fatalf("event IDs do not derive from the readings: %+v", got)
		}
		// As ingest would have stamped them: with the time its reading was received.
		if !got[0].Timestamp.Equal(now) || !got[2].Timestamp.Equal(now.Add(10*time.Minute)) {
			t.Fatalf("timestamps %v and %v", got[0].Timestamp, got[2].Timestamp)
		}
		if at := backfilledAt(t, s); at == nil || !at.Equal(now.Add(2*time.Hour)) {
			t.Fatalf("backfilled at %v", at)
		}
		if h.reported(t, s, tenant, serial) {
			t.Fatal("the backfill recorded a group for the Mac, which ingest owns")
		}

		// Once done, it does nothing more.
		if n, err = s.BackfillAdminGroups(ctx, now.Add(3*time.Hour)); err != nil || n != 0 {
			t.Fatalf("second call raised %d, %v", n, err)
		}
		if got := raised(t, s, sink); len(got) != 0 {
			t.Fatalf("second call queued %+v", got)
		}
		if at := backfilledAt(t, s); at == nil || !at.Equal(now.Add(2*time.Hour)) {
			t.Fatalf("backfilled at %v after the second call", at)
		}
	})

	t.Run("holds what it stores for an hour", func(t *testing.T) {
		s, sink := upgraded(t)
		h.startAt(t, s, now.Add(time.Hour))
		at := now.Add(2 * time.Hour)
		if n, err := s.BackfillAdminGroups(ctx, at); err != nil || n != 3 {
			t.Fatalf("raised %d, %v", n, err)
		}
		// An older revision still running during an update claims only what is due, so it
		// can't mark these sent without sending them.
		if got := raisedBy(t, s, sink, at.Add(59*time.Minute)); len(got) != 0 {
			t.Fatalf("due within the hour: %+v", got)
		}
		if got := raisedBy(t, s, sink, at.Add(time.Hour)); len(got) != 3 {
			t.Fatalf("due once the hour was up: %+v", got)
		}
	})

	t.Run("leaves out readings received after the start", func(t *testing.T) {
		s, sink := upgraded(t)
		// The third reading came 10 minutes after the first, so it is the live path's.
		h.startAt(t, s, now.Add(10*time.Minute))
		n, err := s.BackfillAdminGroups(ctx, now.Add(time.Hour))
		if err != nil || n != 2 {
			t.Fatalf("raised %d, %v", n, err)
		}
		if got := raised(t, s, sink); !slices.Equal(states(got), []string{event.AdminGroupSnapshot, event.AdminGroupChanged}) {
			t.Fatalf("states %v", states(got))
		}
	})

	t.Run("stores nothing that ingest raised already, and still finishes", func(t *testing.T) {
		sink := "sink-" + randomHex(t)
		s := h.open(t, sink)
		ingest(t, s, readings(t)) // raised live
		if got := raised(t, s, sink); len(got) != 3 {
			t.Fatalf("live path queued %+v", got)
		}
		h.startAt(t, s, now.Add(time.Hour))
		n, err := s.BackfillAdminGroups(ctx, now.Add(2*time.Hour))
		if err != nil || n != 0 {
			t.Fatalf("raised %d, %v", n, err)
		}
		if got := raised(t, s, sink); len(got) != 0 {
			t.Fatalf("queued again: %+v", got)
		}
		if backfilledAt(t, s) == nil {
			t.Fatal("not recorded as done")
		}
	})

	t.Run("finishes when there are no readings", func(t *testing.T) {
		s := h.open(t, "sink-"+randomHex(t))
		if n, err := s.BackfillAdminGroups(ctx, now); err != nil || n != 0 {
			t.Fatalf("raised %d, %v", n, err)
		}
		if at := backfilledAt(t, s); at == nil || !at.Equal(now) {
			t.Fatalf("backfilled at %v", at)
		}
	})
}

func TestMemoryAdminGroupBackfill(t *testing.T) {
	backfillSuite(t, backfillHarness{
		open: func(t *testing.T, sink string) Store { return NewMemory([]string{sink}) },
		quietly: func(s Store, f func()) {
			m := s.(*Memory)
			secret := m.installation.RaisedIDSecret
			m.installation.RaisedIDSecret = nil
			defer func() { m.installation.RaisedIDSecret = secret }()
			f()
		},
		startAt: func(t *testing.T, s Store, at time.Time) { s.(*Memory).installation.AdminGroupStartedAt = at },
		reported: func(t *testing.T, s Store, tenantID, serial string) bool {
			_, ok := s.(*Memory).adminGroups[key{tenantID, serial}]
			return ok
		},
	})
}

func TestPostgresAdminGroupBackfill(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	// Pages of two readings, so the three each case stores take two pages and the walk
	// carries the group across them.
	page := backfillPage
	backfillPage = 2
	t.Cleanup(func() { backfillPage = page })
	backfillSuite(t, backfillHarness{
		open: func(t *testing.T, sink string) Store {
			s, err := OpenPostgres(context.Background(), inSchema(t, url, "backfill_"+randomHex(t)), []string{sink})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Close)
			return s
		},
		quietly: func(s Store, f func()) {
			p := s.(*Postgres)
			secret := p.raisedIDSecret
			p.raisedIDSecret = nil
			defer func() { p.raisedIDSecret = secret }()
			f()
		},
		startAt: func(t *testing.T, s Store, at time.Time) {
			if _, err := s.(*Postgres).pool.Exec(context.Background(),
				`UPDATE installation SET admin_group_started_at = $1`, at); err != nil {
				t.Fatal(err)
			}
		},
		reported: func(t *testing.T, s Store, tenantID, serial string) bool {
			var group []byte
			err := s.(*Postgres).pool.QueryRow(context.Background(),
				`SELECT admin_group FROM devices WHERE tenant_id = $1 AND serial = $2`, tenantID, serial).Scan(&group)
			if err != nil {
				t.Fatal(err)
			}
			return group != nil
		},
	})
}
