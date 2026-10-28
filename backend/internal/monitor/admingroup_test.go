package monitor_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/monitor"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// sweeps counts the sweeps and backfills that reach the store, and records which came
// first. A backfill fails while failing is set.
type sweeps struct {
	store.Store
	n          atomic.Int32
	backfills  atomic.Int32
	order      []string
	mu         sync.Mutex
	failing    atomic.Bool
	firstSweep chan struct{}
	once       sync.Once
}

func (s *sweeps) AdminGroupSnapshotCandidates(ctx context.Context, since time.Time) ([]store.DeviceRef, error) {
	s.n.Add(1)
	s.note("sweep")
	if s.firstSweep != nil {
		s.once.Do(func() { close(s.firstSweep) })
	}
	return s.Store.AdminGroupSnapshotCandidates(ctx, since)
}

func (s *sweeps) BackfillAdminGroups(ctx context.Context, now time.Time) (int, error) {
	s.backfills.Add(1)
	if s.failing.Load() {
		s.note("failed backfill")
		return 0, errors.New("database unavailable")
	}
	s.note("backfill")
	return s.Store.BackfillAdminGroups(ctx, now)
}

func (s *sweeps) note(what string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.order = append(s.order, what)
}

func (s *sweeps) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.order)
}

func TestAdminGroupsSweepRaisesOneSnapshotADay(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory([]string{"splunk"})
	health := testfixture.Event(t, "agent-health")
	now := health.Timestamp.Add(time.Hour)
	if _, err := st.Ingest(ctx, tenant, []event.Event{health}, now); err != nil {
		t.Fatal(err)
	}
	w := &monitor.AdminGroups{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}
	for i, want := range []int{1, 0} {
		raised, err := w.Sweep(ctx)
		if err != nil || raised != want {
			t.Fatalf("sweep %d: raised = %d, err = %v", i, raised, err)
		}
	}
	// The reading, the group it reported, then the day's snapshot.
	items, _ := st.ClaimExports(ctx, "splunk", 10, time.Minute, now)
	if len(items) != 3 || items[2].Event.Type != event.AgentAdminGroup || items[2].Event.Detail["state"] != event.AdminGroupSnapshot {
		t.Fatalf("exports = %+v", items)
	}
	// A Mac that hasn't checked in for a day isn't snapshotted.
	w.Now = func() time.Time { return now.Add(25 * time.Hour) }
	if raised, err := w.Sweep(ctx); raised != 0 || err != nil {
		t.Fatalf("raised = %d, err = %v for a Mac last seen over a day ago", raised, err)
	}
}

func TestAdminGroupsRunWaitsBeforeTheFirstSweep(t *testing.T) {
	counting := &sweeps{Store: store.NewMemory(nil)}
	w := &monitor.AdminGroups{Store: counting, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now}

	// Cancelled before the first delay is up: nothing is swept.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx, time.Hour, 50*time.Millisecond); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't stop when its context was cancelled")
	}
	time.Sleep(100 * time.Millisecond)
	if n := counting.n.Load(); n != 0 {
		t.Fatalf("swept %d times before the first delay was up", n)
	}
	// Nor is the backfill run: an older revision may still be draining new event types.
	if n := counting.backfills.Load(); n != 0 {
		t.Fatalf("backfilled %d times before the first delay was up", n)
	}

	// Left alone, it sweeps once the delay has passed.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx, time.Hour, 50*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for counting.n.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("never swept")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The backfill of readings stored before the upgrade waits for the first sweep's delay, as
// the snapshots do, runs before that sweep, and is tried again before the next sweep until
// it succeeds.
func TestAdminGroupsRunBackfillsBeforeTheFirstSweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := store.NewMemory(nil)
	counting := &sweeps{Store: st, firstSweep: make(chan struct{})}
	counting.failing.Store(true)
	w := &monitor.AdminGroups{Store: counting, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now}
	go w.Run(ctx, 20*time.Millisecond, 50*time.Millisecond)
	select {
	case <-counting.firstSweep:
	case <-time.After(5 * time.Second):
		t.Fatal("never swept")
	}
	counting.failing.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for counting.n.Load() < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("swept %d times", counting.n.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	got := counting.seen()
	// A failed backfill, then each sweep; the first sweep after the store recovers is
	// preceded by the backfill that succeeds, and none follows it.
	if len(got) < 2 || got[0] != "failed backfill" || got[1] != "sweep" {
		t.Fatalf("order = %v", got)
	}
	done := slices.Index(got, "backfill")
	if done < 0 || got[done+1] != "sweep" || slices.Contains(got[done+1:], "backfill") || slices.Contains(got[done+1:], "failed backfill") {
		t.Fatalf("order = %v", got)
	}
	if in, err := st.Installation(ctx); err != nil || in.AdminGroupBackfilledAt == nil {
		t.Fatalf("installation = %+v, %v", in, err)
	}
}
