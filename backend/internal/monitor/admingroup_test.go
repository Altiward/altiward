package monitor_test

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/monitor"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// sweeps counts the sweeps that reach the store.
type sweeps struct {
	store.Store
	n atomic.Int32
}

func (s *sweeps) AdminGroupSnapshotCandidates(ctx context.Context, since time.Time) ([]store.DeviceRef, error) {
	s.n.Add(1)
	return s.Store.AdminGroupSnapshotCandidates(ctx, since)
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
