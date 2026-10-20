package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// TestPostgresReplayExports checks that a sink added later can be sent what came before it.
// The test database is shared, so it counts only this test's tenant.
func TestPostgresReplayExports(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	tenant := "tenant-" + randomHex(t)
	before := testfixture.Time(t, "2026-10-16T12:00:00Z")
	since := before.Add(time.Hour)

	// Written while no sink was configured: nothing is queued.
	old, err := OpenPostgres(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(old.Close)
	if _, err := old.Ingest(ctx, tenant, []event.Event{testfixture.Event(t, "elevation-granted")}, before); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Ingest(ctx, tenant, []event.Event{testfixture.Event(t, "elevation-revoked")}, since.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	a := auditFor(t, tenant, AuditChangeSettings)
	a.At = since.Add(2 * time.Minute)
	if err := old.PutTenantSettings(ctx, tenant, TenantSettings{SilentAfterHours: 48}, a); err != nil {
		t.Fatal(err)
	}

	sink := "sink-" + randomHex(t)
	s, err := OpenPostgres(ctx, url, []string{sink})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	t.Cleanup(func() { _, _ = s.DropExports(ctx, sink) })
	queued := func() int {
		var n int
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM export_outbox WHERE sink = $1 AND tenant_id = $2`,
			sink, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := queued(); n != 0 {
		t.Fatalf("queued before replay = %d", n)
	}

	now := since.Add(time.Hour)
	if _, err := s.ReplayExports(ctx, sink, since, now); err != nil {
		t.Fatal(err)
	}
	// The event and the console action from since on, not the event before it.
	if n := queued(); n != 2 {
		t.Fatalf("queued after replay = %d, want 2", n)
	}
	items, err := s.ClaimExports(ctx, sink, 100, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	var mine []ExportItem
	for _, it := range items {
		if it.TenantID == tenant {
			mine = append(mine, it)
		}
	}
	if len(mine) != 2 || mine[0].Audit != nil || mine[0].Event.Type != event.ElevationRevoked ||
		mine[1].Audit == nil || mine[1].Audit.ID != a.ID {
		t.Fatalf("claimed %+v, want the revoke then the console action", mine)
	}
	if err := s.RetryExports(ctx, []int64{mine[0].ID, mine[1].ID}, "", now); err != nil {
		t.Fatal(err)
	}

	// Replaying again doesn't queue what is already waiting.
	if _, err := s.ReplayExports(ctx, sink, since, now); err != nil {
		t.Fatal(err)
	}
	if n := queued(); n != 2 {
		t.Fatalf("queued after a second replay = %d, want 2", n)
	}
}
