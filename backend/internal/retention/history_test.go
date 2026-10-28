package retention_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/command"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/retention"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// The stores never remove anything received in the last 90 days by the real clock, so
// history here is received in 2025, and the job's clock is a year and five months on.
var (
	received = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	runAt    = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) // a year back is 2025-06-01
)

func newHistory(s store.Store, sinks ...string) *retention.History {
	return &retention.History{Store: s, Sinks: sinks, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return runAt }, BatchSize: 2}
}

// oldSession stores an ended session for tenant, received in 2025, and delivers everything
// queued for sinks, so only the period holds it.
func oldSession(t *testing.T, s store.Store, tenant string, sinks ...string) {
	t.Helper()
	ctx := context.Background()
	evs := []event.Event{testfixture.Event(t, "elevation-granted"), testfixture.Event(t, "elevation-revoked")}
	if _, err := s.Ingest(ctx, tenant, evs, received); err != nil {
		t.Fatal(err)
	}
	for _, sink := range sinks {
		items, err := s.ClaimExports(ctx, sink, 100, time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		ids := []int64{}
		for _, it := range items {
			ids = append(ids, it.ID)
		}
		if err := s.CompleteExports(ctx, ids, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

func setHistory(t *testing.T, s store.Store, tenant string, days int) {
	t.Helper()
	a := store.AuditEntry{ID: newID(t), TenantID: tenant, At: received, Actor: "token:test",
		Action: store.AuditChangeSettings, Target: "settings"}
	if err := s.PutTenantSettings(context.Background(), tenant, store.TenantSettings{HistoryDays: days}, a); err != nil {
		t.Fatal(err)
	}
}

func backfilled(t *testing.T, s store.Store) {
	t.Helper()
	if _, err := s.BackfillAdminGroups(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func kept(t *testing.T, s store.Store, tenant string) bool {
	t.Helper()
	_, _, err := s.GetSession(context.Background(), tenant, *testfixture.Event(t, "elevation-granted").SessionID)
	if err != nil && err != store.ErrNotFound {
		t.Fatal(err)
	}
	return err == nil
}

func expiryEntries(t *testing.T, s store.Store, tenant string) []store.AuditEntry {
	t.Helper()
	all, err := s.ListAudit(context.Background(), tenant, store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	out := []store.AuditEntry{}
	for _, a := range all {
		if a.Action == store.AuditExpireHistory {
			out = append(out, a)
		}
	}
	return out
}

func newID(t *testing.T) string {
	t.Helper()
	id, err := store.NewDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestHistoryWaitsForTheAdminGroupBackfill(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory(nil)
	setHistory(t, s, "acme", 365)
	oldSession(t, s, "acme")
	h := newHistory(s)
	if n, err := h.Purge(ctx); err != nil || n != (store.ExpiryCounts{}) || !kept(t, s, "acme") {
		t.Fatalf("before the backfill: removed %+v, %v", n, err)
	}
	backfilled(t, s)
	if n, err := h.Purge(ctx); err != nil || n != (store.ExpiryCounts{Events: 2, Sessions: 1}) || kept(t, s, "acme") {
		t.Fatalf("after the backfill: removed %+v, %v", n, err)
	}
}

func TestHistoryIsKeptWithoutASIEMByDefault(t *testing.T) {
	s := store.NewMemory(nil)
	oldSession(t, s, "acme")
	backfilled(t, s)
	if n, err := newHistory(s).Purge(context.Background()); err != nil || n != (store.ExpiryCounts{}) || !kept(t, s, "acme") {
		t.Fatalf("removed %+v, %v", n, err)
	}
	if got := expiryEntries(t, s, "acme"); len(got) != 0 {
		t.Fatalf("recorded %+v", got)
	}
}

// A SIEM is connected but nothing says since when: nothing is removed rather than guess.
func TestHistoryIsKeptWhenTheSIEMCoverageIsUnknown(t *testing.T) {
	s := store.NewMemory([]string{"siem"})
	oldSession(t, s, "acme", "siem")
	backfilled(t, s)
	if n, err := newHistory(s, "siem").Purge(context.Background()); err != nil || n != (store.ExpiryCounts{}) || !kept(t, s, "acme") {
		t.Fatalf("removed %+v, %v", n, err)
	}
}

func TestHistoryExpiryIsRecordedOncePerOrganisation(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory([]string{"siem"})
	covered := time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC)
	if err := s.RecordSinks(ctx, []string{"siem"}, covered); err != nil {
		t.Fatal(err)
	}
	setHistory(t, s, "keeps", store.HistoryKeptForGood)
	oldSession(t, s, "acme", "siem")
	oldSession(t, s, "keeps", "siem")
	backfilled(t, s)

	h := newHistory(s, "siem")
	n, err := h.Purge(ctx)
	if err != nil || n != (store.ExpiryCounts{Events: 2, Sessions: 1}) {
		t.Fatalf("removed %+v, %v", n, err)
	}
	if kept(t, s, "acme") || !kept(t, s, "keeps") {
		t.Fatalf("acme kept %v, keeps kept %v", kept(t, s, "acme"), kept(t, s, "keeps"))
	}
	got := expiryEntries(t, s, "acme")
	if len(got) != 1 {
		t.Fatalf("entries = %+v", got)
	}
	a := got[0]
	if a.Actor != store.ServerActor || a.Target != "history" || !a.At.Equal(runAt) {
		t.Fatalf("entry = %+v", a)
	}
	counts, _ := a.Detail["counts"].(map[string]any)
	if a.Detail["before"] != "2025-06-01T00:00:00Z" || a.Detail["days"] != 365.0 || a.Detail["reason"] != store.HistoryReasonDefaultSIEM ||
		a.Detail["held_before"] != "2024-12-01T00:00:00Z" ||
		counts["events"] != 2.0 || counts["sessions"] != 1.0 || counts["commands"] != 0.0 || counts["macs"] != 0.0 {
		t.Fatalf("detail = %#v", a.Detail)
	}
	if got := expiryEntries(t, s, "keeps"); len(got) != 0 {
		t.Fatalf("kept for good, yet recorded %+v", got)
	}
	// The entry goes to the SIEM like any other.
	items, err := s.ClaimExports(ctx, "siem", 10, time.Minute, runAt)
	if err != nil || len(items) != 1 || items[0].Audit == nil || items[0].Audit.ID != a.ID {
		t.Fatalf("queued = %+v, %v", items, err)
	}

	// A second run finds nothing more, and records nothing.
	if n, err := h.Purge(ctx); err != nil || n != (store.ExpiryCounts{}) {
		t.Fatalf("second run removed %+v, %v", n, err)
	}
	if got := expiryEntries(t, s, "acme"); len(got) != 1 {
		t.Fatalf("entries after a second run = %+v", got)
	}
}

// stopsAfterOneBatch is a store whose run is stopped, as at shutdown, once one batch of
// history has gone. Like Postgres, it then refuses anything asked on the cancelled context,
// and it refuses an entry recorded with no time limit.
type stopsAfterOneBatch struct {
	store.Store
	stop context.CancelFunc
}

func (s *stopsAfterOneBatch) ExpireHistory(ctx context.Context, tenant string, c store.HistoryCutoff, limit int) (store.ExpiryCounts, error) {
	if err := ctx.Err(); err != nil {
		return store.ExpiryCounts{}, err
	}
	n, err := s.Store.ExpireHistory(ctx, tenant, c, limit)
	s.stop()
	return n, err
}

func (s *stopsAfterOneBatch) RecordAudit(ctx context.Context, a store.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("recorded with no time limit")
	}
	return s.Store.RecordAudit(ctx, a)
}

// What a run removed before it was stopped stays removed, so it is still recorded and logged.
func TestHistoryStoppedPartWayRecordsWhatItRemoved(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	mem := store.NewMemory(nil)
	setHistory(t, mem, "acme", 365)
	oldSession(t, mem, "acme")
	for range 2 {
		c := command.Command{CommandID: newID(t), TenantID: "acme", Serial: "C02XK0AAJGH5", Type: command.TypeRevokeAdmin,
			IssuedBy: "token:test", CreatedAt: received, ExpiresAt: received.Add(command.Lifetime)}
		a := store.AuditEntry{ID: newID(t), TenantID: "acme", At: received, Actor: "token:test",
			Action: store.AuditRevokeDevice, Target: "C02XK0AAJGH5"}
		if err := mem.CreateCommand(context.Background(), c, a); err != nil {
			t.Fatal(err)
		}
	}
	backfilled(t, mem)
	logged := &bytes.Buffer{}
	h := &retention.History{Store: &stopsAfterOneBatch{Store: mem, stop: stop}, Log: slog.New(slog.NewTextHandler(logged, nil)),
		Now: func() time.Time { return runAt }, BatchSize: 1}

	// The first batch takes the session with its two events, and one of the commands.
	n, err := h.Purge(ctx)
	if !errors.Is(err, context.Canceled) || n != (store.ExpiryCounts{Events: 2, Sessions: 1, Commands: 1}) {
		t.Fatalf("removed %+v, %v", n, err)
	}
	if left, _ := mem.ListCommands(context.Background(), "acme", store.CommandFilter{}, runAt); len(left) != 1 {
		t.Fatalf("commands left = %d, want the run stopped with one to go", len(left))
	}
	got := expiryEntries(t, mem, "acme")
	if len(got) != 1 {
		t.Fatalf("entries = %+v", got)
	}
	if counts, _ := got[0].Detail["counts"].(map[string]any); counts["events"] != 2.0 || counts["sessions"] != 1.0 || counts["commands"] != 1.0 {
		t.Fatalf("detail = %#v", got[0].Detail)
	}
	for _, want := range []string{"tenant=acme", "events=2", "sessions=1", "commands=1"} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("log has no %s:\n%s", want, logged)
		}
	}
}
