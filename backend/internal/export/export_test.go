package export_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/export"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

type fakeSink struct {
	mu      sync.Mutex
	fail    bool
	batches [][]export.Record
}

func (f *fakeSink) Name() string { return "fake" }

func (f *fakeSink) Send(_ context.Context, rs []export.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("SIEM down")
	}
	f.batches = append(f.batches, rs)
	return nil
}

func setup(t *testing.T) (*store.Memory, *fakeSink, *export.Worker, *time.Time) {
	s := store.NewMemory([]string{"fake"})
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	events := []event.Event{
		testfixture.Event(t, "elevation-granted"),
		testfixture.Event(t, "agent-health"),
		testfixture.Event(t, "admin-out-of-band"),
	}
	if _, err := s.Ingest(context.Background(), "acme", events, now); err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	w := &export.Worker{
		Store: s, Sinks: []export.Sink{sink}, BatchSize: 2, Lease: time.Minute,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now },
	}
	return s, sink, w, &now
}

func TestDrainSendsExportableEventsOnce(t *testing.T) {
	_, sink, w, _ := setup(t)
	sent, err := w.Drain(context.Background(), sink)
	if err != nil {
		t.Fatal(err)
	}
	// agent.health maps to nothing. The admin group it raised has a record for each of its
	// two members and one for the Mac.
	if sent != 5 {
		t.Fatalf("sent = %d (agent.health must be skipped)", sent)
	}
	var classes []int
	for _, b := range sink.batches {
		for _, r := range b {
			classes = append(classes, r.OCSF["class_uid"].(int))
			if r.TenantID != "acme" {
				t.Fatalf("tenant = %s", r.TenantID)
			}
		}
	}
	if len(classes) != 5 || classes[0] != 3005 || classes[1] != 3006 || classes[3] != 3006 || classes[4] != 2004 {
		t.Fatalf("classes = %v", classes)
	}
	again, _ := w.Drain(context.Background(), sink)
	if again != 0 {
		t.Fatalf("re-sent %d", again)
	}
}

func TestAnEventWithANewAccountSendsARecordForEach(t *testing.T) {
	s := store.NewMemory([]string{"fake"})
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	e := testfixture.Event(t, "persistence-detected")
	e.Detail["findings"] = append(e.Detail["findings"].([]any),
		map[string]any{"kind": "local_account", "change": "added", "name": "breakglass", "uid": 502.0, "admin": true})
	if _, err := s.Ingest(context.Background(), "acme", []event.Event{e}, now); err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	w := &export.Worker{
		Store: s, Sinks: []export.Sink{sink}, BatchSize: 10, Lease: time.Minute,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now },
	}
	if sent, err := w.Drain(context.Background(), sink); err != nil || sent != 2 {
		t.Fatalf("sent %d, err %v", sent, err)
	}
	b := sink.batches[0]
	if b[0].UID() != e.EventID || b[1].UID() != e.EventID+"/account/breakglass" {
		t.Fatalf("uids %s, %s", b[0].UID(), b[1].UID())
	}
	if cef := export.CEF(b[1]); !strings.Contains(cef, "externalId="+e.EventID+"/account/breakglass") ||
		!strings.Contains(cef, "|altiward.account_created|Admin account created|") {
		t.Fatalf("cef = %s", cef)
	}
}

func TestDrainLeavesUnknownTypesQueued(t *testing.T) {
	s := store.NewMemory([]string{"fake"})
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	future := testfixture.Event(t, "agent-health")
	future.EventID = "7d1c4a52-93e0-4b6f-8a1d-5e2f60b7c9a4"
	future.Type = "agent.future" // a type a newer server raises; the memory store doesn't validate
	events := []event.Event{testfixture.Event(t, "elevation-granted"), future}
	if _, err := s.Ingest(context.Background(), "acme", events, now); err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	w := &export.Worker{
		Store: s, Sinks: []export.Sink{sink}, BatchSize: 10, Lease: time.Minute,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now },
	}
	if sent, err := w.Drain(context.Background(), sink); err != nil || sent != 1 {
		t.Fatalf("sent = %d, err = %v", sent, err)
	}
	backlog, err := s.ExportStatus(context.Background(), "acme")
	if err != nil || len(backlog) != 1 || backlog[0].Pending != 1 || !strings.Contains(backlog[0].LastError, "unknown event type agent.future") {
		t.Fatalf("backlog = %+v, err = %v", backlog, err)
	}
	// It waits for the hour: nothing is sent before then.
	if sent, err := w.Drain(context.Background(), sink); err != nil || sent != 0 {
		t.Fatalf("second drain sent = %d, err = %v", sent, err)
	}
	if len(sink.batches) != 1 {
		t.Fatalf("batches = %d", len(sink.batches))
	}
}

func TestFailedSendIsRetriedAfterBackoff(t *testing.T) {
	_, sink, w, now := setup(t)
	sink.fail = true
	if _, err := w.Drain(context.Background(), sink); err == nil {
		t.Fatal("expected failure")
	}
	sink.fail = false
	// The failed batch (grant + health) waits out its backoff; the untried admin group
	// the health raised and out-of-band finding are not held hostage by it.
	sent, _ := w.Drain(context.Background(), sink)
	if sent != 4 || len(sink.batches) != 1 || sink.batches[0][0].Event.Type != event.AgentAdminGroup ||
		sink.batches[0][3].Event.Type != event.AdminOutOfBand {
		t.Fatalf("sent = %d batches = %v", sent, sink.batches)
	}
	*now = now.Add(export.Backoff(1) + time.Second)
	sent, err := w.Drain(context.Background(), sink)
	if err != nil || sent != 1 || sink.batches[1][0].Event.Type != event.ElevationGranted {
		t.Fatalf("sent = %d err = %v", sent, err)
	}
}

func TestDrainSendsConsoleActionsInOrder(t *testing.T) {
	s, sink, w, now := setup(t)
	a := store.AuditEntry{ID: "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", TenantID: "acme", At: *now, Actor: "token:3f2a9c1b",
		Action: store.AuditChangeSettings, Target: "settings"}
	if err := s.PutTenantSettings(context.Background(), "acme", store.TenantSettings{SilentAfterHours: 24}, a); err != nil {
		t.Fatal(err)
	}
	// The grant, the admin group's three records, the out-of-band finding and the action.
	if sent, err := w.Drain(context.Background(), sink); err != nil || sent != 6 {
		t.Fatalf("sent %d, %v", sent, err)
	}
	last := sink.batches[len(sink.batches)-1]
	r := last[len(last)-1]
	if r.Audit == nil || r.UID() != a.ID || r.Type() != "console.change_settings" || r.Host() != "altiward" ||
		!r.Time().Equal(*now) || r.OCSF["class_uid"] != 6003 {
		t.Fatalf("record = %+v", r)
	}
}

func TestBackoff(t *testing.T) {
	cases := map[int]time.Duration{1: 30 * time.Second, 2: time.Minute, 4: 4 * time.Minute, 20: time.Hour}
	for n, want := range cases {
		if got := export.Backoff(n); got != want {
			t.Errorf("Backoff(%d) = %v, want %v", n, got, want)
		}
	}
}
