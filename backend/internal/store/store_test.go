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
	"strings"
	"testing"
	"time"

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
		// enrolment, the health event and the pending enrolment, in the order they arrived.
		queued, _ = s.ClaimExports(ctx, sink, 10, time.Minute, now.Add(time.Hour))
		if len(queued) != 3 || queued[2].Event.EventID != pending.EventID {
			t.Fatalf("pending enrolment not queued for export: %d items", len(queued))
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
	if mine == nil || mine.Pending != 2 || mine.Failing != 1 || mine.MaxAttempts != 1 || mine.LastError != "SIEM said no" {
		t.Fatalf("export backlog = %+v", mine)
	}

	// Dropping a removed sink's queue leaves the events and other sinks' queues alone.
	if n, err := ro.DropExports(ctx, sink); err != nil || n != 2 {
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
