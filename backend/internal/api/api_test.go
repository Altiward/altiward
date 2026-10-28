package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/admingroup"
	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

const (
	agentToken   = "agent-token-acme-0001"
	consoleToken = "console-token-acme-0001"
	otherConsole = "console-token-other-001"
)

func newServer(t *testing.T) http.Handler {
	t.Helper()
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken+",other="+otherConsole)
	if err != nil {
		t.Fatal(err)
	}
	now := serverNow(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.New(store.NewMemory(nil), tokens, log, func() time.Time { return now })
}

func do(t *testing.T, h http.Handler, method, path, token string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, ok := body.([]byte)
		if !ok {
			var err error
			if b, err = json.Marshal(body); err != nil {
				t.Fatal(err)
			}
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func batch(t *testing.T, names ...string) []byte {
	raws := []json.RawMessage{}
	for _, n := range names {
		raws = append(raws, testfixture.Raw(t, n))
	}
	b, _ := json.Marshal(map[string]any{"events": raws})
	return b
}

func TestIngestThenReadTimeline(t *testing.T) {
	h := newServer(t)
	rec, out := enrollAgent(t, h, fixtureSerial).post(t, batch(t, "elevation-granted", "elevation-revoked"))
	if rec.Code != 200 || len(out["accepted"].([]any)) != 2 {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}

	rec, out = do(t, h, "GET", "/v1/sessions", consoleToken, nil)
	sessions := out["sessions"].([]any)
	if rec.Code != 200 || len(sessions) != 1 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	s := sessions[0].(map[string]any)
	if s["local_user"] != "jdoe" || s["open"] != false || s["allowed_seconds"] != 1200.0 || s["overran"] != false {
		t.Fatalf("session view = %v", s)
	}

	rec, out = do(t, h, "GET", "/v1/sessions/"+s["session_id"].(string), consoleToken, nil)
	events := out["events"].([]any)
	if rec.Code != 200 || len(events) != 2 || events[0].(map[string]any)["received_at"] == nil {
		t.Fatalf("timeline: %d %s", rec.Code, rec.Body)
	}
}

func TestIngestVerdictsPerEvent(t *testing.T) {
	h := newServer(t)
	bad := strings.Replace(string(testfixture.Raw(t, "elevation-revoked")), `"schema_version": 1`, `"schema_version": 9`, 1)
	body, _ := json.Marshal(map[string]any{"events": []json.RawMessage{
		testfixture.Raw(t, "elevation-granted"),
		testfixture.Raw(t, "elevation-granted"), // duplicate within the batch
		json.RawMessage(bad),
	}})
	a := enrollAgent(t, h, fixtureSerial)
	rec, out := a.post(t, body)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rejected := out["rejected"].([]any)
	if len(out["accepted"].([]any)) != 1 || len(out["duplicate"].([]any)) != 1 || len(rejected) != 1 {
		t.Fatalf("verdicts = %v", out)
	}
	r := rejected[0].(map[string]any)
	if r["event_id"] != "1c7a7b63-7b1f-4e4f-8a6f-4a3b2d0e8f12" || !strings.Contains(r["error"].(string), "schema_version") {
		t.Fatalf("rejection = %v", r)
	}

	// A retry of the same batch is all duplicates.
	_, out = a.post(t, batch(t, "elevation-granted"))
	if len(out["duplicate"].([]any)) != 1 {
		t.Fatalf("retry = %v", out)
	}
}

// A raised event's ID already stored as something else means someone forged it: the server
// says so in its log, and the Mac's reading is stored and acknowledged all the same.
func TestIngestLogsARaisedIDAlreadyTaken(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory(nil)
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	now := serverNow(t)
	h := api.New(st, tokens, slog.New(slog.NewTextHandler(&logs, nil)), func() time.Time { return now })

	in, err := st.Installation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	health := testfixture.Event(t, "agent-health")
	taken := testfixture.Event(t, "elevation-granted")
	taken.EventID = admingroup.ID(in.RaisedIDSecret, "acme", fixtureSerial, "first/"+health.EventID)
	if _, err := st.Ingest(ctx, "acme", []event.Event{taken}, now); err != nil {
		t.Fatal(err)
	}

	rec, out := enrollAgent(t, h, fixtureSerial).post(t, batch(t, "agent-health"))
	if accepted, _ := out["accepted"].([]any); rec.Code != 200 || len(accepted) != 1 || accepted[0] != health.EventID ||
		len(out["duplicate"].([]any)) != 0 {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	line := ""
	for l := range strings.Lines(logs.String()) {
		if strings.Contains(l, "raised event ID already taken") {
			line = l
		}
	}
	if !strings.Contains(line, "level=ERROR") || !strings.Contains(line, "event_id="+taken.EventID) ||
		!strings.Contains(line, "device="+fixtureSerial) {
		t.Fatalf("log = %s", logs.String())
	}
}

// raisesInvalid is a store whose ingest reports a raised event that failed validation.
type raisesInvalid struct {
	store.Store
	id string
}

func (s raisesInvalid) Ingest(ctx context.Context, tenantID string, events []event.Event, receivedAt time.Time) (store.IngestResult, error) {
	res, err := s.Store.Ingest(ctx, tenantID, events, receivedAt)
	res.RaisedInvalid = append(res.RaisedInvalid, s.id)
	return res, err
}

// A raised event the server couldn't make valid is a bug in the server: it says so in its
// log, and the Mac's reading is stored and acknowledged all the same.
func TestIngestLogsAnInvalidRaisedEvent(t *testing.T) {
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	now := serverNow(t)
	const id = "0b9f5f2e-4c1d-5e6f-8a7b-9c0d1e2f3a4b"
	h := api.New(raisesInvalid{store.NewMemory(nil), id}, tokens, slog.New(slog.NewTextHandler(&logs, nil)),
		func() time.Time { return now })
	health := testfixture.Event(t, "agent-health")
	rec, out := enrollAgent(t, h, fixtureSerial).post(t, batch(t, "agent-health"))
	if accepted, _ := out["accepted"].([]any); rec.Code != 200 || len(accepted) != 1 || accepted[0] != health.EventID {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), id) {
		t.Fatalf("the agent was told of the server's event: %s", rec.Body)
	}
	line := ""
	for l := range strings.Lines(logs.String()) {
		if strings.Contains(l, "raised event invalid") {
			line = l
		}
	}
	if !strings.Contains(line, "level=ERROR") || !strings.Contains(line, "event_id="+id) ||
		!strings.Contains(line, "device="+fixtureSerial) {
		t.Fatalf("log = %s", logs.String())
	}
}

func TestAuth(t *testing.T) {
	h := newServer(t)
	cases := []struct {
		method, path, token string
		want                int
	}{
		{"GET", "/v1/sessions", "", 401},
		{"GET", "/v1/sessions", "wrong-token-xxxxxxxx", 401},
		{"GET", "/v1/sessions", agentToken, 403},
		{"POST", "/v1/agent/events", consoleToken, 401},
		{"POST", "/v1/agent/enroll", consoleToken, 403},
		{"GET", "/v1/enrollments", agentToken, 403},
		{"PUT", "/v1/settings", agentToken, 403},
		{"GET", "/healthz", "", 200},
	}
	for _, c := range cases {
		rec, _ := do(t, h, c.method, c.path, c.token, map[string]any{"events": []any{}})
		if rec.Code != c.want {
			t.Errorf("%s %s token=%q: %d, want %d", c.method, c.path, c.token, rec.Code, c.want)
		}
	}
}

func TestTenantIsolation(t *testing.T) {
	h := newServer(t)
	enrollAgent(t, h, fixtureSerial).post(t, batch(t, "elevation-granted"))
	_, out := do(t, h, "GET", "/v1/sessions", otherConsole, nil)
	if len(out["sessions"].([]any)) != 0 {
		t.Fatalf("other tenant sees %v", out)
	}
	rec, _ := do(t, h, "GET", "/v1/sessions/5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d", otherConsole, nil)
	if rec.Code != 404 {
		t.Fatalf("cross-tenant get: %d", rec.Code)
	}
}

func TestListFiltersAndValidation(t *testing.T) {
	h := newServer(t)
	enrollAgent(t, h, fixtureSerial).post(t, batch(t, "elevation-granted", "admin-out-of-band", "agent-health"))
	_, out := do(t, h, "GET", "/v1/sessions?open=true&user=backdoor", consoleToken, nil)
	if n := len(out["sessions"].([]any)); n != 1 {
		t.Fatalf("filtered = %d", n)
	}
	for _, q := range []string{"since=yesterday", "limit=0", "limit=x"} {
		if rec, _ := do(t, h, "GET", "/v1/sessions?"+q, consoleToken, nil); rec.Code != 400 {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
	_, out = do(t, h, "GET", "/v1/devices", consoleToken, nil)
	devices := out["devices"].([]any)
	if len(devices) != 1 || len(devices[0].(map[string]any)["admin_members"].([]any)) != 2 {
		t.Fatalf("devices = %v", out)
	}
}

func TestRejectsOversizedBatch(t *testing.T) {
	h := newServer(t)
	events := make([]json.RawMessage, api.MaxBatchEvents+1)
	for i := range events {
		events[i] = json.RawMessage(`{}`)
	}
	body, _ := json.Marshal(map[string]any{"events": events})
	rec, _ := enrollAgent(t, h, fixtureSerial).post(t, body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("%d", rec.Code)
	}
}

func TestTokenConfig(t *testing.T) {
	if _, err := auth.Parse("acme=short", ""); err == nil {
		t.Fatal("short token accepted")
	}
	if _, err := auth.Parse("acme="+agentToken, "acme="+agentToken); err == nil {
		t.Fatal("duplicate token accepted")
	}
	if _, err := auth.Parse(" acme=a-valid-long-token-value , ", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Parse("noequalsign-supersecretvalue", ""); err == nil || strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("bad entry error leaks token or passes: %v", err)
	}
}

func TestAgentsCannotSendServerRaisedEvents(t *testing.T) {
	for _, c := range []struct{ fixture, want string }{
		{"agent-silent", "agent.silent is raised only by the server"},
		{"agent-enrollment-pending", "agent.enrollment is raised only by the server"},
		{"agent-admin-group-changed", "agent.admin_group is raised only by the server"},
	} {
		t.Run(c.fixture, func(t *testing.T) {
			h := newServer(t)
			rec, out := enrollAgent(t, h, fixtureSerial).post(t, batch(t, c.fixture))
			rejected, _ := out["rejected"].([]any)
			if rec.Code != 200 || len(rejected) != 1 || rejected[0].(map[string]any)["error"] != c.want {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestSilentAfterHoursIsBounded(t *testing.T) {
	h := newServer(t)
	for _, c := range []struct{ hours, want int }{{0, 200}, {1, 200}, {-1, 400}, {721, 400}, {720, 200}} {
		rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"silent_after_hours": c.hours})
		if rec.Code != c.want {
			t.Errorf("silent_after_hours %d: %d %s", c.hours, rec.Code, rec.Body)
		}
	}
	rec, out := do(t, h, "GET", "/v1/settings", consoleToken, nil)
	if rec.Code != 200 || out["silent_after_hours"] != 720.0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestHistoryDaysIsBounded(t *testing.T) {
	h := newServer(t)
	for _, c := range []struct{ days, want int }{{0, 200}, {-1, 200}, {90, 200}, {3650, 200}, {89, 400}, {3651, 400}, {-2, 400}} {
		rec, out := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"history_days": c.days})
		if rec.Code != c.want {
			t.Errorf("history_days %d: %d %s", c.days, rec.Code, rec.Body)
		}
		if c.want == 400 && out["error"] != "history_days must be 0 for the default, -1 to keep history for good, or between 90 and 3650" {
			t.Errorf("history_days %d: error = %v", c.days, out["error"])
		}
	}
	// The last accepted value stays after the refused ones.
	if rec, out := do(t, h, "GET", "/v1/settings", consoleToken, nil); rec.Code != 200 || out["history_days"] != 3650.0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// A console tab or script that doesn't know the setting must not reset it.
func TestPutSettingsWithoutHistoryKeepsIt(t *testing.T) {
	h := newServer(t)
	if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"history_days": -1}); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for _, body := range []map[string]any{{"silent_after_hours": 48}, {"history_days": nil}} {
		if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, body); rec.Code != 200 {
			t.Fatalf("%v: %d %s", body, rec.Code, rec.Body)
		}
		if _, out := do(t, h, "GET", "/v1/settings", consoleToken, nil); out["history_days"] != -1.0 {
			t.Fatalf("%v: history_days = %v, want -1", body, out["history_days"])
		}
	}
}

// coveredFrom is a store whose SIEMs count as covered from at: a store records coverage by
// its own clock, which this test doesn't set.
type coveredFrom struct {
	store.Store
	at time.Time
}

func (c coveredFrom) SinkCoverage(_ context.Context, sinks []string) (*time.Time, error) {
	if len(sinks) == 0 {
		return nil, nil
	}
	at := c.at
	return &at, nil
}

func TestRetentionReportsThePolicy(t *testing.T) {
	history := func(t *testing.T, h http.Handler) map[string]any {
		t.Helper()
		rec, out := do(t, h, "GET", "/v1/retention", consoleToken, nil)
		if rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		got, _ := out["history"].(map[string]any)
		return got
	}
	tokens, _ := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := serverNow(t)

	t.Run("no SIEM", func(t *testing.T) {
		h := api.New(store.NewMemory(nil), tokens, log, func() time.Time { return now })
		got := history(t, h)
		if got["reason"] != "default_no_siem" || got["kept_for_good"] != true || got["days"] != 0.0 ||
			got["held_before"] != nil || got["waiting_for_backfill"] != true {
			t.Fatalf("history = %v", got)
		}
	})

	t.Run("with a SIEM", func(t *testing.T) {
		st := coveredFrom{store.NewMemory([]string{"splunk"}), now.Add(-time.Hour)}
		h := api.New(st, tokens, log, func() time.Time { return now }, api.WithSinks([]string{"splunk"}))
		got := history(t, h)
		if got["reason"] != "default_siem" || got["kept_for_good"] != false || got["days"] != 365.0 ||
			got["held_before"] != now.Add(-time.Hour).Format(time.RFC3339) {
			t.Fatalf("history = %v", got)
		}
		if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"history_days": 120}); rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		got = history(t, h)
		if got["reason"] != "set" || got["days"] != 120.0 || got["kept_for_good"] != false || got["held_before"] != nil {
			t.Fatalf("history = %v", got)
		}
		if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"history_days": -1}); rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		got = history(t, h)
		if got["reason"] != "kept_for_good" || got["kept_for_good"] != true || got["days"] != 0.0 {
			t.Fatalf("history = %v", got)
		}
	})

	t.Run("backfill done", func(t *testing.T) {
		st := store.NewMemory(nil)
		if _, err := st.BackfillAdminGroups(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		h := api.New(st, tokens, log, func() time.Time { return now })
		if got := history(t, h); got["waiting_for_backfill"] != false {
			t.Fatalf("history = %v", got)
		}
	})

	t.Run("a viewer may ask", func(t *testing.T) {
		if rec, _ := do(t, newServer(t), "GET", "/v1/retention", "", nil); rec.Code != 401 {
			t.Fatalf("no token: %d", rec.Code)
		}
	})
}

// History turns the setting into days, and says why.
func TestSettingsHistory(t *testing.T) {
	for _, c := range []struct {
		days       int
		siem       bool
		want       int
		wantReason string
	}{
		{0, true, 365, "default_siem"},
		{0, false, 0, "default_no_siem"},
		{120, true, 120, "set"},
		{120, false, 120, "set"},
		{-1, true, 0, "kept_for_good"},
		{-1, false, 0, "kept_for_good"},
	} {
		days, reason := store.TenantSettings{HistoryDays: c.days}.History(c.siem)
		if days != c.want || reason != c.wantReason {
			t.Errorf("History(%d, %v) = %d, %q; want %d, %q", c.days, c.siem, days, reason, c.want, c.wantReason)
		}
	}
}

func TestAboutReportsVersionAndOldestAgent(t *testing.T) {
	tokens, _ := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	h := api.New(store.NewMemory(nil), tokens, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now, api.WithVersion("0.1.0"))
	rec, out := do(t, h, "GET", "/v1/about", consoleToken, nil)
	if rec.Code != 200 || out["version"] != "0.1.0" || out["oldest_supported_agent"] != "1.1" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if s, _ := out["tamper_severities"].(map[string]any); s["launch_daemon"] != "High" || s["settings_managed"] != "Medium" {
		t.Fatalf("tamper_severities = %v", out["tamper_severities"])
	}
	if _, out := do(t, newServer(t), "GET", "/v1/about", consoleToken, nil); out["version"] != "dev" {
		t.Fatalf("default version = %v", out["version"])
	}
}

// The console checks GitHub for newer releases only while the server says it may.
func TestAboutReportsUpdateCheck(t *testing.T) {
	if _, out := do(t, newServer(t), "GET", "/v1/about", consoleToken, nil); out["update_check"] != true {
		t.Fatalf("default update_check = %v", out["update_check"])
	}
	tokens, _ := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	for _, on := range []bool{true, false} {
		h := api.New(store.NewMemory(nil), tokens, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now, api.WithUpdateCheck(on))
		if rec, out := do(t, h, "GET", "/v1/about", consoleToken, nil); rec.Code != 200 || out["update_check"] != on {
			t.Fatalf("WithUpdateCheck(%v): %d %s", on, rec.Code, rec.Body)
		}
	}
}

// On Azure Container Apps the console shows how to change the app's image instead of upgrade.sh.
func TestAboutReportsAnAzureContainerApp(t *testing.T) {
	if _, out := do(t, newServer(t), "GET", "/v1/about", consoleToken, nil); out["platform"] != nil || out["app"] != nil {
		t.Fatalf("default platform = %v, app = %v", out["platform"], out["app"])
	}
	tokens, _ := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	h := api.New(store.NewMemory(nil), tokens, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now,
		api.WithAzureContainerApp("altiward"))
	if rec, out := do(t, h, "GET", "/v1/about", consoleToken, nil); rec.Code != 200 ||
		out["platform"] != "azure-container-apps" || out["app"] != "altiward" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestOverviewAlwaysServed(t *testing.T) {
	if rec, _ := do(t, newServer(t), "GET", "/v1/overview", consoleToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("overview = %d %s", rec.Code, rec.Body)
	}
}

// Approving a Mac never depends on how many are already enrolled.
func TestApproveDoesNotDependOnHowManyMacsAreEnrolled(t *testing.T) {
	h := newServer(t)
	for i := 0; i < 26; i++ {
		if a := enrollAgent(t, h, fmt.Sprintf("C02ACTIVE%03d", i)); a.status != "active" {
			t.Fatalf("Mac %d = %s, want active", i, a.status)
		}
	}
	if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"reenrollment_requires_approval": true}); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	pending := enrollAgent(t, h, "C02ACTIVE000") // a reinstalled Mac: a new key, waiting for approval
	if pending.status != "pending" {
		t.Fatalf("re-enrollment = %s, want pending", pending.status)
	}
	rec, out := do(t, h, "POST", "/v1/enrollments/"+pending.deviceID+"/approve", consoleToken, nil)
	if rec.Code != http.StatusOK || out["status"] != "active" {
		t.Fatalf("approve with 26 active: %d %s", rec.Code, rec.Body)
	}
}
