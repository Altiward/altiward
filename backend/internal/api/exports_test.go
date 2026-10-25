package api_test

import (
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
)

// newServerWithSinks is newServer with the given SIEM sinks configured.
func newServerWithSinks(t *testing.T, sinks ...string) http.Handler {
	t.Helper()
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken+",other="+otherConsole)
	if err != nil {
		t.Fatal(err)
	}
	now := serverNow(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.New(store.NewMemory(sinks), tokens, log, func() time.Time { return now }, api.WithSinks(sinks))
}

func sinkStatus(t *testing.T, h http.Handler, token string) map[string]map[string]any {
	t.Helper()
	rec, out := do(t, h, "GET", "/v1/exports", token, nil)
	if rec.Code != 200 {
		t.Fatalf("exports: %d %s", rec.Code, rec.Body)
	}
	bySink := map[string]map[string]any{}
	for _, s := range out["sinks"].([]any) {
		m := s.(map[string]any)
		bySink[m["sink"].(string)] = m
	}
	return bySink
}

func TestExportStatusListsEveryConfiguredSink(t *testing.T) {
	h := newServerWithSinks(t, "splunk", "sentinel")
	got := sinkStatus(t, h, consoleToken)
	if len(got) != 2 || got["splunk"]["pending"] != 0.0 || got["sentinel"]["failing"] != 0.0 {
		t.Fatalf("status with nothing queued = %v", got)
	}
	a := enrollAgent(t, h, fixtureSerial)
	// The enrolment is reported to the SIEM like any event.
	if got := sinkStatus(t, h, consoleToken); got["sentinel"]["pending"] != 1.0 || got["sentinel"]["oldest_queued_at"] == nil {
		t.Fatalf("status after an enrolment = %v", got)
	}
	if rec, _ := a.post(t, batch(t, "elevation-granted")); rec.Code != 200 {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	if got := sinkStatus(t, h, consoleToken); got["sentinel"]["pending"] != 2.0 {
		t.Fatalf("status after an event = %v", got)
	}
	// Another tenant's queue is its own.
	if got := sinkStatus(t, h, otherConsole); got["sentinel"]["pending"] != 0.0 {
		t.Fatalf("other tenant sees %v", got)
	}
}

func TestExportStatusWithoutSinks(t *testing.T) {
	h := newServer(t)
	if rec, out := do(t, h, "GET", "/v1/exports", consoleToken, nil); rec.Code != 200 || len(out["sinks"].([]any)) != 0 {
		t.Fatalf("exports: %d %v", rec.Code, out)
	}
	if rec, _ := do(t, h, "POST", "/v1/exports/test", consoleToken, nil); rec.Code != http.StatusConflict {
		t.Fatalf("test without a SIEM: %d", rec.Code)
	}
}

func TestSendTestEventIsAnAuditedConsoleAction(t *testing.T) {
	h := newServerWithSinks(t, "sentinel")
	rec, out := do(t, h, "POST", "/v1/exports/test", consoleToken, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("test: %d %s", rec.Code, rec.Body)
	}
	if sinks, _ := out["queued_for"].([]any); len(sinks) != 1 || sinks[0] != "sentinel" {
		t.Fatalf("test response = %v", out)
	}
	if got := sinkStatus(t, h, consoleToken); got["sentinel"]["pending"] != 1.0 {
		t.Fatalf("status after a test = %v", got)
	}
	_, audit := do(t, h, "GET", "/v1/audit", consoleToken, nil)
	entries := audit["entries"].([]any)
	if len(entries) != 1 || entries[0].(map[string]any)["action"] != "test_export" {
		t.Fatalf("audit = %v", audit)
	}
}

func TestRetryNow(t *testing.T) {
	h := newServerWithSinks(t, "sentinel")
	rec, out := do(t, h, "POST", "/v1/exports/sentinel/retry", consoleToken, nil)
	if rec.Code != 200 || out["retried"] != 0.0 {
		t.Fatalf("retry with nothing failing: %d %v", rec.Code, out)
	}
	_, audit := do(t, h, "GET", "/v1/audit", consoleToken, nil)
	if e := audit["entries"].([]any); len(e) != 1 || e[0].(map[string]any)["target"] != "sentinel" {
		t.Fatalf("audit = %v", audit)
	}
	if rec, _ := do(t, h, "POST", "/v1/exports/splunk/retry", consoleToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("retry of a sink that isn't configured: %d", rec.Code)
	}
}
