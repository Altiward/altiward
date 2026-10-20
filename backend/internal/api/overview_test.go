package api_test

import (
	"net/http"
	"testing"
)

func TestOverviewSumsUpSessionsDevicesAndSIEMs(t *testing.T) {
	h := newServerWithSinks(t, "sentinel")
	if rec, _ := enrollAgent(t, h, fixtureSerial).post(t,
		batch(t, "elevation-granted", "elevation-revoked", "admin-out-of-band", "agent-health")); rec.Code != 200 {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	rec, out := do(t, h, "GET", "/v1/overview", consoleToken, nil)
	if rec.Code != 200 || out["days"] != 30.0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	now, period, health := out["now"].(map[string]any), out["period"].(map[string]any), out["health"].(map[string]any)
	if now["without_grant"] != 1.0 || now["privileges"] != 0.0 {
		t.Fatalf("now = %v", now)
	}
	if period["elevations"] != 2.0 || period["without_grant"] != 1.0 || len(period["buckets"].([]any)) != 30 {
		t.Fatalf("period = %v", period)
	}
	sinks := health["sinks"].([]any)
	if health["macs"] != 1.0 || len(sinks) != 1 || sinks[0].(map[string]any)["sink"] != "sentinel" ||
		sinks[0].(map[string]any)["state"] != "delivering" {
		t.Fatalf("health = %v", health)
	}

	if _, out := do(t, h, "GET", "/v1/overview?days=90", consoleToken, nil); out["period"].(map[string]any)["bucket_days"] != 7.0 {
		t.Fatalf("90 days = %v", out["period"])
	}
	if rec, _ := do(t, h, "GET", "/v1/overview?days=31", consoleToken, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("days=31: %d", rec.Code)
	}
	// Another tenant sees only its own.
	if _, out := do(t, h, "GET", "/v1/overview", otherConsole, nil); out["period"].(map[string]any)["elevations"] != 0.0 {
		t.Fatalf("other tenant = %v", out["period"])
	}
	if rec, _ := do(t, h, "GET", "/v1/overview", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("signed out: %d", rec.Code)
	}
}
