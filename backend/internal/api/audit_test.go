package api_test

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"testing"
)

func TestConsoleActionsAreAudited(t *testing.T) {
	h := newServer(t)
	if rec, _ := enrollAgent(t, h, fixtureSerial).post(t, batch(t, "elevation-granted")); rec.Code != 200 {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"silent_after_hours": 24}); rec.Code != 200 {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	rec, cmd := do(t, h, "POST", "/v1/devices/"+fixtureSerial+"/revoke", consoleToken, map[string]any{"user": "jdoe"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}

	rec, out := do(t, h, "GET", "/v1/audit", consoleToken, nil)
	entries, _ := out["entries"].([]any)
	// The two actions, and the sign-in the token's first request recorded.
	if rec.Code != 200 || len(entries) != 3 {
		t.Fatalf("audit: %d %s", rec.Code, rec.Body)
	}
	actor := fmt.Sprintf("token:%x", sha256.Sum256([]byte(consoleToken)))[:len("token:")+8]
	// The test clock is fixed, so the entries share a time; find each by its action.
	byAction := map[string]map[string]any{}
	for _, e := range entries {
		m := e.(map[string]any)
		byAction[m["action"].(string)] = m
	}
	revoke, settings, signIn := byAction["revoke_device"], byAction["change_settings"], byAction["sign_in"]
	if signIn["actor"] != actor {
		t.Fatalf("sign-in entry = %v", signIn)
	}
	detail := revoke["detail"].(map[string]any)
	if revoke["action"] != "revoke_device" || revoke["target"] != fixtureSerial || revoke["actor"] != actor ||
		detail["command_id"] != cmd["command_id"] || detail["user"] != "jdoe" {
		t.Fatalf("revoke entry = %v", revoke)
	}
	if cmd["issued_by"] != actor {
		t.Fatalf("command issued_by = %v", cmd["issued_by"])
	}
	sd := settings["detail"].(map[string]any)
	if settings["action"] != "change_settings" || sd["settings"].(map[string]any)["silent_after_hours"] != 24.0 ||
		sd["previous"].(map[string]any)["silent_after_hours"] != 0.0 {
		t.Fatalf("settings entry = %v", settings)
	}

	// Another tenant sees only its own token's sign-in, and a refused change records nothing.
	if _, out := do(t, h, "GET", "/v1/audit", otherConsole, nil); len(out["entries"].([]any)) != 1 ||
		out["entries"].([]any)[0].(map[string]any)["tenant_id"] != "other" {
		t.Fatalf("other tenant sees %v", out)
	}
	if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"silent_after_hours": 9999}); rec.Code != 400 {
		t.Fatalf("bad settings: %d", rec.Code)
	}
	if _, out := do(t, h, "GET", "/v1/audit?limit=10", consoleToken, nil); len(out["entries"].([]any)) != 3 {
		t.Fatalf("refused change was audited: %v", out)
	}
}

func TestAuditQueryValidation(t *testing.T) {
	h := newServer(t)
	for _, q := range []string{"?limit=0", "?limit=x", "?before=yesterday", "?before_seq=3", "?before=2026-10-16T12:00:00Z&before_seq=x"} {
		if rec, _ := do(t, h, "GET", "/v1/audit"+q, consoleToken, nil); rec.Code != 400 {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
	if rec, _ := do(t, h, "GET", "/v1/audit", agentToken, nil); rec.Code != 403 {
		t.Errorf("agent token: %d", rec.Code)
	}
}
