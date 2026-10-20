package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

const fixtureSession = "5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d"

func (a *agent) get(t *testing.T, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	return a.send(t, httptest.NewRequest("GET", path, nil), nil)
}

func (a *agent) postTo(t *testing.T, path string, body []byte) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	return a.send(t, httptest.NewRequest("POST", path, bytes.NewReader(body)), body)
}

const completedResult = `{"status":"completed","error":null,"revoked":["jdoe"],"failed":[],"skipped":[],"completed_at":"2026-10-16T12:00:30Z"}`

func TestSessionRevokeRoundTrip(t *testing.T) {
	h := newServer(t)
	mac := enrollAgent(t, h, fixtureSerial)
	mac.post(t, batch(t, "elevation-granted"))

	rec, cmd := do(t, h, "POST", "/v1/sessions/"+fixtureSession+"/revoke", consoleToken, nil)
	if rec.Code != http.StatusCreated || cmd["user"] != "jdoe" || cmd["session_id"] != fixtureSession ||
		cmd["serial"] != fixtureSerial || cmd["status"] != "pending" || cmd["type"] != "revoke_admin" {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	id := cmd["command_id"].(string)

	rec, out := mac.get(t, "/v1/agent/commands")
	list := out["commands"].([]any)
	if rec.Code != 200 || len(list) != 1 || list[0].(map[string]any)["command_id"] != id {
		t.Fatalf("agent poll: %d %s", rec.Code, rec.Body)
	}

	rec, out = mac.postTo(t, "/v1/agent/commands/"+id+"/result", []byte(completedResult))
	if rec.Code != 200 || out["status"] != "completed" {
		t.Fatalf("result: %d %s", rec.Code, rec.Body)
	}
	if _, out := mac.get(t, "/v1/agent/commands"); len(out["commands"].([]any)) != 0 {
		t.Fatalf("still delivered after result: %v", out)
	}
	rec, out = do(t, h, "GET", "/v1/commands/"+id, consoleToken, nil)
	if rec.Code != 200 || out["status"] != "completed" || out["delivered_at"] == nil {
		t.Fatalf("console view: %d %s", rec.Code, rec.Body)
	}
}

func TestSessionRevokeErrors(t *testing.T) {
	h := newServer(t)
	mac := enrollAgent(t, h, fixtureSerial)
	if rec, _ := do(t, h, "POST", "/v1/sessions/"+fixtureSession+"/revoke", consoleToken, nil); rec.Code != 404 {
		t.Fatalf("unknown session: %d", rec.Code)
	}
	mac.post(t, batch(t, "elevation-granted", "elevation-revoked"))
	if rec, _ := do(t, h, "POST", "/v1/sessions/"+fixtureSession+"/revoke", consoleToken, nil); rec.Code != http.StatusConflict {
		t.Fatalf("ended session: %d", rec.Code)
	}
	if rec, _ := do(t, h, "POST", "/v1/sessions/"+fixtureSession+"/revoke", otherConsole, nil); rec.Code != 404 {
		t.Fatalf("other tenant: %d", rec.Code)
	}
}

// permanentGrant is elevation-granted for itadmin, whom agent-health lists as a
// permanent admin on the same Mac.
const permanentSession = "7a2e4c1d-3b5f-4e6a-8c9d-0f1e2d3c4b5a"

func permanentGrant(t *testing.T) json.RawMessage {
	t.Helper()
	var e map[string]any
	if err := json.Unmarshal(testfixture.Raw(t, "elevation-granted"), &e); err != nil {
		t.Fatal(err)
	}
	e["event_id"], e["session_id"] = "9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d", permanentSession
	e["user"] = map[string]any{"local_name": "itadmin", "upn": nil}
	raw, _ := json.Marshal(e)
	return raw
}

func TestSessionsMarkPermanentAdmins(t *testing.T) {
	h := newServer(t)
	body, _ := json.Marshal(map[string]any{"events": []json.RawMessage{
		testfixture.Raw(t, "agent-health"), testfixture.Raw(t, "elevation-granted"), permanentGrant(t),
	}})
	enrollAgent(t, h, fixtureSerial).post(t, body)

	_, out := do(t, h, "GET", "/v1/sessions", consoleToken, nil)
	permanent := map[string]any{}
	for _, s := range out["sessions"].([]any) {
		v := s.(map[string]any)
		permanent[v["local_user"].(string)] = v["permanent_admin"]
	}
	if permanent["itadmin"] != true || permanent["jdoe"] != false {
		t.Fatalf("permanent_admin by user = %v", permanent)
	}
	_, out = do(t, h, "GET", "/v1/sessions/"+permanentSession, consoleToken, nil)
	if out["session"].(map[string]any)["permanent_admin"] != true {
		t.Fatalf("session detail = %v", out["session"])
	}

	// The agent would only skip it, so the server doesn't queue it.
	rec, out := do(t, h, "POST", "/v1/sessions/"+permanentSession+"/revoke", consoleToken, nil)
	if rec.Code != http.StatusConflict || out["error"] != "itadmin is a permanent admin on "+fixtureSerial+", so Altiward doesn’t remove their rights" {
		t.Fatalf("revoke permanent admin: %d %s", rec.Code, rec.Body)
	}
	if _, out := do(t, h, "GET", "/v1/commands", consoleToken, nil); len(out["commands"].([]any)) != 0 {
		t.Fatalf("queued anyway: %v", out)
	}
}

func TestDeviceRevoke(t *testing.T) {
	h := newServer(t)
	enrollAgent(t, h, fixtureSerial).post(t, batch(t, "agent-health"))

	rec, cmd := do(t, h, "POST", "/v1/devices/"+fixtureSerial+"/revoke", consoleToken, nil)
	if rec.Code != http.StatusCreated || cmd["user"] != nil || cmd["session_id"] != nil {
		t.Fatalf("whole device: %d %s", rec.Code, rec.Body)
	}
	rec, cmd = do(t, h, "POST", "/v1/devices/"+fixtureSerial+"/revoke", consoleToken, map[string]any{"user": "jdoe"})
	if rec.Code != http.StatusCreated || cmd["user"] != "jdoe" {
		t.Fatalf("one user: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := do(t, h, "POST", "/v1/devices/NO-SUCH-MAC/revoke", consoleToken, nil); rec.Code != 404 {
		t.Fatalf("unknown device: %d", rec.Code)
	}
	if rec, _ := do(t, h, "POST", "/v1/devices/"+fixtureSerial+"/revoke", consoleToken, map[string]any{"user": ""}); rec.Code != 400 {
		t.Fatalf("empty user: %d", rec.Code)
	}

	rec, out := do(t, h, "GET", "/v1/commands?serial="+fixtureSerial+"&status=pending", consoleToken, nil)
	if rec.Code != 200 || len(out["commands"].([]any)) != 2 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := do(t, h, "GET", "/v1/commands?status=bogus", consoleToken, nil); rec.Code != 400 {
		t.Fatalf("bad status: %d", rec.Code)
	}
}

func TestMacsOnlySeeTheirOwnCommands(t *testing.T) {
	h := newServer(t)
	mac := enrollAgent(t, h, fixtureSerial)
	mac.post(t, batch(t, "agent-health"))
	other := enrollAgent(t, h, "ANOTHER-MAC")
	_, cmd := do(t, h, "POST", "/v1/devices/"+fixtureSerial+"/revoke", consoleToken, nil)
	id := cmd["command_id"].(string)

	if _, out := other.get(t, "/v1/agent/commands"); len(out["commands"].([]any)) != 0 {
		t.Fatalf("other Mac sees %v", out)
	}
	if rec, _ := other.postTo(t, "/v1/agent/commands/"+id+"/result", []byte(completedResult)); rec.Code != 404 {
		t.Fatalf("other Mac reported a result: %d", rec.Code)
	}
	if rec, _ := mac.postTo(t, "/v1/agent/commands/"+id+"/result", []byte(`{"status":"done"}`)); rec.Code != 400 {
		t.Fatalf("bad result: %d", rec.Code)
	}
	if rec, out := do(t, h, "GET", "/v1/agent/commands", agentToken, nil); rec.Code != 401 {
		t.Fatalf("bearer poll: %d %v", rec.Code, out)
	}
	if rec, _ := do(t, h, "POST", "/v1/devices/"+fixtureSerial+"/revoke", agentToken, nil); rec.Code != 403 {
		t.Fatalf("enrollment token issued a revoke: %d", rec.Code)
	}
}

// getAsync sends a signed GET from the Mac and delivers the response on the channel, for a
// request the server may hold.
func (a *agent) getAsync(t *testing.T, path string) <-chan map[string]any {
	t.Helper()
	out := make(chan map[string]any, 1)
	req := httptest.NewRequest("GET", path, nil)
	go func() {
		rec, body := a.send(t, req, nil)
		if rec.Code != http.StatusOK {
			body = map[string]any{"status_code": float64(rec.Code)}
		}
		out <- body
	}()
	return out
}

func commandCount(t *testing.T, out map[string]any) int {
	t.Helper()
	list, ok := out["commands"].([]any)
	if !ok {
		t.Fatalf("not a command list: %v", out)
	}
	return len(list)
}

func TestAgentCommandsWaitForTheNextCommand(t *testing.T) {
	h := newServer(t)
	mac := enrollAgent(t, h, fixtureSerial)
	mac.post(t, batch(t, "agent-health"))

	held := mac.getAsync(t, "/v1/agent/commands?wait=30")
	select {
	case out := <-held:
		t.Fatalf("answered with nothing queued: %v", out)
	case <-time.After(200 * time.Millisecond):
	}
	if rec, _ := do(t, h, "POST", "/v1/devices/"+fixtureSerial+"/revoke", consoleToken, nil); rec.Code != http.StatusCreated {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	select {
	case out := <-held:
		if commandCount(t, out) != 1 {
			t.Fatalf("held request answered %v", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("held request not answered when the command was queued")
	}
}

func TestAgentCommandsWaitEndsEmpty(t *testing.T) {
	h := newServer(t)
	mac := enrollAgent(t, h, fixtureSerial)
	start := time.Now()
	out := <-mac.getAsync(t, "/v1/agent/commands?wait=1")
	if commandCount(t, out) != 0 || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("after %v: %v", time.Since(start), out)
	}
	for _, bad := range []string{"abc", "-1", "51", "1.5"} {
		if out := <-mac.getAsync(t, "/v1/agent/commands?wait="+bad); out["status_code"] != 400.0 {
			t.Fatalf("wait=%s: %v", bad, out)
		}
	}
}

func TestAgentCommandsWaitEndsAtShutdown(t *testing.T) {
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	if err != nil {
		t.Fatal(err)
	}
	now := serverNow(t)
	stopping := make(chan struct{})
	h := api.New(store.NewMemory(nil), tokens, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() time.Time { return now }, api.WithShutdown(stopping))
	held := enrollAgent(t, h, fixtureSerial).getAsync(t, "/v1/agent/commands?wait=30")
	time.Sleep(100 * time.Millisecond)
	close(stopping)
	select {
	case out := <-held:
		if commandCount(t, out) != 0 {
			t.Fatalf("answered %v", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("held request not released at shutdown")
	}
}
