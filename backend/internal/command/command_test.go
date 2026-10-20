package command_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/command"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schema", "commands", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeResultFixture(t *testing.T) {
	r, err := command.DecodeResult(fixture(t, "command-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != command.StatusFailed || len(r.Revoked) != 1 || r.Revoked[0] != "jdoe" {
		t.Fatalf("result = %+v", r)
	}
	if r.Failed[0].User != "contractor" || r.Skipped[0].Reason != command.SkipPermanentAdmin {
		t.Fatalf("result = %+v", r)
	}
	if !r.CompletedAt.Equal(testfixture.Time(t, "2026-10-16T09:20:31.250Z")) {
		t.Fatalf("completed_at = %v", r.CompletedAt)
	}
}

func TestDecodeResultRejectsBadInput(t *testing.T) {
	good := string(fixture(t, "command-result.json"))
	cases := map[string]string{
		"unknown field":  strings.Replace(good, `"error": null`, `"error": null, "extra": 1`, 1),
		"bad status":     strings.Replace(good, `"status": "failed"`, `"status": "done"`, 1),
		"pending status": strings.Replace(good, `"status": "failed"`, `"status": "pending"`, 1),
		"bad reason":     strings.Replace(good, `"permanent_admin"`, `"felt like it"`, 1),
		"no time":        strings.Replace(good, `"completed_at": "2026-10-16T09:20:31.250Z"`, `"completed_at": null`, 1),
	}
	for name, body := range cases {
		if _, err := command.DecodeResult([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAgentViewMatchesFixture(t *testing.T) {
	jdoe, sid := "jdoe", "5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d"
	cmds := []command.Command{
		{CommandID: "8c1d2e3f-4a5b-4c6d-9e7f-0a1b2c3d4e5f", Type: command.TypeRevokeAdmin, User: &jdoe, SessionID: &sid,
			ExpiresAt: testfixture.Time(t, "2026-10-17T09:20:00Z")},
		{CommandID: "9d2e3f4a-5b6c-4d7e-8f90-1a2b3c4d5e6f", Type: command.TypeRevokeAdmin,
			ExpiresAt: testfixture.Time(t, "2026-10-17T09:25:00Z")},
	}
	got, err := json.Marshal(command.AgentList(cmds))
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	_ = json.Unmarshal(got, &a)
	_ = json.Unmarshal(fixture(t, "agent-commands.json"), &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("agent list =\n%s", got)
	}
}

func TestStatus(t *testing.T) {
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	c := command.Command{ExpiresAt: now.Add(time.Hour)}
	if c.Status(now) != command.StatusPending {
		t.Fatalf("new = %s", c.Status(now))
	}
	if c.Status(now.Add(2*time.Hour)) != command.StatusExpired {
		t.Fatalf("late = %s", c.Status(now.Add(2*time.Hour)))
	}
	c.Result = &command.Result{Status: command.StatusSkipped}
	if c.Status(now.Add(2*time.Hour)) != command.StatusSkipped {
		t.Fatal("a result outranks expiry")
	}
}
