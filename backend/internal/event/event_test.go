package event_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func TestContractFixturesDecodeAndValidate(t *testing.T) {
	for _, name := range testfixture.Names {
		t.Run(name, func(t *testing.T) {
			e := testfixture.Event(t, name)
			if e.Device.Serial != "C02XK0AAJGH5" {
				t.Fatalf("serial = %q", e.Device.Serial)
			}
		})
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	raw := bytes.Replace(testfixture.Raw(t, "elevation-granted"), []byte(`"delayed"`), []byte(`"surprise": 1, "delayed"`), 1)
	if _, err := event.Decode(raw); err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Fatalf("err = %v", err)
	}
}

func TestPeekID(t *testing.T) {
	if got := event.PeekID([]byte(`{"event_id":"abc","type":42}`)); got != "abc" {
		t.Fatalf("got %q", got)
	}
	if got := event.PeekID([]byte(`not json`)); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestValidate(t *testing.T) {
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	cases := []struct {
		name    string
		fixture string
		mutate  func(e *event.Event)
		wantErr string
	}{
		{"valid", "elevation-granted", func(e *event.Event) {}, ""},
		{"schema version", "elevation-granted", func(e *event.Event) { e.SchemaVersion = 2 }, "schema_version"},
		{"upper-case id", "elevation-granted", func(e *event.Event) { e.EventID = strings.ToUpper(e.EventID) }, "event_id"},
		{"unknown type", "elevation-granted", func(e *event.Event) { e.Type = "elevation.maybe" }, "unknown type"},
		{"future", "elevation-granted", func(e *event.Event) { e.Timestamp = now.Add(25 * time.Hour) }, "future"},
		{"no serial", "elevation-granted", func(e *event.Event) { e.Device.Serial = "" }, "device.serial"},
		{"grant without session", "elevation-granted", func(e *event.Event) { e.SessionID = nil }, "requires session_id"},
		{"grant without user", "elevation-granted", func(e *event.Event) { e.User = nil }, "requires session_id, user"},
		{"overdue without session", "elevation-overdue", func(e *event.Event) { e.SessionID = nil }, "requires session_id"},
		{"overdue without user", "elevation-overdue", func(e *event.Event) { e.User = nil }, "requires session_id, user"},
		{"out of band removed", "admin-out-of-band-removed", func(e *event.Event) {}, ""},
		{"out of band removed without session", "admin-out-of-band-removed", func(e *event.Event) { e.SessionID = nil }, "requires session_id, user and elevation"},
		{"bad source", "elevation-granted", func(e *event.Event) { e.Elevation.Source = "sudo" }, "elevation.source"},
		{"long reason", "elevation-granted", func(e *event.Event) {
			e.Elevation.Reason = testfixture.Ptr(strings.Repeat("x", event.MaxReasonLength+1))
		}, "reason too long"},
		{"huge detail", "agent-health", func(e *event.Event) { e.Detail["blob"] = strings.Repeat("x", event.MaxDetailBytes) }, "64 KiB"},
		{"health needs no session", "agent-health", func(e *event.Event) {}, ""},
		{"tamper", "agent-tamper", func(e *event.Event) {}, ""},
		{"tamper without check", "agent-tamper", func(e *event.Event) { delete(e.Detail, "check") }, "detail.check"},
		{"silent", "agent-silent", func(e *event.Event) {}, ""},
		{"resumed", "agent-silent", func(e *event.Event) { e.Detail["state"] = "resumed" }, ""},
		{"silent without state", "agent-silent", func(e *event.Event) { delete(e.Detail, "state") }, "detail.state"},
		{"silent with user", "agent-silent", func(e *event.Event) { e.User = &event.User{LocalName: "jdoe"} }, "no session_id or user"},
		{"enrollment pending", "agent-enrollment-pending", func(e *event.Event) {}, ""},
		{"enrollment enrolled", "agent-enrollment-enrolled", func(e *event.Event) {}, ""},
		{"enrollment replaced", "agent-enrollment-enrolled", func(e *event.Event) { e.Detail["state"] = "replaced" }, ""},
		{"enrollment with a bogus state", "agent-enrollment-pending", func(e *event.Event) { e.Detail["state"] = "bogus" },
			"agent.enrollment requires detail.state (enrolled, pending or replaced) and detail.device_id"},
		{"enrollment without a state", "agent-enrollment-pending", func(e *event.Event) { delete(e.Detail, "state") },
			"agent.enrollment requires detail.state (enrolled, pending or replaced) and detail.device_id"},
		{"enrollment without a device id", "agent-enrollment-pending", func(e *event.Event) { delete(e.Detail, "device_id") },
			"agent.enrollment requires detail.state (enrolled, pending or replaced) and detail.device_id"},
		{"enrollment with an empty device id", "agent-enrollment-pending", func(e *event.Event) { e.Detail["device_id"] = "" },
			"agent.enrollment requires detail.state (enrolled, pending or replaced) and detail.device_id"},
		{"nil detail defaults", "agent-health", func(e *event.Event) { e.Detail = nil }, ""},
		{"persistence", "persistence-detected", func(e *event.Event) {}, ""},
		{"persistence without session", "persistence-detected", func(e *event.Event) { e.SessionID = nil }, "requires session_id"},
		{"persistence without user", "persistence-detected", func(e *event.Event) { e.User = nil }, "requires session_id, user"},
		{"persistence without findings", "persistence-detected", func(e *event.Event) { e.Detail["findings"] = []any{} }, "detail.findings"},
		{"persistence findings not a list", "persistence-detected", func(e *event.Event) { e.Detail["findings"] = "x" }, "detail.findings"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := testfixture.Event(t, tc.fixture)
			tc.mutate(&e)
			err := e.Validate(now)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			case err == nil && e.Detail == nil:
				t.Fatal("detail left nil")
			}
		})
	}
}

func TestServerRaised(t *testing.T) {
	if !event.AgentSilent.IsServerRaised() || !event.AgentEnrollment.IsServerRaised() || event.AgentTamper.IsServerRaised() {
		t.Fatal("only agent.silent and agent.enrollment are raised by the server")
	}
}

// The namespace and the algorithm must not change: agent.silent event IDs come from them.
// The vector is the version 5 UUID of the name.
func TestRaisedID(t *testing.T) {
	const name = "t1/C02XK0AAJGH5/silent/2026-10-16T10:05:00Z"
	if got, want := event.RaisedID(name), "3d87c4bd-d502-50eb-8f02-c12fdd45687f"; got != want {
		t.Fatalf("RaisedID(%q) = %s, want %s", name, got, want)
	}
	if event.RaisedID(name) == event.RaisedID(name+"x") {
		t.Fatal("two names share an ID")
	}
}

func TestValidatePermanentUse(t *testing.T) {
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	cases := []struct {
		name    string
		fixture string
		mutate  func(e *event.Event)
		wantErr string
	}{
		{"started", "admin-permanent-use-started", func(e *event.Event) {}, ""},
		{"ended", "admin-permanent-use-ended", func(e *event.Event) {}, ""},
		{"prompt", "admin-permanent-use-prompt", func(e *event.Event) {}, ""},
		{"session id", "admin-permanent-use-started", func(e *event.Event) {
			e.SessionID = testfixture.Ptr("7e3d4c9b-0a6f-4c8d-be5f-4a3b2c1d0e9f")
		}, "no session_id"},
		{"elevation", "admin-permanent-use-started", func(e *event.Event) {
			e.Elevation = &event.Elevation{Source: event.SourceOutOfBand}
		}, "no session_id"},
		{"no user", "admin-permanent-use-started", func(e *event.Event) { e.User = nil }, "requires user"},
		{"empty use id", "admin-permanent-use-started", func(e *event.Event) { e.Detail["use_id"] = "" }, "detail.use_id"},
		{"no use id", "admin-permanent-use-started", func(e *event.Event) { delete(e.Detail, "use_id") }, "detail.use_id"},
		{"bad state", "admin-permanent-use-started", func(e *event.Event) { e.Detail["state"] = "paused" }, "detail.state"},
		{"single state", "admin-permanent-use-started", func(e *event.Event) { e.Detail["state"] = event.UseStateSingle }, ""},
		{"ended state", "admin-permanent-use-started", func(e *event.Event) { e.Detail["state"] = event.UseStateEnded }, ""},
		{"started state", "admin-permanent-use-prompt", func(e *event.Event) { e.Detail["state"] = event.UseStateStarted }, ""},
		{"later method", "admin-permanent-use-started", func(e *event.Event) { e.Detail["method"] = "endpoint_thing" }, ""},
		{"empty method", "admin-permanent-use-started", func(e *event.Event) { e.Detail["method"] = "" }, "detail.method"},
		{"no method", "admin-permanent-use-started", func(e *event.Event) { delete(e.Detail, "method") }, "detail.method"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := testfixture.Event(t, tc.fixture)
			tc.mutate(&e)
			err := e.Validate(now)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
	if event.AdminPermanentUse.IsSessionEvent() {
		t.Fatal("admin.permanent_use is not a session event")
	}
}
