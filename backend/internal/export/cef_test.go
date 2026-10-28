package export_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/Altiward/altiward/backend/internal/export"
	"github.com/Altiward/altiward/backend/internal/ocsf"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
	"github.com/Altiward/altiward/integrations/syslog"
)

func record(t *testing.T, name string) export.Record {
	t.Helper()
	e := testfixture.Event(t, name)
	se := store.StoredEvent{Event: e, ReceivedAt: e.Timestamp}
	records := ocsf.Map(se, "acme")
	if len(records) == 0 {
		t.Fatalf("%s is not exported", name)
	}
	return export.Record{TenantID: "acme", Event: se, OCSF: records[0]}
}

func TestCEFForAGrant(t *testing.T) {
	r := record(t, "elevation-granted")
	got := export.CEF(r)
	head := "CEF:0|Altiward|Altiward|" + r.Event.Device.AgentVersion +
		"|elevation.granted|User Access Management: Assign Privileges|1|"
	if !strings.HasPrefix(got, head) {
		t.Fatalf("header:\n got %q\nwant %q", got, head)
	}
	for _, want := range []string{
		"externalId=" + r.Event.EventID, "act=Assign Privileges", "outcome=Success", "dvchost=C02XK0AAJGH5",
		"duser=jane.doe@example.com", "cs1Label=tenant cs1=acme", "cs2Label=sessionId cs2=" + *r.Event.SessionID,
		"cs3Label=reason cs3=Installing Xcode command line tools", "cs4Label=source cs4=privileges",
		"cs6Label=eventType cs6=elevation.granted",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Fatal("CEF line contains a line break")
	}
}

func TestCEFForAFindingKeysOnTheAnalytic(t *testing.T) {
	got := export.CEF(record(t, "agent-tamper"))
	if !strings.Contains(got, "|altiward.tamper.settings_managed|Altiward settings set outside MDM|5|") {
		t.Fatalf("header: %s", got)
	}
	if !strings.Contains(got, "cs5Label=findingUid cs5=8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D/settings_managed") {
		t.Fatalf("finding uid: %s", got)
	}
}

func TestCEFForAnEnrollment(t *testing.T) {
	got := export.CEF(record(t, "agent-enrollment-pending"))
	if !strings.Contains(got, "|agent.enrollment|API Activity: Create|5|") {
		t.Fatalf("header: %s", got)
	}
	for _, want := range []string{
		"cat=API Activity", "act=Create", "dvchost=C02XK0AAJGH5",
		"suser=token:1a2b3c4d", "cs5Label=target cs5=5d2c8e1a-7b4f-4a93-8c6d-0f1e2a3b4c5d",
		"msg=C02XK0AAJGH5 enrolled again with a new key, waiting for approval", "cs6Label=eventType cs6=agent.enrollment",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestCEFSeverityForRotation(t *testing.T) {
	for _, c := range []struct{ fixture, header string }{
		{"agent-enrollment-rotated", "|agent.enrollment|API Activity: Update|1|"},
		{"agent-enrollment-rotated-key-used", "|agent.enrollment|API Activity: Stale key used|8|"},
	} {
		got := export.CEF(record(t, c.fixture))
		if !strings.Contains(got, c.header) {
			t.Errorf("%s header: %s", c.fixture, got)
		}
		if !strings.Contains(got, "suser=C02XK0AAJGH5") {
			t.Errorf("%s actor: %s", c.fixture, got)
		}
	}
}

// A permanent admin's use on someone else's session: duser is the admin account, suser the
// OCSF actor, whose session it was.
func TestCEFForPermanentAdminUseOnAnotherSession(t *testing.T) {
	got := export.CEF(record(t, "admin-permanent-use-prompt"))
	for _, want := range []string{"duser=breakglass", "suser=alex"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

// Each person of an admin group event is the destination user of their own record; the
// Mac's record has none.
func TestCEFNamesAdminGroupPeople(t *testing.T) {
	e := testfixture.Event(t, "agent-admin-group-changed")
	se := store.StoredEvent{Event: e, ReceivedAt: e.Timestamp}
	records := ocsf.Map(se, "acme")
	if len(records) != 3 {
		t.Fatalf("%d records", len(records))
	}
	for i, want := range []string{"duser=jdoe", "duser=asmith"} {
		got := export.CEF(export.Record{TenantID: "acme", Event: se, OCSF: records[i]})
		if !strings.Contains(got, want) || !strings.Contains(got, "cat=Group Management") {
			t.Errorf("record %d: missing %q in\n%s", i, want, got)
		}
	}
	if got := export.CEF(export.Record{TenantID: "acme", Event: se, OCSF: records[2]}); strings.Contains(got, "duser=") {
		t.Errorf("the Mac's record names a user:\n%s", got)
	}
}

func TestCEFForAConsoleAction(t *testing.T) {
	a := store.AuditEntry{ID: "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", TenantID: "acme", Actor: "token:3f2a9c1b",
		At: testfixture.Time(t, "2026-10-17T09:00:00Z"), Action: store.AuditRevokeSession, Target: "s1",
		Detail: map[string]any{"serial": "C02XK0AAJGH5", "user": "jdoe", "session_id": "s1"}}
	got := export.CEF(export.Record{TenantID: "acme", Audit: &a, OCSF: ocsf.MapAudit(a)})
	if !strings.HasPrefix(got, "CEF:0|Altiward|Altiward|0|console.revoke_session|API Activity: Create|1|") {
		t.Fatalf("header: %s", got)
	}
	for _, want := range []string{
		"externalId=" + a.ID, "act=revoke_session", "suser=token:3f2a9c1b", "dvchost=C02XK0AAJGH5", "duser=jdoe",
		"cs1Label=tenant cs1=acme", "cs2Label=sessionId cs2=s1", "cs5Label=target cs5=s1",
		"cs6Label=eventType cs6=console.revoke_session",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestCEFEscapes(t *testing.T) {
	r := record(t, "elevation-granted")
	reason := `a=b \ c|d` + "\nnext"
	r.Event.Elevation.Reason = &reason
	r.OCSF["type_name"] = "x|y"
	got := export.CEF(r)
	if !strings.Contains(got, `|x\|y|`) {
		t.Fatalf("header pipe not escaped: %s", got)
	}
	if !strings.Contains(got, `cs3=a\=b \\ c|d\nnext`) {
		t.Fatalf("value not escaped: %s", got)
	}
}

func TestSyslogSinkSendsEachRecord(t *testing.T) {
	for _, format := range []export.SyslogFormat{export.FormatCEF, export.FormatJSON} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		got := make(chan string, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				got <- ""
				return
			}
			b, _ := io.ReadAll(conn)
			conn.Close()
			got <- string(b)
		}()
		sink := &export.SyslogSink{Client: &syslog.Client{Addr: ln.Addr().String(), Framing: syslog.Newline}, Format: format}
		records := []export.Record{record(t, "elevation-granted"), record(t, "admin-out-of-band")}
		if err := sink.Send(context.Background(), records); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(<-got, "\n"), "\n")
		ln.Close()
		if len(lines) != 2 {
			t.Fatalf("%s: lines = %q", format, lines)
		}
		// authpriv (10) × 8 + info (6); the out-of-band finding is High, so err (3).
		if !strings.HasPrefix(lines[0], "<86>1 ") || !strings.HasPrefix(lines[1], "<83>1 ") ||
			!strings.Contains(lines[0], " altiward altiward - elevation.granted - ") {
			t.Fatalf("%s: headers = %q", format, lines)
		}
		body := lines[1][strings.Index(lines[1], " - admin.out_of_band - ")+len(" - admin.out_of_band - "):]
		switch format {
		case export.FormatCEF:
			if !strings.HasPrefix(body, "CEF:0|Altiward|Altiward|") {
				t.Fatalf("cef body = %q", body)
			}
		case export.FormatJSON:
			var o map[string]any
			if err := json.Unmarshal([]byte(body), &o); err != nil || o["class_uid"] != 2004.0 {
				t.Fatalf("json body = %q (%v)", body, err)
			}
		}
	}
}
