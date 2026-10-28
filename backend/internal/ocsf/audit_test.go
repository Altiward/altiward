package ocsf_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/ocsf"
	"github.com/Altiward/altiward/backend/internal/store"
)

func auditJSON(t *testing.T, a store.AuditEntry) map[string]any {
	t.Helper()
	b, err := json.Marshal(ocsf.MapAudit(a))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func auditEntry(action, target string, detail map[string]any) store.AuditEntry {
	return store.AuditEntry{
		ID: "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", TenantID: "acme", Actor: "token:3f2a9c1b",
		At: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC), Action: action, Target: target, Detail: detail, Seq: 7,
	}
}

func TestConsoleRevokeIsAnAPIActivity(t *testing.T) {
	r := auditJSON(t, auditEntry(store.AuditRevokeDevice, "C02XK0AAJGH5",
		map[string]any{"serial": "C02XK0AAJGH5", "user": "jdoe", "command_id": "c1"}))
	for path, want := range map[string]any{
		"class_uid": 6003.0, "category_uid": 6.0, "activity_id": 1.0, "type_uid": 600301.0, "severity_id": 1.0,
		"status": "Success", "metadata.uid": "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", "metadata.tenant_uid": "acme",
		"metadata.logged_time": 1792227600000.0, "time": 1792227600000.0, "actor.user.name": "token:3f2a9c1b",
		"api.operation": "revoke_device", "unmapped.altiward.event_type": "console.revoke_device",
		"message": "token:3f2a9c1b revoked admin rights for jdoe on C02XK0AAJGH5 from the Altiward console",
	} {
		if got := get(r, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	res := r["resources"].([]any)[0].(map[string]any)
	if res["uid"] != "C02XK0AAJGH5" || res["type"] != "Mac" || res["name"] != "C02XK0AAJGH5" {
		t.Errorf("resources = %v", res)
	}
}

func TestConsoleRevokeOfEveryoneSaysSo(t *testing.T) {
	r := auditJSON(t, auditEntry(store.AuditRevokeDevice, "C02XK0AAJGH5", map[string]any{"serial": "C02XK0AAJGH5"}))
	if r["message"] != "token:3f2a9c1b revoked admin rights for everyone but permanent admins on C02XK0AAJGH5 from the Altiward console" {
		t.Errorf("message = %v", r["message"])
	}
}

func TestSettingsChangeListsWhatChanged(t *testing.T) {
	r := auditJSON(t, auditEntry(store.AuditChangeSettings, "settings", map[string]any{
		"previous": map[string]any{"silent_after_hours": 0.0, "reenrollment_requires_approval": false},
		"settings": map[string]any{"silent_after_hours": 24.0, "reenrollment_requires_approval": false},
	}))
	if r["activity_id"] != 3.0 || r["severity_id"] != 2.0 {
		t.Errorf("activity %v, severity %v", r["activity_id"], r["severity_id"])
	}
	if r["message"] != "token:3f2a9c1b changed Altiward settings: silent_after_hours: 0 → 24" {
		t.Errorf("message = %v", r["message"])
	}
}

func TestEnrollmentApprovalNamesTheMac(t *testing.T) {
	r := auditJSON(t, auditEntry(store.AuditApproveEnrollment, "7e8f90a1-b2c3-4d4e-8f5a-6b7c8d9e0f1a",
		map[string]any{"serial": "C02XK0AAJGH5"}))
	if r["activity_id"] != 3.0 || r["message"] != "token:3f2a9c1b approved the enrollment of C02XK0AAJGH5" {
		t.Errorf("activity %v, message %v", r["activity_id"], r["message"])
	}
}

func TestSignInIsAnAuthentication(t *testing.T) {
	a := auditEntry(store.AuditSignIn, "console", map[string]any{"role": "operator", "name": "Jane Doe"})
	a.Actor = "jane.doe@example.com"
	r := auditJSON(t, a)
	for path, want := range map[string]any{
		"class_uid": 3002.0, "activity_id": 1.0, "type_uid": 300201.0, "user.name": "jane.doe@example.com",
		"user.email_addr": "jane.doe@example.com", "auth_protocol": "OpenID", "status": "Success",
		"unmapped.altiward.event_type": "console.sign_in",
		"message":                      "jane.doe@example.com signed in to the Altiward console as operator",
	} {
		if got := get(r, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	a.Action, a.Detail = store.AuditSignOut, map[string]any{}
	if r := auditJSON(t, a); r["activity_id"] != 2.0 || r["message"] != "jane.doe@example.com signed out of the Altiward console" {
		t.Errorf("sign out: %v, %v", r["activity_id"], r["message"])
	}
}

func TestSIEMTestEventSaysWhatItIs(t *testing.T) {
	r := auditJSON(t, auditEntry(store.AuditTestExport, "exports", nil))
	for path, want := range map[string]any{
		"class_uid": 6003.0, "activity_id": 1.0, "severity_id": 1.0, "api.operation": "test_export",
		"unmapped.altiward.event_type": "console.test_export",
		"message":                      "token:3f2a9c1b sent a test event from the Altiward console to check the SIEM connection",
	} {
		if got := get(r, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	if res := r["resources"].([]any)[0].(map[string]any); res["type"] != "SIEM export" {
		t.Errorf("resources = %v", res)
	}
}

func TestEndingSomeonesSignInIsALowDelete(t *testing.T) {
	r := auditJSON(t, auditEntry(store.AuditEndConsoleSession, "bob@example.com", map[string]any{"name": "Bob", "role": "viewer"}))
	if r["activity_id"] != 4.0 || r["activity_name"] != "Delete" || r["severity_id"] != 2.0 {
		t.Errorf("activity %v %v, severity %v", r["activity_id"], r["activity_name"], r["severity_id"])
	}
	if r["message"] != "token:3f2a9c1b ended bob@example.com's console sign-in from the Altiward console" {
		t.Errorf("message = %v", r["message"])
	}
}

func TestRetryNowNamesTheSink(t *testing.T) {
	r := auditJSON(t, auditEntry(store.AuditRetryExports, "sentinel", nil))
	for path, want := range map[string]any{
		"activity_id": 3.0, "api.operation": "retry_exports",
		"message": "token:3f2a9c1b retried the exports waiting for sentinel from the Altiward console",
	} {
		if got := get(r, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	if res := r["resources"].([]any)[0].(map[string]any); res["type"] != "SIEM export" || res["uid"] != "sentinel" {
		t.Errorf("resources = %v", res)
	}
}

func TestHistoryExpiryIsADeleteByTheServer(t *testing.T) {
	a := auditEntry(store.AuditExpireHistory, "history", map[string]any{
		"before": "2025-06-01T00:00:00Z", "days": 365.0, "reason": store.HistoryReasonDefaultSIEM,
		"held_before": "2024-12-01T00:00:00Z",
		"counts":      map[string]any{"events": 4.0, "sessions": 1.0, "commands": 0.0, "macs": 0.0},
	})
	a.Actor = store.ServerActor
	r := auditJSON(t, a)
	for path, want := range map[string]any{
		"class_uid": 6003.0, "activity_id": 4.0, "activity_name": "Delete", "type_uid": 600304.0, "severity_id": 1.0,
		"actor.user.name": "altiward:server", "actor.user.type": "System", "actor.user.type_id": 3.0,
		"actor.app_name": "Altiward server", "src_endpoint.name": "Altiward server", "api.service.name": "Altiward server",
		"api.operation": "expire_history", "unmapped.altiward.event_type": "console.expire_history",
		"message": "Altiward removed history received before 2025-06-01T00:00:00Z, past the 365 days it keeps " +
			"(the default with a SIEM connected): 4 events, 1 session, 0 commands",
	} {
		if got := get(r, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	if res := r["resources"].([]any)[0].(map[string]any); res["type"] != "History" || res["uid"] != "history" {
		t.Errorf("resources = %v", res)
	}
	// A person's action keeps the console as its source.
	if r := auditJSON(t, auditEntry(store.AuditRetryExports, "sentinel", nil)); get(r, "src_endpoint.name") != "Altiward console" ||
		get(r, "actor.user.type") != nil {
		t.Errorf("a person's entry: %v", r)
	}
}

func TestMacRemovalIsADeleteByTheServer(t *testing.T) {
	a := auditEntry(store.AuditRemoveDevice, "C02XK0AAJGH5", map[string]any{
		"last_check_in": "2025-01-01T12:00:00Z", "days": 365.0,
		"counts":          map[string]any{"events": 5.0, "sessions": 1.0, "commands": 0.0, "macs": 1.0},
		"silent_event_id": "3f6d1c2a-8b4e-5a7f-9c0d-1e2f3a4b5c6d",
	})
	a.Actor = store.ServerActor
	r := auditJSON(t, a)
	for path, want := range map[string]any{
		"class_uid": 6003.0, "activity_id": 4.0, "activity_name": "Delete", "type_uid": 600304.0, "severity_id": 1.0,
		"actor.user.name": "altiward:server", "actor.user.type": "System", "src_endpoint.name": "Altiward server",
		"api.operation": "remove_device", "unmapped.altiward.event_type": "console.remove_device",
		"unmapped.altiward.detail.silent_event_id": "3f6d1c2a-8b4e-5a7f-9c0d-1e2f3a4b5c6d",
		"message": "Altiward removed the Mac C02XK0AAJGH5, which last checked in at 2025-01-01T12:00:00Z, " +
			"past the 365 days of history it keeps, with 5 events, 1 session, 0 commands",
	} {
		if got := get(r, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	if res := r["resources"].([]any)[0].(map[string]any); res["type"] != "Mac" || res["uid"] != "C02XK0AAJGH5" || res["name"] != "C02XK0AAJGH5" {
		t.Errorf("resources = %v", res)
	}
}
