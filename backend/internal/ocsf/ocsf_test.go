package ocsf_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Altiward/altiward/backend/internal/ocsf"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func stored(t *testing.T, name string) store.StoredEvent {
	e := testfixture.Event(t, name)
	return store.StoredEvent{Event: e, ReceivedAt: e.Timestamp}
}

// Round-trip through JSON so assertions see what a SIEM sees.
func mapAllJSON(t *testing.T, e store.StoredEvent) []map[string]any {
	t.Helper()
	records := ocsf.Map(e, "acme")
	if len(records) == 0 {
		t.Fatal("not exported")
	}
	b, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func mapJSON(t *testing.T, e store.StoredEvent) map[string]any {
	t.Helper()
	records := mapAllJSON(t, e)
	if len(records) != 1 {
		t.Fatalf("%d records", len(records))
	}
	return records[0]
}

func get(m map[string]any, path string) any {
	var v any = m
	for _, k := range strings.Split(path, ".") {
		v = v.(map[string]any)[k]
	}
	return v
}

func TestGrantMapsToAssignPrivileges(t *testing.T) {
	r := mapJSON(t, stored(t, "elevation-granted"))
	want := map[string]any{
		"class_uid":                    3005.0,
		"activity_id":                  1.0,
		"type_uid":                     300501.0,
		"category_uid":                 3.0,
		"severity_id":                  1.0,
		"time":                         1792142043120.0,
		"metadata.uid":                 "0b6f6a52-6a0e-4d3e-9f5e-3f2a1c9d7e01",
		"metadata.correlation_uid":     "5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d",
		"metadata.version":             ocsf.Version,
		"metadata.tenant_uid":          "acme",
		"user.name":                    "jdoe",
		"user.email_addr":              "jane.doe@example.com",
		"device.hw_info.serial_number": "C02XK0AAJGH5",
		"device.os.type_id":            300.0,
		"unmapped.altiward.reason":     "Installing Xcode command line tools",
	}
	for path, v := range want {
		if got := get(r, path); got != v {
			t.Errorf("%s = %v, want %v", path, got, v)
		}
	}
	if !strings.Contains(r["message"].(string), "Installing Xcode") {
		t.Errorf("message = %v", r["message"])
	}
}

func TestRevokeMapsToRevokePrivileges(t *testing.T) {
	r := mapJSON(t, stored(t, "elevation-revoked"))
	if r["activity_id"] != 2.0 || r["type_uid"] != 300502.0 {
		t.Fatalf("%v %v", r["activity_id"], r["type_uid"])
	}
	if labels := get(r, "metadata.labels").([]any); labels[0] != "delayed" {
		t.Fatalf("labels = %v", labels)
	}
}

func TestUnverifiedClaimRaisesSeverity(t *testing.T) {
	e := stored(t, "elevation-revoked")
	e.Detail["verified"] = false
	r := mapJSON(t, e)
	if r["severity_id"] != 3.0 || r["status_detail"] == nil {
		t.Fatalf("severity = %v detail = %v", r["severity_id"], r["status_detail"])
	}
}

func TestOutOfBandIsHighSeverityFinding(t *testing.T) {
	r := mapJSON(t, stored(t, "admin-out-of-band"))
	if r["class_uid"] != 2004.0 || r["type_uid"] != 200401.0 || r["severity_id"] != 4.0 || r["is_alert"] != true {
		t.Fatalf("%v", r)
	}
	if get(r, "finding_info.analytic.name") != "altiward.admin_out_of_band" {
		t.Fatalf("analytic = %v", get(r, "finding_info.analytic"))
	}
	if get(r, "finding_info.title") != "Admin rights without a grant" {
		t.Fatalf("title = %v", get(r, "finding_info.title"))
	}
	if want := "backdoor holds admin rights on C02XK0AAJGH5 that nobody granted through SAP Privileges"; get(r, "finding_info.desc") != want {
		t.Fatalf("desc = %v", get(r, "finding_info.desc"))
	}
}

// Made a permanent admin later: the rights stay, and the out-of-band finding closes as
// resolved under the uid it opened with, the session's. Nothing was revoked.
func TestPermanentAdminClosesTheOutOfBandFinding(t *testing.T) {
	opened := mapJSON(t, stored(t, "admin-out-of-band"))
	closed := mapJSON(t, stored(t, "elevation-revoked-permanent-admin"))
	const session = "7e3d4c9b-0a6f-4c8d-be5f-4a3b2c1d0e9f"
	if get(opened, "metadata.uid") != "2d8b8c74-8c2a-4f5a-9b7a-5b4c3e1f9a23" {
		t.Fatalf("record uid = %v, want the event ID", get(opened, "metadata.uid"))
	}
	if get(opened, "finding_info.uid") != session || get(closed, "finding_info.uid") != session {
		t.Fatalf("uids = %v, %v", get(opened, "finding_info.uid"), get(closed, "finding_info.uid"))
	}
	if closed["class_uid"] != 2004.0 || closed["activity_name"] != "Close" || closed["status"] != "Resolved" ||
		closed["severity_id"] != 1.0 || closed["is_alert"] != nil {
		t.Fatalf("%v", closed)
	}
	if get(closed, "finding_info.analytic.name") != "altiward.admin_out_of_band" {
		t.Fatalf("analytic = %v", get(closed, "finding_info.analytic"))
	}
	if want := "Resolved on C02XK0AAJGH5: backdoor is now a permanent admin, so their admin rights are expected"; closed["message"] != want {
		t.Fatalf("message = %q", closed["message"])
	}
}

func TestPrivilegesGrantClosesTheOutOfBandFinding(t *testing.T) {
	// The grant is the hook's claim, so the finding closes as Other, saying why, not Resolved.
	closed := mapJSON(t, stored(t, "elevation-revoked-privileges-grant"))
	if get(closed, "finding_info.uid") != "7e3d4c9b-0a6f-4c8d-be5f-4a3b2c1d0e9f" {
		t.Fatalf("finding uid = %v, want the out-of-band session ID", get(closed, "finding_info.uid"))
	}
	if closed["class_uid"] != 2004.0 || closed["activity_name"] != "Close" || closed["status_id"] != 99.0 ||
		closed["status"] != "Replaced by a Privileges grant" || closed["severity_id"] != 1.0 || closed["is_alert"] != nil {
		t.Fatalf("%v", closed)
	}
	if get(closed, "finding_info.analytic.name") != "altiward.admin_out_of_band" {
		t.Fatalf("analytic = %v", get(closed, "finding_info.analytic"))
	}
	if want := "Replaced on C02XK0AAJGH5: a Privileges grant was reported for backdoor, who held admin rights without one"; closed["message"] != want {
		t.Fatalf("message = %q", closed["message"])
	}
}

func TestPersistenceIsAFindingWithFileEvidence(t *testing.T) {
	r := mapJSON(t, stored(t, "persistence-detected"))
	if r["class_uid"] != 2004.0 || r["type_uid"] != 200401.0 || r["severity_id"] != 4.0 || r["is_alert"] != true {
		t.Fatalf("%v", r)
	}
	if get(r, "finding_info.analytic.name") != "altiward.persistence_detected" {
		t.Fatalf("analytic = %v", get(r, "finding_info.analytic"))
	}
	if types := get(r, "finding_info.types").([]any); len(types) != 1 || types[0] != "Persistence" {
		t.Fatalf("types = %v", types)
	}
	want := "New persistence appeared on C02XK0AAJGH5 while jane.doe@example.com held admin rights: " +
		"new LaunchDaemon /Library/LaunchDaemons/com.example.updater.plist, new SSH key for root, " +
		"new sudoers rules in /etc/sudoers.d/jdoe"
	if get(r, "finding_info.desc") != want {
		t.Fatalf("desc = %v", get(r, "finding_info.desc"))
	}
	if get(r, "metadata.correlation_uid") != "5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d" {
		t.Fatalf("correlation_uid = %v", get(r, "metadata.correlation_uid"))
	}
	evidences := r["evidences"].([]any)
	var paths []string
	for _, ev := range evidences {
		paths = append(paths, get(ev.(map[string]any), "file.path").(string))
	}
	if strings.Join(paths, " ") != "/Library/LaunchDaemons/com.example.updater.plist /var/root/.ssh/authorized_keys /etc/sudoers.d/jdoe" {
		t.Fatalf("evidence paths = %v", paths)
	}
	if get(evidences[0].(map[string]any), "file.name") != "com.example.updater.plist" {
		t.Fatalf("evidence = %v", evidences[0])
	}
}

func TestPersistenceSummaryCountsWhatItLeavesOut(t *testing.T) {
	e := stored(t, "persistence-detected")
	e.Detail["findings"] = append(e.Detail["findings"].([]any),
		map[string]any{"kind": "local_account", "change": "modified", "name": "support", "uid": 499.0},
		map[string]any{"kind": "remote_access", "change": "added", "service": "remote_login"})
	e.Detail["truncated"] = 2.0
	r := mapJSON(t, e)
	if desc := get(r, "finding_info.desc").(string); !strings.HasSuffix(desc, "new sudoers rules in /etc/sudoers.d/jdoe, and 4 more") {
		t.Fatalf("desc = %v", desc)
	}
	evidences := r["evidences"].([]any)
	if got := get(evidences[3].(map[string]any), "user.name"); got != "support" {
		t.Fatalf("account evidence = %v", evidences[3])
	}

	e.Detail["findings"] = e.Detail["findings"].([]any)[3:]
	e.Detail["truncated"] = 1.0
	if desc := get(mapJSON(t, e), "finding_info.desc").(string); !strings.HasSuffix(desc, "changed account support, Remote Login turned on, and 1 more") {
		t.Fatalf("desc = %v", desc)
	}
}

func withAccount(t *testing.T, account map[string]any, others bool) store.StoredEvent {
	e := stored(t, "persistence-detected")
	findings := []any{account}
	if others {
		findings = append(e.Detail["findings"].([]any), account)
	}
	e.Detail = map[string]any{"findings": findings, "since": e.Detail["since"], "truncated": 0.0}
	return e
}

func TestANewAdminAccountIsItsOwnFinding(t *testing.T) {
	e := withAccount(t, map[string]any{"kind": "local_account", "change": "added", "name": "breakglass", "uid": 502.0, "admin": true}, true)
	records := mapAllJSON(t, e)
	if len(records) != 2 {
		t.Fatalf("%d records", len(records))
	}
	rest, r := records[0], records[1]
	if get(rest, "finding_info.analytic.name") != "altiward.persistence_detected" || get(rest, "metadata.uid") != e.EventID {
		t.Fatalf("persistence record = %v", rest["finding_info"])
	}
	if desc := get(rest, "finding_info.desc").(string); strings.Contains(desc, "breakglass") {
		t.Fatalf("account repeated in persistence: %v", desc)
	}

	uid := e.EventID + "/account/breakglass"
	want := map[string]any{
		"class_uid":                     2004.0,
		"type_uid":                      200401.0,
		"severity_id":                   4.0,
		"is_alert":                      true,
		"metadata.uid":                  uid,
		"metadata.correlation_uid":      "5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d",
		"finding_info.uid":              uid,
		"finding_info.title":            "Admin account created",
		"finding_info.analytic.name":    "altiward.account_created",
		"finding_info.desc":             "New admin account breakglass appeared on C02XK0AAJGH5 while jane.doe@example.com held admin rights",
		"user.name":                     "jdoe",
		"unmapped.altiward.account.uid": 502.0,
	}
	for path, v := range want {
		if got := get(r, path); got != v {
			t.Errorf("%s = %v, want %v", path, got, v)
		}
	}
	attack := r["finding_info"].(map[string]any)["attacks"].([]any)[0].(map[string]any)
	if get(attack, "sub_technique.uid") != "T1136.001" || get(attack, "tactic.uid") != "TA0003" {
		t.Errorf("attack = %v", attack)
	}
	evidence := r["evidences"].([]any)[0].(map[string]any)
	if get(evidence, "user.name") != "breakglass" || get(evidence, "user.uid") != "502" {
		t.Errorf("evidence = %v", evidence)
	}
}

func TestAnAccountAloneMakesOnlyItsOwnFinding(t *testing.T) {
	// Not an admin, or from an agent that doesn't say: still a finding, at Medium.
	for _, account := range []map[string]any{
		{"kind": "local_account", "change": "added", "name": "support", "uid": 499.0, "admin": false},
		{"kind": "local_account", "change": "added", "name": "support", "uid": 499.0},
	} {
		r := mapJSON(t, withAccount(t, account, false))
		if get(r, "finding_info.title") != "Local account created" || r["severity_id"] != 3.0 {
			t.Errorf("title %v severity %v", get(r, "finding_info.title"), r["severity_id"])
		}
		if want := "New account support appeared on C02XK0AAJGH5 while jane.doe@example.com held admin rights"; r["message"] != want {
			t.Errorf("message = %v", r["message"])
		}
	}
}

func TestOverdueIsFindingWhoseSeverityRisesWhenEnforcementFails(t *testing.T) {
	e := stored(t, "elevation-overdue")
	r := mapJSON(t, e)
	if r["class_uid"] != 2004.0 || r["severity_id"] != 3.0 || r["is_alert"] != true {
		t.Fatalf("class = %v severity = %v alert = %v", r["class_uid"], r["severity_id"], r["is_alert"])
	}
	if get(r, "finding_info.analytic.name") != "altiward.rights_after_expiry" {
		t.Fatalf("analytic = %v", get(r, "finding_info.analytic"))
	}
	if get(r, "metadata.correlation_uid") != "5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d" {
		t.Fatalf("correlation = %v", get(r, "metadata.correlation_uid"))
	}

	e.Detail["enforcement"], e.Detail["enforcement_failed"] = "enforce", true
	if r := mapJSON(t, e); r["severity_id"] != 4.0 {
		t.Fatalf("failed enforcement severity = %v", r["severity_id"])
	}
}

// Rights that outlive their expiry mean Privileges' timer failed or was stopped, so an
// enforced removal is a finding too, as in alert mode, besides the Low revoke record.
func TestEnforcedExpiryIsALowRevokeAndAFinding(t *testing.T) {
	records := mapAllJSON(t, stored(t, "elevation-expired-enforced"))
	if len(records) != 2 {
		t.Fatalf("%d records", len(records))
	}
	r := records[0]
	if r["class_uid"] != 3005.0 || r["activity_id"] != 2.0 || r["severity_id"] != 2.0 {
		t.Fatalf("class = %v activity = %v severity = %v", r["class_uid"], r["activity_id"], r["severity_id"])
	}
	if get(r, "metadata.uid") != "9a7c5e3b-1d2f-4b8a-9c6e-0f4d2b8a6c35" {
		t.Fatalf("revoke uid = %v", get(r, "metadata.uid"))
	}
	f := records[1]
	if f["class_uid"] != 2004.0 || f["severity_id"] != 3.0 || f["is_alert"] != true {
		t.Fatalf("class = %v severity = %v alert = %v", f["class_uid"], f["severity_id"], f["is_alert"])
	}
	if get(f, "finding_info.analytic.name") != "altiward.rights_after_expiry" {
		t.Fatalf("analytic = %v", get(f, "finding_info.analytic"))
	}
	const uid = "9a7c5e3b-1d2f-4b8a-9c6e-0f4d2b8a6c35/finding"
	if get(f, "metadata.uid") != uid || get(f, "finding_info.uid") != uid {
		t.Fatalf("finding uids = %v, %v", get(f, "metadata.uid"), get(f, "finding_info.uid"))
	}
	if get(f, "metadata.correlation_uid") != "5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d" {
		t.Fatalf("correlation = %v", get(f, "metadata.correlation_uid"))
	}
	if !strings.HasSuffix(f["message"].(string), "after they expired; Altiward removed them") {
		t.Fatalf("message = %q", f["message"])
	}
}

func TestRemoteRevokeMessage(t *testing.T) {
	e := stored(t, "elevation-revoked")
	e.Detail["trigger"], e.Detail["command_id"] = "command", "8c1d2e3f-4a5b-4c6d-9e7f-0a1b2c3d4e5f"
	r := mapJSON(t, e)
	if msg := r["message"].(string); !strings.Contains(msg, "revoked from the Altiward console") {
		t.Fatalf("message = %q", msg)
	}
	if get(r, "unmapped.altiward.command_id") != "8c1d2e3f-4a5b-4c6d-9e7f-0a1b2c3d4e5f" {
		t.Fatalf("command_id not exported: %v", r["unmapped"])
	}
}

func TestGrantMessageNamesSAPPrivilegesAndTheReason(t *testing.T) {
	msg := mapJSON(t, stored(t, "elevation-granted"))["message"].(string)
	if want := "jane.doe@example.com was granted admin rights on C02XK0AAJGH5 via SAP Privileges: Installing Xcode command line tools"; msg != want {
		t.Fatalf("message = %q", msg)
	}
}

func TestInferredRevokeFromHeartbeatMessage(t *testing.T) {
	e := stored(t, "elevation-revoked")
	e.Detail["trigger"], e.Detail["inferred"] = "heartbeat", true
	msg := mapJSON(t, e)["message"].(string)
	if want := "jane.doe@example.com no longer holds admin rights on C02XK0AAJGH5 (observed by heartbeat)"; msg != want {
		t.Fatalf("message = %q", msg)
	}
}

func TestHealthIsNotExported(t *testing.T) {
	if records := ocsf.Map(stored(t, "agent-health"), "acme"); len(records) != 0 {
		t.Fatal("agent.health exported")
	}
}

func TestTamperFailureIsAFinding(t *testing.T) {
	r := mapJSON(t, stored(t, "agent-tamper"))
	if r["class_uid"] != float64(2004) || r["activity_name"] != "Create" || r["is_alert"] != true || r["severity"] != "Medium" {
		t.Fatalf("class %v activity %v severity %v", r["class_uid"], r["activity_name"], r["severity"])
	}
	if get(r, "finding_info.analytic.name") != "altiward.tamper.settings_managed" ||
		get(r, "finding_info.uid") != "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D/settings_managed" {
		t.Fatalf("finding = %v", r["finding_info"])
	}
	if msg := r["message"].(string); !strings.Contains(msg, "C02XK0AAJGH5") || !strings.Contains(msg, "set outside MDM: PermanentAdmins") {
		t.Fatalf("message = %q", msg)
	}
}

func TestStoppedPrivilegesTimerIsAHighFinding(t *testing.T) {
	e := stored(t, "agent-tamper")
	e.Detail = map[string]any{"check": "privileges_timer", "state": "failed",
		"problem": "Privileges' timer isn't running for jdoe, who holds admin rights it granted"}
	r := mapJSON(t, e)
	if r["severity"] != "High" || get(r, "finding_info.title") != "SAP Privileges' timer stopped while someone holds admin rights" {
		t.Fatalf("severity %v title %v", r["severity"], get(r, "finding_info.title"))
	}
	if msg := r["message"].(string); !strings.HasSuffix(msg, "isn't running for jdoe, who holds admin rights it granted") {
		t.Fatalf("message = %q", msg)
	}
}

// The console shows the severity a SIEM gets for each failing check.
func TestTamperSeveritiesMatchTheFindings(t *testing.T) {
	severities := ocsf.TamperSeverities()
	if len(severities) == 0 {
		t.Fatal("no severities")
	}
	for check, want := range severities {
		e := stored(t, "agent-tamper")
		e.Detail = map[string]any{"check": check, "state": "failed", "problem": nil}
		if got := mapJSON(t, e)["severity"]; got != want {
			t.Errorf("%s: finding %v, TamperSeverities %q", check, got, want)
		}
	}
	if severities["settings_managed"] != "Medium" || severities["code_signature"] != "High" {
		t.Fatalf("severities = %v", severities)
	}
}

func TestTamperRestoredClosesTheFinding(t *testing.T) {
	e := stored(t, "agent-tamper")
	e.Detail = map[string]any{"check": "code_signature", "state": "restored", "problem": nil}
	r := mapJSON(t, e)
	if r["activity_name"] != "Close" || r["status"] != "Resolved" || r["severity"] != "Informational" || r["is_alert"] == true {
		t.Fatalf("activity %v status %v severity %v", r["activity_name"], r["status"], r["severity"])
	}
	// Same uid as the failure it resolves.
	if get(r, "finding_info.uid") != "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D/code_signature" {
		t.Fatalf("uid = %v", get(r, "finding_info.uid"))
	}
}

// A failing check that stops applying closes its finding, saying why rather than "Resolved".
func TestTamperRetiredClosesTheFindingAsNoLongerChecked(t *testing.T) {
	r := mapJSON(t, stored(t, "agent-tamper-retired"))
	if r["activity_name"] != "Close" || r["status_id"] != 99.0 || r["status"] != "No longer checked" ||
		r["severity"] != "Informational" || r["is_alert"] == true {
		t.Fatalf("activity %v status %v %v severity %v", r["activity_name"], r["status_id"], r["status"], r["severity"])
	}
	if get(r, "finding_info.uid") != "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D/privileges_tamper_protection" {
		t.Fatalf("uid = %v", get(r, "finding_info.uid"))
	}
	want := "No longer checked on C02XK0AAJGH5 (SAP Privileges isn't installed now): SAP Privileges tamper protection is off"
	if r["message"] != want || r["status_detail"] != "SAP Privileges isn't installed now" {
		t.Fatalf("message %q, status_detail %v", r["message"], r["status_detail"])
	}
}

func TestDowngradeIsAHighFinding(t *testing.T) {
	e := stored(t, "agent-tamper")
	e.Detail = map[string]any{"check": "agent_version", "state": "detected", "problem": "the agent went from 0.3.0 to 0.2.0",
		"previous_version": "0.3.0", "current_version": "0.2.0"}
	r := mapJSON(t, e)
	if r["severity"] != "High" || get(r, "finding_info.title") != "Altiward agent was downgraded" {
		t.Fatalf("severity %v title %v", r["severity"], get(r, "finding_info.title"))
	}
	// A one-off: its own uid.
	if get(r, "finding_info.uid") != e.EventID {
		t.Fatalf("uid = %v", get(r, "finding_info.uid"))
	}
}

func TestSilentIsAFindingTheResumeCloses(t *testing.T) {
	silent := stored(t, "agent-silent")
	r := mapJSON(t, silent)
	if r["class_uid"] != float64(2004) || r["activity_name"] != "Create" || r["is_alert"] != true || r["severity"] != "Medium" {
		t.Fatalf("class %v activity %v severity %v", r["class_uid"], r["activity_name"], r["severity"])
	}
	if get(r, "finding_info.uid") != silent.EventID || get(r, "finding_info.analytic.name") != "altiward.agent_silent" {
		t.Fatalf("finding = %v", r["finding_info"])
	}
	if msg := r["message"].(string); !strings.Contains(msg, "C02XK0AAJGH5 has not checked in since 2026-10-13T09:00:00Z") ||
		!strings.Contains(msg, "72 hours") {
		t.Fatalf("message = %q", msg)
	}

	resumed := stored(t, "agent-silent")
	resumed.EventID = "4a7e2d3b-9c5f-5b80-8d1e-2f3a4b5c6d7e"
	resumed.Detail = map[string]any{"state": "resumed", "last_seen_at": "2026-10-16T11:55:00Z",
		"silent_since": "2026-10-13T09:00:00Z", "alert_event_id": silent.EventID}
	r = mapJSON(t, resumed)
	if r["activity_name"] != "Close" || r["status"] != "Resolved" || r["is_alert"] == true ||
		get(r, "finding_info.uid") != silent.EventID {
		t.Fatalf("activity %v status %v uid %v", r["activity_name"], r["status"], get(r, "finding_info.uid"))
	}
}
