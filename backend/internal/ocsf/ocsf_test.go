package ocsf_test

import (
	"encoding/json"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
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

// Known is what stops the export drain from completing an event type a newer server
// raises and this one cannot map: every example type has to be in it.
func TestKnownCoversEveryExampleType(t *testing.T) {
	for _, name := range testfixture.Names {
		if e := testfixture.Event(t, name); !ocsf.Known(e.Type) {
			t.Errorf("%s: %q is not Known", name, e.Type)
		}
	}
	if ocsf.Known("agent.future") {
		t.Error("agent.future is Known")
	}
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
	if want := "backdoor holds admin rights on C02XK0AAJGH5 that nobody granted through SAP Privileges; added by /usr/sbin/dseditgroup"; get(r, "finding_info.desc") != want {
		t.Fatalf("desc = %v", get(r, "finding_info.desc"))
	}
}

// Privileges' system extension said which process added the user: it is the finding's
// evidence. Without it the finding says only what the agent saw.
func TestOutOfBandNamesTheProcessThatAddedTheUser(t *testing.T) {
	r := mapJSON(t, stored(t, "admin-out-of-band"))
	evidences, _ := r["evidences"].([]any)
	if len(evidences) != 1 || get(evidences[0].(map[string]any), "process.file.path") != "/usr/sbin/dseditgroup" ||
		get(evidences[0].(map[string]any), "process.pid") != 5165.0 {
		t.Fatalf("evidences = %v", r["evidences"])
	}

	e := stored(t, "admin-out-of-band")
	e.Detail = map[string]any{"first_observed": "2026-10-16T10:00:00Z"}
	r = mapJSON(t, e)
	if r["evidences"] != nil || strings.Contains(r["message"].(string), "added by") {
		t.Fatalf("without an instigator: evidences %v, message %q", r["evidences"], r["message"])
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

const outOfBandSession = "7e3d4c9b-0a6f-4c8d-be5f-4a3b2c1d0e9f"

// outOfBandRevoke is the elevation-revoked example ending the admin-out-of-band session
// instead, with detail in place of the hook's: backdoor's rights, at 10:03, inside the
// grace period before the automatic removal at 10:05, from the same agent.
func outOfBandRevoke(t *testing.T, detail map[string]any) store.StoredEvent {
	e := stored(t, "elevation-revoked")
	opened := stored(t, "admin-out-of-band")
	session := outOfBandSession
	e.EventID = "6c2f9a1e-4b7d-4e3a-9f05-8d1c7b2a3e64"
	e.SessionID = &session
	e.Timestamp = time.Date(2026, 10, 16, 10, 3, 0, 0, time.UTC)
	e.ReceivedAt = e.Timestamp
	e.Delayed = false
	e.Device.AgentVersion = opened.Device.AgentVersion
	e.User = &event.User{LocalName: "backdoor"}
	e.Elevation = &event.Elevation{Source: event.SourceOutOfBand}
	e.Detail = detail
	return e
}

// consoleRevokeOfOutOfBand revokes rights nobody granted from the console.
func consoleRevokeOfOutOfBand(t *testing.T) store.StoredEvent {
	return outOfBandRevoke(t, map[string]any{"trigger": "command", "command_id": "8c1d2e3f-4a5b-4c6d-9e7f-0a1b2c3d4e5f",
		"observed_admin": false, "verified": true})
}

// assertRemovedClose checks the second record of a removal of rights nobody granted: it
// closes the session's out-of-band finding as "Rights removed", which is no explanation.
func assertRemovedClose(t *testing.T, e store.StoredEvent, records []map[string]any, wantMessage string) {
	t.Helper()
	if len(records) != 2 {
		t.Fatalf("%d records", len(records))
	}
	if r := records[0]; r["class_uid"] != 3005.0 || r["activity_id"] != 2.0 || get(r, "metadata.uid") != e.EventID {
		t.Fatalf("revoke record: class %v activity %v uid %v", r["class_uid"], r["activity_id"], get(r, "metadata.uid"))
	}
	f := records[1]
	want := map[string]any{
		"class_uid":                  2004.0,
		"activity_id":                3.0,
		"activity_name":              "Close",
		"status_id":                  99.0,
		"status":                     "Rights removed",
		"severity_id":                1.0,
		"metadata.uid":               e.EventID + "/finding",
		"finding_info.uid":           outOfBandSession,
		"finding_info.title":         "Admin rights without a grant",
		"finding_info.analytic.name": "altiward.admin_out_of_band",
	}
	for path, v := range want {
		if got := get(f, path); got != v {
			t.Errorf("%s = %v, want %v", path, got, v)
		}
	}
	if f["is_alert"] != nil {
		t.Errorf("is_alert = %v", f["is_alert"])
	}
	if f["message"] != wantMessage || get(f, "finding_info.desc") != wantMessage {
		t.Errorf("message = %q, want %q", f["message"], wantMessage)
	}
}

// The agent removed rights nobody granted after the grace period: a Low revoke, and the
// out-of-band finding closes, as "Rights removed" rather than Resolved, since nobody
// explained them.
func TestOutOfBandRemovedIsALowRevokeAndClosesTheFinding(t *testing.T) {
	e := stored(t, "admin-out-of-band-removed")
	records := mapAllJSON(t, e)
	assertRemovedClose(t, e, records,
		"Removed on C02XK0AAJGH5: Altiward removed backdoor's admin rights, which nobody granted, after the grace period")
	r := records[0]
	if r["severity_id"] != 2.0 || r["activity_name"] != "Revoke Privileges" {
		t.Fatalf("severity %v activity %v", r["severity_id"], r["activity_name"])
	}
	if want := "Altiward removed backdoor's admin rights on C02XK0AAJGH5, which nobody granted"; r["message"] != want {
		t.Fatalf("message = %q", r["message"])
	}
}

func TestConsoleRevokeOfRightsNobodyGrantedClosesTheFinding(t *testing.T) {
	e := consoleRevokeOfOutOfBand(t)
	records := mapAllJSON(t, e)
	assertRemovedClose(t, e, records,
		"Removed on C02XK0AAJGH5: backdoor's admin rights, which nobody granted, were revoked from the Altiward console")
	if r := records[0]; r["severity_id"] != 1.0 || !strings.Contains(r["message"].(string), "revoked from the Altiward console") {
		t.Fatalf("revoke record: severity %v message %q", r["severity_id"], r["message"])
	}
}

func TestHeartbeatSeeingRightsNobodyGrantedGoneClosesTheFinding(t *testing.T) {
	e := outOfBandRevoke(t, map[string]any{"trigger": "heartbeat", "inferred": true, "observed_admin": false, "verified": true})
	assertRemovedClose(t, e, mapAllJSON(t, e),
		"Removed on C02XK0AAJGH5: backdoor no longer holds the admin rights nobody granted")
}

// An orphan revoke ends no session the server knows, so there is no finding to close.
func TestOrphanRevokeClosesNoFinding(t *testing.T) {
	e := consoleRevokeOfOutOfBand(t)
	e.Detail["orphan"] = true
	if r := mapJSON(t, e); r["class_uid"] != 3005.0 {
		t.Fatalf("class = %v", r["class_uid"])
	}
}

// Rights that stay, or rights Privileges granted, close no out-of-band finding as removed.
func TestRevokeOfAPrivilegesGrantClosesNoFinding(t *testing.T) {
	if r := mapJSON(t, stored(t, "elevation-revoked")); r["class_uid"] != 3005.0 {
		t.Fatalf("class = %v", r["class_uid"])
	}
	e := consoleRevokeOfOutOfBand(t)
	e.Detail["observed_admin"] = true
	if r := mapJSON(t, e); r["class_uid"] != 3005.0 {
		t.Fatalf("still admin: class = %v", r["class_uid"])
	}
	e = consoleRevokeOfOutOfBand(t)
	e.SessionID = nil
	if r := mapJSON(t, e); r["class_uid"] != 3005.0 {
		t.Fatalf("no session: class = %v", r["class_uid"])
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

// The Privileges settings Altiward recommends are standing findings, closed when fixed.
func TestPrivilegesSettingsChecksAreStandingFindings(t *testing.T) {
	for check, want := range map[string]struct{ title, severity string }{
		"privileges_expiry_cap":        {"SAP Privileges grants have no expiry cap", "Medium"},
		"privileges_renewal":           {"SAP Privileges allows renewals that Altiward doesn't see", "Medium"},
		"privileges_give_back_hook":    {"SAP Privileges may not report give-backs to Altiward", "Medium"},
		"privileges_revoke_exclusions": {"SAP Privileges removes admin rights from a permanent admin account", "Medium"},
	} {
		e := stored(t, "agent-tamper")
		e.Detail = map[string]any{"check": check, "state": "failed", "problem": "a problem"}
		r := mapJSON(t, e)
		if r["severity"] != want.severity || r["activity_name"] != "Create" || get(r, "finding_info.title") != want.title ||
			get(r, "finding_info.analytic.name") != "altiward.tamper."+check {
			t.Fatalf("%s: severity %v finding %v", check, r["severity"], r["finding_info"])
		}
		e.Detail["state"], e.Detail["problem"] = "restored", nil
		if r := mapJSON(t, e); r["activity_name"] != "Close" || r["status"] != "Resolved" {
			t.Fatalf("%s: activity %v status %v", check, r["activity_name"], r["status"])
		}
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

// Each attempt Privileges blocked is its own alert, like a downgrade: nothing closes it.
func TestPrivilegesBlockedIsAOneOffAlert(t *testing.T) {
	r := mapJSON(t, stored(t, "agent-tamper-privileges-blocked"))
	if r["activity_name"] != "Create" || r["severity"] != "High" || r["is_alert"] != true {
		t.Fatalf("activity %v severity %v alert %v", r["activity_name"], r["severity"], r["is_alert"])
	}
	if get(r, "finding_info.uid") != "9b4e2d71-3c5a-4f8e-a6d2-7e1f0c9b8a35" ||
		get(r, "finding_info.analytic.name") != "altiward.tamper.privileges_blocked" {
		t.Fatalf("uid %v analytic %v", get(r, "finding_info.uid"), get(r, "finding_info.analytic.name"))
	}
	want := "SAP Privileges blocked an attempt to tamper with it on C02XK0AAJGH5: SAP Privileges blocked /bin/rm from trying to delete /Applications/Privileges.app (2 attempts)"
	if r["message"] != want {
		t.Fatalf("message %q", r["message"])
	}
}

// A refused or unconfirmed grant claim is a one-off alert, like a blocked attempt: nothing closes it.
func TestGrantClaimIsAOneOffAlert(t *testing.T) {
	r := mapJSON(t, stored(t, "agent-tamper-grant-claim"))
	if r["activity_name"] != "Create" || r["severity"] != "High" || r["is_alert"] != true {
		t.Fatalf("activity %v severity %v alert %v", r["activity_name"], r["severity"], r["is_alert"])
	}
	if get(r, "finding_info.uid") != "c3f1a8e4-6b2d-4d7f-9a05-1e8b7c6d5f42" ||
		get(r, "finding_info.analytic.name") != "altiward.tamper.grant_claim" {
		t.Fatalf("uid %v analytic %v", get(r, "finding_info.uid"), get(r, "finding_info.analytic.name"))
	}
	if title := get(r, "finding_info.title"); title != "A SAP Privileges grant claim was refused or not confirmed by Privileges' log" {
		t.Fatalf("title %v", title)
	}
	if msg := r["message"].(string); !strings.HasSuffix(msg, "a Privileges grant claimed for jdoe, which Privileges' own log does not confirm") {
		t.Fatalf("message %q", msg)
	}
}

// The standing check is a medium finding that the restore closes, paired by device and check.
func TestGrantConfirmationIsAStandingMediumFinding(t *testing.T) {
	e := stored(t, "agent-tamper")
	e.Detail = map[string]any{"check": "grant_confirmation", "state": "failed",
		"problem": "Privileges' system extension isn't running"}
	r := mapJSON(t, e)
	if r["severity"] != "Medium" || r["activity_name"] != "Create" ||
		get(r, "finding_info.title") != "Altiward can't confirm SAP Privileges grants against Privileges' log" ||
		get(r, "finding_info.analytic.name") != "altiward.tamper.grant_confirmation" ||
		get(r, "finding_info.uid") != "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D/grant_confirmation" {
		t.Fatalf("severity %v finding %v", r["severity"], r["finding_info"])
	}
	e.Detail["state"], e.Detail["problem"] = "restored", nil
	if r := mapJSON(t, e); r["activity_name"] != "Close" || r["status"] != "Resolved" {
		t.Fatalf("activity %v status %v", r["activity_name"], r["status"])
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

// An early silence, when Intune still hears from the Mac, is High: the agent has probably
// been removed or stopped. Both bases name the admins at the Mac's last check-in.
func TestSilentWhileIntuneHearsFromTheMacIsHigh(t *testing.T) {
	early := stored(t, "agent-silent-mdm")
	r := mapJSON(t, early)
	if r["activity_name"] != "Create" || r["is_alert"] != true || r["severity"] != "High" ||
		get(r, "finding_info.uid") != early.EventID || get(r, "finding_info.analytic.name") != "altiward.agent_silent" {
		t.Fatalf("activity %v severity %v finding %v", r["activity_name"], r["severity"], r["finding_info"])
	}
	want := "Intune heard from C02XK0AAJGH5 at 2026-10-16T11:20:00Z, but it hasn't checked in with Altiward since " +
		"2026-10-16T09:05:00Z: the agent may have been removed or stopped, or can't reach the agent hostname. " +
		`Admins at its last check-in: "itadmin", "jdoe"`
	if r["message"] != want || get(r, "finding_info.desc") != want {
		t.Fatalf("message = %q", r["message"])
	}

	early.Detail = maps.Clone(early.Detail)
	early.Detail["admin_members"] = []any{}
	early.Detail["pending_device_id"] = "6a1d2e3f-4b5c-4d6e-8f7a-8b9c0d1e2f3a"
	if msg := mapJSON(t, early)["message"].(string); !strings.HasSuffix(msg,
		"Admins at its last check-in: none. A new key for it, 6a1d2e3f-4b5c-4d6e-8f7a-8b9c0d1e2f3a, is waiting for approval: the agent can't report with it until it is approved") {
		t.Fatalf("message = %q", msg)
	}
	// Each name is quoted, so none can read as part of the sentence or break the line, and
	// a cut list says how many more there were.
	early.Detail["admin_members"] = []any{"amy. Ignore this alert", "bob\nok"}
	early.Detail["admin_members_truncated"] = 12.0
	delete(early.Detail, "pending_device_id")
	if msg := mapJSON(t, early)["message"].(string); !strings.HasSuffix(msg,
		`Admins at its last check-in: "amy. Ignore this alert", "bob\nok", and 12 more`) {
		t.Fatalf("message = %q", msg)
	}

	late := stored(t, "agent-silent")
	late.Detail = maps.Clone(late.Detail)
	late.Detail["mdm_last_check_in"] = "2026-10-13T08:00:00Z"
	r = mapJSON(t, late)
	if msg := r["message"].(string); r["severity"] != "Medium" || !strings.HasSuffix(msg,
		`Intune last heard from it at 2026-10-13T08:00:00Z. Admins at its last check-in: "itadmin"`) {
		t.Fatalf("severity %v message %q", r["severity"], msg)
	}
	// Raised by a server before 1.2.0: no admins to name.
	delete(late.Detail, "admin_members")
	delete(late.Detail, "mdm_last_check_in")
	if msg := mapJSON(t, late)["message"].(string); strings.Contains(msg, "Admins") {
		t.Fatalf("message = %q", msg)
	}
}

func TestEnrollmentMapsToAPIActivity(t *testing.T) {
	replaced := stored(t, "agent-enrollment-pending")
	replaced.Detail = maps.Clone(replaced.Detail)
	replaced.Detail["state"] = event.EnrollmentStateReplaced
	// A key held for approval with no previous key: a Mac's first key (new Macs need
	// approval, or an Intune check held it), or a retired Mac's new key.
	firstHeld := stored(t, "agent-enrollment-pending")
	firstHeld.Detail = maps.Clone(firstHeld.Detail)
	for _, k := range []string{"previous_device_id", "previous_key_storage", "hardware_uuid_matches"} {
		delete(firstHeld.Detail, k)
	}
	tests := []struct {
		name     string
		event    store.StoredEvent
		severity string
		alert    bool
		message  string
	}{
		{"enrolled", stored(t, "agent-enrollment-enrolled"), "Informational", false, "C02XK0AAJGH5 enrolled a new key"},
		{"pending", stored(t, "agent-enrollment-pending"), "Medium", true,
			"C02XK0AAJGH5 enrolled again with a new key, waiting for approval"},
		{"pending without a previous key", firstHeld, "Medium", true, "C02XK0AAJGH5 enrolled a new key, waiting for approval"},
		{"replaced", replaced, "High", true,
			"C02XK0AAJGH5 enrolled again; the new key replaced the previous one without approval"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mapJSON(t, tt.event)
			want := map[string]any{
				"class_uid": 6003.0, "class_name": "API Activity", "category_uid": 6.0,
				"activity_id": 1.0, "activity_name": "Create", "type_uid": 600301.0,
				"severity": tt.severity, "status": "Success", "message": tt.message,
				"actor.user.name":                "token:1a2b3c4d",
				"api.operation":                  "enroll",
				"unmapped.altiward.event_type":   "agent.enrollment",
				"unmapped.altiward.detail.state": tt.event.Detail["state"],
			}
			for path, w := range want {
				if got := get(r, path); got != w {
					t.Errorf("%s = %v, want %v", path, got, w)
				}
			}
			if _, ok := get(r, "device.os").(map[string]any)["version"]; ok {
				t.Error("device.os.version is set, but the server doesn't know it")
			}
			if (r["is_alert"] == true) != tt.alert {
				t.Errorf("is_alert = %v, want %v", r["is_alert"], tt.alert)
			}
			resources, _ := r["resources"].([]any)
			if len(resources) != 1 {
				t.Fatalf("resources = %v", r["resources"])
			}
			wantResource := map[string]any{"type": "Enrollment", "uid": "5d2c8e1a-7b4f-4a93-8c6d-0f1e2a3b4c5d", "name": "C02XK0AAJGH5"}
			if got := resources[0]; !reflect.DeepEqual(got, wantResource) {
				t.Errorf("resource = %v, want %v", got, wantResource)
			}
		})
	}
}

func TestRotatedEnrollmentMapsToAnUpdate(t *testing.T) {
	r := mapJSON(t, stored(t, "agent-enrollment-rotated"))
	want := map[string]any{
		"class_uid": 6003.0, "activity_id": 3.0, "activity_name": "Update", "type_uid": 600303.0,
		"type_name": "API Activity: Update", "severity": "Informational", "status": "Success",
		"message":                        "C02XK0AAJGH5 replaced its key by rotation",
		"actor.user.name":                "C02XK0AAJGH5",
		"api.operation":                  "rotate",
		"unmapped.altiward.event_type":   "agent.enrollment",
		"unmapped.altiward.detail.state": "rotated",
	}
	for path, w := range want {
		if got := get(r, path); got != w {
			t.Errorf("%s = %v, want %v", path, got, w)
		}
	}
	if _, ok := r["is_alert"]; ok {
		t.Errorf("is_alert = %v, want none", r["is_alert"])
	}
	resources, _ := r["resources"].([]any)
	if len(resources) != 1 || get(map[string]any{"r": resources[0]}, "r.uid") != "9b4e7d2c-1a63-4f85-b0d9-6c3a5e8f1d27" {
		t.Errorf("resources = %v", r["resources"])
	}
}

func TestStaleKeyUseMapsToAnAlert(t *testing.T) {
	r := mapJSON(t, stored(t, "agent-enrollment-rotated-key-used"))
	want := map[string]any{
		"class_uid": 6003.0, "activity_id": 99.0, "activity_name": "Stale key used", "type_uid": 600399.0,
		"type_name": "API Activity: Stale key used", "severity": "High", "status": "Failure", "status_id": 2.0,
		"message":                        "C02XK0AAJGH5 used a key it had already replaced",
		"actor.user.name":                "C02XK0AAJGH5",
		"api.operation":                  "rotate",
		"unmapped.altiward.event_type":   "agent.enrollment",
		"unmapped.altiward.detail.state": "rotated_key_used",
		"metadata.product.version":       "1.0.0",
	}
	for path, w := range want {
		if got := get(r, path); got != w {
			t.Errorf("%s = %v, want %v", path, got, w)
		}
	}
	if r["is_alert"] != true {
		t.Errorf("is_alert = %v", r["is_alert"])
	}
	resources, _ := r["resources"].([]any)
	if len(resources) != 1 || get(map[string]any{"r": resources[0]}, "r.uid") != "5d2c8e1a-7b4f-4a93-8c6d-0f1e2a3b4c5d" {
		t.Errorf("resources = %v", r["resources"])
	}
}

func TestEnrollmentWithoutATokenHasNoActor(t *testing.T) {
	e := stored(t, "agent-enrollment-enrolled")
	e.Detail = maps.Clone(e.Detail)
	delete(e.Detail, "token")
	if r := mapJSON(t, e); r["actor"] != nil {
		t.Fatalf("actor = %v", r["actor"])
	}
}

func TestFirstPendingEnrollmentKeepsPreviousKeyUnknown(t *testing.T) {
	e := stored(t, "agent-enrollment-pending")
	e.Detail = maps.Clone(e.Detail)
	for _, field := range []string{"previous_device_id", "previous_key_storage", "hardware_uuid_matches"} {
		delete(e.Detail, field)
	}
	r := mapJSON(t, e)
	if get(r, "unmapped.altiward.detail.state") != "pending" || r["severity"] != "Medium" || r["is_alert"] != true {
		t.Fatalf("first pending enrolment lost its alert state: %v", r)
	}
	if get(r, "actor.user.name") != "token:1a2b3c4d" {
		t.Fatalf("first pending enrolment lost its token attribution: %v", r)
	}
	detail, ok := get(r, "unmapped.altiward.detail").(map[string]any)
	if !ok {
		t.Fatalf("missing enrolment detail: %v", r)
	}
	for _, field := range []string{"previous_device_id", "previous_key_storage", "hardware_uuid_matches"} {
		if _, exists := detail[field]; exists {
			t.Errorf("first pending enrolment invented %s = %v", field, detail[field])
		}
	}
}

// A changed admin group is one Add User record per person added, one Remove User per
// person removed, then the Mac's: each with its own uid, and the first with the event's.
func TestAdminGroupChangedRecords(t *testing.T) {
	e := stored(t, "agent-admin-group-changed")
	records := mapAllJSON(t, e)
	if len(records) != 3 {
		t.Fatalf("%d records, want 1 added + 1 removed + 1 for the Mac", len(records))
	}
	added, removed, mac := records[0], records[1], records[2]
	uids := map[string]bool{}
	for i, r := range records {
		if get(r, "class_uid") != 3006.0 || get(r, "class_name") != "Group Management" || get(r, "category_uid") != 3.0 ||
			get(r, "severity_id") != 1.0 || get(r, "group.name") != "admin" || get(r, "device.hw_info.serial_number") != "C02XK0AAJGH5" {
			t.Errorf("record %d: %v", i, r)
		}
		uids[get(r, "metadata.uid").(string)] = true
	}
	if len(uids) != 3 || get(added, "metadata.uid") != e.EventID {
		t.Errorf("uids = %v, want three distinct, the first the event's", uids)
	}
	if get(added, "activity_id") != 3.0 || get(added, "activity_name") != "Add User" || get(added, "type_uid") != 300603.0 ||
		get(added, "user.name") != "jdoe" || get(added, "metadata.correlation_uid") != "7f3a9c2e-1d4b-4e8a-9b60-5c2d8e1f4a37" ||
		get(added, "unmapped.altiward.source") != "privileges" {
		t.Errorf("added = %v", added)
	}
	if get(removed, "activity_id") != 4.0 || get(removed, "activity_name") != "Remove User" || get(removed, "user.name") != "asmith" {
		t.Errorf("removed = %v", removed)
	}
	if get(removed, "metadata").(map[string]any)["correlation_uid"] != nil {
		t.Errorf("a removed person has no session: %v", removed["metadata"])
	}
	if get(mac, "activity_id") != 99.0 || get(mac, "activity_name") != "Admin group" || mac["user"] != nil {
		t.Errorf("mac = %v", mac)
	}
	if got := get(mac, "unmapped.altiward.detail.members"); !reflect.DeepEqual(got, []any{"root", "itadmin", "jdoe"}) {
		t.Errorf("mac members = %v", got)
	}
	for field, want := range map[string]float64{"member_count": 3, "permanent_admin_count": 1, "added_count": 1, "removed_count": 1} {
		if got := get(mac, "unmapped.altiward."+field); got != want {
			t.Errorf("mac %s = %v, want %v", field, got, want)
		}
	}
	// A person's record names the person, not the group around them.
	for _, r := range []map[string]any{added, removed} {
		detail := get(r, "unmapped.altiward.detail").(map[string]any)
		for _, field := range []string{"members", "permanent_admins", "added", "removed"} {
			if _, ok := detail[field]; ok {
				t.Errorf("%s carries %s: %v", get(r, "user.name"), field, detail)
			}
		}
	}
}

func TestAdminGroupSnapshotRecords(t *testing.T) {
	e := stored(t, "agent-admin-group-snapshot")
	records := mapAllJSON(t, e)
	if len(records) != 3 {
		t.Fatalf("%d records, want 2 members + 1 for the Mac", len(records))
	}
	for i, want := range []struct {
		name      string
		permanent bool
	}{{"root", false}, {"itadmin", true}} {
		r := records[i]
		if get(r, "class_uid") != 3006.0 || get(r, "activity_id") != 99.0 || get(r, "activity_name") != "Admin group member" ||
			get(r, "user.name") != want.name || get(r, "group.name") != "admin" {
			t.Errorf("member %s = %v", want.name, r)
		}
		if got, _ := get(r, "unmapped.altiward").(map[string]any)["permanent"].(bool); got != want.permanent {
			t.Errorf("%s permanent = %v", want.name, got)
		}
		if _, ok := get(r, "unmapped.altiward.detail").(map[string]any)["members"]; ok {
			t.Errorf("%s carries the whole group: %v", want.name, r["unmapped"])
		}
	}
	mac := records[2]
	if get(mac, "activity_name") != "Admin group" || get(mac, "unmapped.altiward.member_count") != 2.0 || mac["user"] != nil {
		t.Errorf("mac = %v", mac)
	}
	if get(records[0], "metadata.uid") != e.EventID || get(records[1], "metadata.uid") == get(records[2], "metadata.uid") {
		t.Errorf("uids = %v %v %v", get(records[0], "metadata.uid"), get(records[1], "metadata.uid"), get(records[2], "metadata.uid"))
	}
}

// Nobody in the group is still a fact worth sending: the Mac's record goes even then.
func TestAdminGroupSnapshotOfEmptyGroup(t *testing.T) {
	e := stored(t, "agent-admin-group-snapshot")
	e.Detail = maps.Clone(e.Detail)
	e.Detail["members"], e.Detail["permanent_admins"] = []any{}, []any{}
	records := mapAllJSON(t, e)
	if len(records) != 1 {
		t.Fatalf("%d records, want exactly the Mac's", len(records))
	}
	r := records[0]
	if get(r, "activity_name") != "Admin group" || get(r, "metadata.uid") != e.EventID || get(r, "unmapped.altiward.member_count") != 0.0 {
		t.Errorf("record = %v", r)
	}
}

// A person listed twice is still one record, and no uid repeats.
func TestAdminGroupRecordsHaveDistinctUIDs(t *testing.T) {
	e := stored(t, "agent-admin-group-snapshot")
	e.Detail = maps.Clone(e.Detail)
	e.Detail["members"] = []any{"root", "root", "itadmin"}
	records := mapAllJSON(t, e)
	seen := map[any]bool{}
	for _, r := range records {
		uid := get(r, "metadata.uid")
		if seen[uid] {
			t.Errorf("uid %v repeats", uid)
		}
		seen[uid] = true
	}
	if len(records) != 3 {
		t.Errorf("%d records, want 2 members + 1 for the Mac", len(records))
	}
}

// An enrolment with another Mac's or another device's Intune device ID is High; the other outcomes keep the
// state's severity and say what Intune said.
func TestEnrollmentNamesTheIntuneCheck(t *testing.T) {
	mismatch := mapJSON(t, stored(t, "agent-enrollment-pending-mdm-mismatch"))
	if mismatch["severity"] != "High" || mismatch["is_alert"] != true ||
		mismatch["message"] != "C02XK0AAJGH5 enrolled a new key with another Mac's or another device's Intune device ID, waiting for approval" ||
		get(mismatch, "unmapped.altiward.detail.mdm_check") != "mismatch" || get(mismatch, "unmapped.altiward.detail.mdm_serial_known") != true {
		t.Fatalf("mismatch = %v", mismatch)
	}
	for _, tt := range []struct {
		example, check, severity, message string
	}{
		{"agent-enrollment-enrolled", "match", "Informational", "C02XK0AAJGH5 enrolled a new key (the Intune device ID sent matches the serial)"},
		{"agent-enrollment-enrolled", "not_sent", "Informational", "C02XK0AAJGH5 enrolled a new key (no Intune device ID sent)"},
		{"agent-enrollment-pending", "invalid_id", "Medium",
			"C02XK0AAJGH5 enrolled again with a new key, waiting for approval (the Intune device ID isn't valid)"},
		{"agent-enrollment-pending", "unknown_id", "Medium",
			"C02XK0AAJGH5 enrolled again with a new key, waiting for approval (Intune doesn't know the device ID)"},
		{"agent-enrollment-pending", "unavailable", "Medium",
			"C02XK0AAJGH5 enrolled again with a new key, waiting for approval (Intune couldn't be asked)"},
	} {
		t.Run(tt.check, func(t *testing.T) {
			e := stored(t, tt.example)
			e.Detail = maps.Clone(e.Detail)
			e.Detail["mdm_check"] = tt.check
			r := mapJSON(t, e)
			if r["severity"] != tt.severity || r["message"] != tt.message {
				t.Fatalf("severity %v, message %q; want %s, %q", r["severity"], r["message"], tt.severity, tt.message)
			}
		})
	}
}
