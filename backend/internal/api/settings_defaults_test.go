package api_test

import (
	"net/http"
	"testing"
)

func TestSettingsMissingOrNullApprovalKeepsSecureDefault(t *testing.T) {
	for name, body := range map[string]any{
		"missing": map[string]any{"silent_after_hours": 24},
		"null":    map[string]any{"reenrollment_requires_approval": nil, "silent_after_hours": 24},
	} {
		t.Run(name, func(t *testing.T) {
			h := newServer(t)
			// Even an earlier explicit opt-out must not make an omitted flag disable approval.
			if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"reenrollment_requires_approval": false}); rec.Code != http.StatusOK {
				t.Fatalf("opt-out: %d %s", rec.Code, rec.Body)
			}
			rec, out := do(t, h, "PUT", "/v1/settings", consoleToken, body)
			if rec.Code != http.StatusOK || out["reenrollment_requires_approval"] != true || out["silent_after_hours"] != float64(24) {
				t.Fatalf("secure replacement settings: %d %s", rec.Code, rec.Body)
			}
			rec, out = do(t, h, "GET", "/v1/settings", consoleToken, nil)
			if rec.Code != http.StatusOK || out["reenrollment_requires_approval"] != true {
				t.Fatalf("persisted settings: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestSettingsApprovalDefaultPreservesStrictValidation(t *testing.T) {
	for _, body := range []map[string]any{
		{"reenrollment_requires_approval": "false"},
		{"reenrollment_requires_approval": false, "unknown_setting": true},
	} {
		h := newServer(t)
		if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid settings accepted: %d %s", rec.Code, rec.Body)
		}
		if _, out := do(t, h, "GET", "/v1/settings", consoleToken, nil); out["reenrollment_requires_approval"] != true {
			t.Fatal("invalid input changed the approval default")
		}
	}
}

func TestRevokedSerialStillRequiresApprovalByDefault(t *testing.T) {
	h := newServer(t)
	old := enrollAgent(t, h, fixtureSerial)
	if rec, _ := do(t, h, "POST", "/v1/enrollments/"+old.deviceID+"/revoke", consoleToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	if rec, out := old.enroll(t, fixtureSerial); rec.Code != http.StatusOK || out["status"] != "revoked" || out["device_id"] != old.deviceID {
		t.Fatalf("revoked retry: %d %s", rec.Code, rec.Body)
	}
	replacement := enrollAgent(t, h, fixtureSerial)
	if replacement.status != "pending" {
		t.Fatalf("revoked serial re-enrolled as %s", replacement.status)
	}
	rec, out := replacement.post(t, batch(t, "elevation-granted"))
	wantCode(t, rec, out, http.StatusForbidden, "enrollment_pending")
}

// Approving every new Mac is off unless an admin turns it on, and a later save that leaves
// the flag out turns it off again.
func TestSettingsApproveEveryNewMacIsOffUnlessSet(t *testing.T) {
	h := newServer(t)
	if _, out := do(t, h, "GET", "/v1/settings", consoleToken, nil); out["new_mac_requires_approval"] != false {
		t.Fatalf("default settings = %v", out)
	}
	if rec, out := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"new_mac_requires_approval": true}); rec.Code != http.StatusOK ||
		out["new_mac_requires_approval"] != true || out["reenrollment_requires_approval"] != true {
		t.Fatalf("turn on: %d %s", rec.Code, rec.Body)
	}
	if rec, out := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"silent_after_hours": 24}); rec.Code != http.StatusOK ||
		out["new_mac_requires_approval"] != false {
		t.Fatalf("a save without the flag: %d %s", rec.Code, rec.Body)
	}
}

// With it on, a Mac's first key waits like a re-enrolment, and its event says pending with
// nothing to compare.
func TestApproveEveryNewMacHoldsTheFirstKey(t *testing.T) {
	h, st := newServerWithQueue(t)
	if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"new_mac_requires_approval": true}); rec.Code != http.StatusOK {
		t.Fatalf("turn on: %d %s", rec.Code, rec.Body)
	}
	a := &agent{h: h, key: newKey(t)}
	rec, out := a.enroll(t, fixtureSerial)
	if rec.Code != http.StatusCreated || out["status"] != "pending" {
		t.Fatalf("first enrolment: %d %s", rec.Code, rec.Body)
	}
	a.deviceID = out["device_id"].(string)
	rec, out = a.post(t, batch(t, "elevation-granted"))
	wantCode(t, rec, out, http.StatusForbidden, "enrollment_pending")
	got := queuedEnrollments(t, st)
	if len(got) != 1 || got[0].Detail["state"] != "pending" || got[0].Detail["previous_device_id"] != nil {
		t.Fatalf("events = %+v, want one pending enrolment with no previous key", got)
	}
}

// Settings stored before history_days existed read as the default period.
func TestSettingsHistoryDaysDefaultsToZero(t *testing.T) {
	h := newServer(t)
	if rec, out := do(t, h, "GET", "/v1/settings", consoleToken, nil); rec.Code != http.StatusOK || out["history_days"] != float64(0) {
		t.Fatalf("default settings: %d %s", rec.Code, rec.Body)
	}
	// A body that names other settings only leaves it at the default.
	if rec, out := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"silent_after_hours": 24}); rec.Code != http.StatusOK || out["history_days"] != float64(0) {
		t.Fatalf("put without history_days: %d %s", rec.Code, rec.Body)
	}
}
