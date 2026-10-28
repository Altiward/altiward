package ocsf

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Altiward/altiward/backend/internal/store"
)

// Console actions map to API Activity (6003): the console's API is what was called.
//
//	revoke_session, revoke_device          → Create (1): a revoke command was issued
//	approve_enrollment, revoke_enrollment  → Update (3)
//	change_settings                        → Update (3), Low: it changes tenant policy
//	test_export                            → Create (1): a test event for the SIEM
//	retry_exports                          → Update (3): a sink's waiting exports retried now
//	end_console_session                    → Delete (4), Low: an admin ended someone's sign-in
//	sign_in, sign_out                      → Authentication (3002), Logon (1) or Logoff (2),
//	                                         for single sign-on
//	sign_in by a console token             → Authentication (3002), Logon (1); Low for break-glass
//
// The actor is a console token's fingerprint (token:3f2a9c1b) until single sign-on names
// a person. The event type in unmapped.altiward is "console." and the action.

// AuditEventType is the event type a console action is exported as.
func AuditEventType(a store.AuditEntry) string { return "console." + a.Action }

// MapAudit converts a console action.
func MapAudit(a store.AuditEntry) Record {
	if a.Action == store.AuditSignIn || a.Action == store.AuditSignOut {
		return signIn(a)
	}
	activityID, activity, severity := 3, "Update", SeverityInformational
	resource := map[string]any{"uid": a.Target}
	serial := detailString(a.Detail, "serial")
	switch a.Action {
	case store.AuditRevokeSession:
		activityID, activity = 1, "Create"
		resource["type"] = "Elevation session"
	case store.AuditRevokeDevice:
		activityID, activity = 1, "Create"
		resource["type"] = "Mac"
	case store.AuditApproveEnrollment, store.AuditRevokeEnrollment:
		resource["type"] = "Enrollment"
	case store.AuditChangeSettings:
		severity = SeverityLow
		resource["type"] = "Settings"
	case store.AuditTestExport:
		activityID, activity = 1, "Create"
		resource["type"] = "SIEM export"
	case store.AuditRetryExports:
		resource["type"] = "SIEM export"
	case store.AuditEndConsoleSession:
		activityID, activity, severity = 4, "Delete", SeverityLow
		resource["type"] = "Console session"
	}
	if serial != "" {
		resource["name"] = serial
	}
	ms := a.At.UnixMilli()
	r := Record{
		"class_uid":     6003,
		"class_name":    "API Activity",
		"category_uid":  6,
		"category_name": "Application Activity",
		"activity_id":   activityID,
		"activity_name": activity,
		"type_uid":      6003*100 + activityID,
		"type_name":     "API Activity: " + activity,
		"time":          ms,
		"metadata": map[string]any{
			"version":     Version,
			"uid":         a.ID,
			"tenant_uid":  a.TenantID,
			"logged_time": ms,
			"product":     map[string]any{"name": "Altiward", "vendor_name": "Altiward"},
		},
		"actor":        map[string]any{"user": map[string]any{"name": a.Actor}},
		"api":          map[string]any{"operation": a.Action, "service": map[string]any{"name": "Altiward console"}},
		"src_endpoint": map[string]any{"name": "Altiward console"},
		"resources":    []map[string]any{resource},
		"status_id":    1,
		"status":       "Success",
		"message":      auditMessage(a),
		"unmapped": map[string]any{"altiward": map[string]any{
			"event_type": AuditEventType(a), "action": a.Action, "target": a.Target, "detail": a.Detail,
		}},
	}
	setSeverity(r, severity)
	return r
}

// signIn maps signing in to the console, or out of it, through single sign-on, and each
// hour a console token is used (a sign_in with method "token").
func signIn(a store.AuditEntry) Record {
	activityID, activity := 1, "Logon"
	protocolID, protocol, severity := 4, "OpenID", SeverityInformational
	msg := fmt.Sprintf("%s signed in to the Altiward console", a.Actor)
	if detailString(a.Detail, "method") == "token" {
		// A console token is a bearer token: no OCSF protocol names it, so it is Other (99).
		protocolID, protocol = 99, "Bearer token"
		kind := "console"
		if strings.HasPrefix(a.Actor, "break-glass:") {
			kind, severity = "break-glass", SeverityLow
		}
		msg += " with a " + kind + " token"
	}
	if role := detailString(a.Detail, "role"); role != "" {
		msg += " as " + role
	}
	if a.Action == store.AuditSignOut {
		activityID, activity = 2, "Logoff"
		msg = fmt.Sprintf("%s signed out of the Altiward console", a.Actor)
	}
	ms := a.At.UnixMilli()
	user := map[string]any{"name": a.Actor, "email_addr": a.Actor}
	if !strings.Contains(a.Actor, "@") {
		delete(user, "email_addr")
	}
	r := Record{
		"class_uid":     3002,
		"class_name":    "Authentication",
		"category_uid":  3,
		"category_name": "Identity & Access Management",
		"activity_id":   activityID,
		"activity_name": activity,
		"type_uid":      3002*100 + activityID,
		"type_name":     "Authentication: " + activity,
		"time":          ms,
		"metadata": map[string]any{
			"version":     Version,
			"uid":         a.ID,
			"tenant_uid":  a.TenantID,
			"logged_time": ms,
			"product":     map[string]any{"name": "Altiward", "vendor_name": "Altiward"},
		},
		"user":             user,
		"service":          map[string]any{"name": "Altiward console"},
		"auth_protocol_id": protocolID,
		"auth_protocol":    protocol,
		"status_id":        1,
		"status":           "Success",
		"message":          msg,
		"unmapped": map[string]any{"altiward": map[string]any{
			"event_type": AuditEventType(a), "action": a.Action, "target": a.Target, "detail": a.Detail,
		}},
	}
	setSeverity(r, severity)
	return r
}

func auditMessage(a store.AuditEntry) string {
	serial := detailString(a.Detail, "serial")
	if serial == "" {
		serial = a.Target
	}
	user := detailString(a.Detail, "user")
	switch a.Action {
	case store.AuditRevokeSession:
		if user == "" {
			user = "a user"
		}
		return fmt.Sprintf("%s revoked the admin session of %s on %s from the Altiward console", a.Actor, user, serial)
	case store.AuditRevokeDevice:
		if user == "" {
			user = "everyone but permanent admins"
		}
		return fmt.Sprintf("%s revoked admin rights for %s on %s from the Altiward console", a.Actor, user, serial)
	case store.AuditApproveEnrollment:
		return fmt.Sprintf("%s approved the enrollment of %s", a.Actor, serial)
	case store.AuditRevokeEnrollment:
		return fmt.Sprintf("%s revoked the enrollment of %s", a.Actor, serial)
	case store.AuditChangeSettings:
		return fmt.Sprintf("%s changed Altiward settings: %s", a.Actor, settingsChange(a.Detail))
	case store.AuditTestExport:
		return fmt.Sprintf("%s sent a test event from the Altiward console to check the SIEM connection", a.Actor)
	case store.AuditRetryExports:
		return fmt.Sprintf("%s retried the exports waiting for %s from the Altiward console", a.Actor, a.Target)
	case store.AuditEndConsoleSession:
		return fmt.Sprintf("%s ended %s's console sign-in from the Altiward console", a.Actor, a.Target)
	}
	return fmt.Sprintf("%s did %s on %s in the Altiward console", a.Actor, a.Action, a.Target)
}

// settingsChange lists the settings whose value changed, as "name: before → after".
func settingsChange(detail map[string]any) string {
	before, _ := detail["previous"].(map[string]any)
	after, _ := detail["settings"].(map[string]any)
	var changes []string
	for k, v := range after {
		was, ok := before[k]
		if !ok {
			was = "unset"
		}
		if fmt.Sprint(was) != fmt.Sprint(v) {
			changes = append(changes, fmt.Sprintf("%s: %v → %v", k, was, v))
		}
	}
	if len(changes) == 0 {
		return "no change"
	}
	slices.Sort(changes)
	return strings.Join(changes, "; ")
}

func detailString(detail map[string]any, key string) string {
	s, _ := detail[key].(string)
	return s
}
