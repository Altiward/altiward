package ocsf

import (
	"fmt"
	"slices"
	"strconv"
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
//	expire_history                         → Delete (4): the server removed history past the
//	                                         period it keeps
//	remove_device                          → Delete (4): the server removed a Mac that stopped
//	                                         checking in before that period; the keys it
//	                                         revoked with it are revoke_enrollment entries
//	sign_in, sign_out                      → Authentication (3002), Logon (1) or Logoff (2),
//	                                         for single sign-on
//	sign_in by a console token             → Authentication (3002), Logon (1); Low for break-glass
//
// The actor is a console token's fingerprint (token:3f2a9c1b) until single sign-on names
// a person. What the server does by itself has store.ServerActor as its actor, which maps
// to a System user of the Altiward server, the source of the entry. The event type in
// unmapped.altiward is "console." and the action.

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
	case store.AuditExpireHistory:
		activityID, activity = 4, "Delete"
		resource["type"] = "History"
	case store.AuditRemoveDevice:
		activityID, activity = 4, "Delete"
		resource["type"] = "Mac"
		serial = a.Target
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
	if a.Actor == store.ServerActor {
		r["actor"] = map[string]any{"app_name": "Altiward server",
			"user": map[string]any{"name": a.Actor, "type": "System", "type_id": 3}}
		r["src_endpoint"] = map[string]any{"name": "Altiward server"}
		r["api"] = map[string]any{"operation": a.Action, "service": map[string]any{"name": "Altiward server"}}
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
	case store.AuditExpireHistory:
		return historyExpiry(a.Detail)
	case store.AuditRemoveDevice:
		return macRemoval(a.Target, a.Detail)
	}
	return fmt.Sprintf("%s did %s on %s in the Altiward console", a.Actor, a.Action, a.Target)
}

// historyExpiry says what an expire_history entry removed, and why.
func historyExpiry(detail map[string]any) string {
	why := map[string]string{
		store.HistoryReasonDefaultSIEM: "the default with a SIEM connected",
		store.HistoryReasonSet:         "the period an admin set",
	}[detailString(detail, "reason")]
	if why == "" {
		why = detailString(detail, "reason")
	}
	counts, _ := detail["counts"].(map[string]any)
	removed := []string{
		plural(counts["events"], "event", "events"),
		plural(counts["sessions"], "session", "sessions"),
		plural(counts["commands"], "command", "commands"),
	}
	if macs := fmt.Sprint(counts["macs"]); macs != "0" && macs != "<nil>" {
		removed = append(removed, plural(counts["macs"], "Mac", "Macs"))
	}
	return fmt.Sprintf("Altiward removed history received before %s, past the %v days it keeps (%s): %s",
		detailString(detail, "before"), detail["days"], why, strings.Join(removed, ", "))
}

// macRemoval says which Mac a remove_device entry removed, why, and what went with it.
func macRemoval(serial string, detail map[string]any) string {
	counts, _ := detail["counts"].(map[string]any)
	removed := []string{
		plural(counts["events"], "event", "events"),
		plural(counts["sessions"], "session", "sessions"),
		plural(counts["commands"], "command", "commands"),
	}
	return fmt.Sprintf("Altiward removed the Mac %s, which last checked in at %s, past the %v days of history it keeps, with %s",
		serial, detailString(detail, "last_check_in"), detail["days"], strings.Join(removed, ", "))
}

// plural is n with the noun for its number. n is a JSON number, or nil for none. A float64
// is written out in full: fmt would put a count in the millions in exponent form.
func plural(n any, one, many string) string {
	s := fmt.Sprint(n)
	switch v := n.(type) {
	case nil:
		s = "0"
	case float64:
		s = strconv.FormatFloat(v, 'f', -1, 64)
	}
	if s == "1" {
		return "1 " + one
	}
	return s + " " + many
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
