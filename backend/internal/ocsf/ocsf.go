// Package ocsf maps core events to OCSF (https://schema.ocsf.io) for SIEM export.
//
//	elevation.granted           → User Access Management (3005), Assign Privileges (1)
//	elevation.revoked           → User Access Management (3005), Revoke Privileges (2)
//	admin.out_of_band_removed   → User Access Management (3005), Revoke Privileges (2), Low
//	elevation.expired_enforced  → User Access Management (3005), Revoke Privileges (2), Low, and the
//	                              rights_after_expiry Detection Finding (2004), Medium
//	elevation.overdue           → Detection Finding (2004), Create (1), Medium; High if removal failed
//	admin.out_of_band           → Detection Finding (2004), Create (1), High; an elevation.revoked
//	                              with trigger permanent_admin closes it (Resolved, Informational),
//	                              and one with trigger privileges_grant closes it (Other: "Replaced
//	                              by a Privileges grant", Informational); the process that added
//	                              the user, when Privileges' system extension logged it, is evidence.
//	                              Removing the rights closes it too (Other: "Rights removed",
//	                              Informational), in a second record after the revoke: an
//	                              admin.out_of_band_removed or elevation.revoked with source
//	                              out_of_band, a session and observed_admin false, unless orphan
//	persistence.detected        → Detection Finding (2004), Create (1), High; each new local
//	                              account is a finding of its own (High for an admin account),
//	                              and the rest of the persistence one more
//	agent.tamper                → Detection Finding (2004): Create when a check fails, a downgrade
//	                              is detected or Privileges blocks an attempt on itself; Close (Resolved, Informational) when it passes again,
//	                              or Close (Other: "No longer checked") when it stops applying
//	agent.silent                → Detection Finding (2004): Create, Medium, when a Mac stops checking
//	                              in; Close (Resolved, Informational) when it checks in again
//	admin.permanent_use         → Authentication (3002), Informational: Logon when a permanent admin
//	                              account signs in or uses an approval, sudo or su; Logoff when
//	                              the Mac saw the sign-in end. A sign-in's two records share
//	                              the use ID as metadata.correlation_uid
//	agent.health, activity      → not exported (inventory and v2 telemetry)
//	console actions             → API Activity (6003); see audit.go
//
// Altiward-specific fields the classes have no slot for go under unmapped.altiward.
package ocsf

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
)

const Version = "1.9.0"

// Record is one OCSF event, ready to serialise.
type Record map[string]any

const (
	SeverityInformational = 1
	SeverityLow           = 2
	SeverityMedium        = 3
	SeverityHigh          = 4
)

var severityNames = map[int]string{1: "Informational", 2: "Low", 3: "Medium", 4: "High"}

// Map converts a stored event into its records: none for event types that are not
// exported, and more than one for a persistence.detected that found new accounts.
// Every record has its own metadata.uid; the first one's is the event ID.
func Map(e store.StoredEvent, tenantID string) []Record {
	switch e.Type {
	case event.ElevationGranted, event.ElevationRevoked, event.ElevationExpiredEnforced, event.AdminOutOfBandRemoved:
		if trigger, _ := e.Detail["trigger"].(string); e.Type == event.ElevationRevoked {
			switch trigger {
			case "permanent_admin", "privileges_grant":
				return []Record{outOfBandClosed(e, tenantID, trigger)}
			}
		}
		if removesOutOfBand(e) {
			// The rights are gone but nobody explained them: the finding closes, as
			// "Rights removed", after the revoke.
			return []Record{userAccess(e, tenantID), outOfBandClosed(e, tenantID, "removed")}
		}
		if e.Type == event.ElevationExpiredEnforced {
			// Rights that outlived their expiry mean Privileges' timer failed or was stopped:
			// a finding even though Altiward removed them, as it is in alert mode.
			return []Record{userAccess(e, tenantID), finding(e, tenantID)}
		}
		return []Record{userAccess(e, tenantID)}
	case event.AdminOutOfBand, event.ElevationOverdue:
		return []Record{finding(e, tenantID)}
	case event.PersistenceDetected:
		return persistenceFindings(e, tenantID)
	case event.AgentTamper:
		return []Record{tamper(e, tenantID)}
	case event.AgentSilent:
		return []Record{silent(e, tenantID)}
	case event.AdminPermanentUse:
		return []Record{permanentUse(e, tenantID)}
	}
	return nil
}

// removesOutOfBand reports whether e ends a session of rights nobody granted by removing
// them: its user no longer holds admin, and it isn't an orphan revoke, which ends no session.
func removesOutOfBand(e store.StoredEvent) bool {
	if e.Type != event.ElevationRevoked && e.Type != event.AdminOutOfBandRemoved {
		return false
	}
	if e.Elevation == nil || e.Elevation.Source != event.SourceOutOfBand || e.SessionID == nil {
		return false
	}
	observedAdmin, ok := e.DetailBool("observed_admin")
	orphan, _ := e.DetailBool("orphan")
	return ok && !observedAdmin && !orphan
}

// UID is a record's metadata.uid.
func UID(r Record) string {
	m, _ := r["metadata"].(map[string]any)
	uid, _ := m["uid"].(string)
	return uid
}

func userAccess(e store.StoredEvent, tenantID string) Record {
	activityID, activity := 2, "Revoke Privileges"
	if e.Type == event.ElevationGranted {
		activityID, activity = 1, "Assign Privileges"
	}
	severity := SeverityInformational
	if e.Type == event.ElevationExpiredEnforced || e.Type == event.AdminOutOfBandRemoved {
		severity = SeverityLow
	}
	r := base(e, tenantID, 3005, "User Access Management", 3, "Identity & Access Management", activityID, activity, severity)
	r["privileges"] = []string{"admin"}
	r["status_id"], r["status"] = 1, "Success"
	r["message"] = accessMessage(e)
	if verified, ok := e.DetailBool("verified"); ok && !verified {
		// The hook's claim contradicted real admin-group membership: possible tampering.
		setSeverity(r, SeverityMedium)
		r["status_detail"] = "Reported change did not match local admin group membership"
	}
	return r
}

func accessMessage(e store.StoredEvent) string {
	user := userName(e)
	switch e.Type {
	case event.ElevationGranted:
		msg := fmt.Sprintf("%s was granted admin rights on %s", user, e.Device.Serial)
		if e.Elevation != nil && e.Elevation.Source == event.SourcePrivileges {
			msg += " via SAP Privileges"
		}
		if e.Elevation != nil && e.Elevation.Reason != nil {
			msg += ": " + *e.Elevation.Reason
		}
		return msg
	case event.ElevationExpiredEnforced:
		return fmt.Sprintf("Altiward removed %s's admin rights on %s after they outlived their expiry", user, e.Device.Serial)
	case event.AdminOutOfBandRemoved:
		return fmt.Sprintf("Altiward removed %s's admin rights on %s, which nobody granted", user, e.Device.Serial)
	}
	trigger, _ := e.Detail["trigger"].(string)
	// Inferred first, as the session reducer does: an inferred end says how the agent
	// noticed, not what the trigger alone would mean.
	if inferred, _ := e.DetailBool("inferred"); inferred {
		return fmt.Sprintf("%s no longer holds admin rights on %s (observed by heartbeat)", user, e.Device.Serial)
	}
	switch trigger {
	case "command":
		return fmt.Sprintf("%s's admin rights on %s were revoked from the Altiward console", user, e.Device.Serial)
	}
	return fmt.Sprintf("%s's admin rights on %s were revoked", user, e.Device.Serial)
}

// tamperChecks titles each agent.tamper check, with the severity of its failure.
var tamperChecks = map[string]struct {
	title    string
	severity int
}{
	"launch_daemon":                {"Altiward's LaunchDaemon was removed or changed", SeverityHigh},
	"code_signature":               {"Altiward's app bundle was modified", SeverityHigh},
	"settings_managed":             {"Altiward settings set outside MDM", SeverityMedium},
	"privileges_tamper_protection": {"SAP Privileges tamper protection is off", SeverityHigh},
	"privileges_hook":              {"SAP Privileges no longer reports to Altiward", SeverityHigh},
	"privileges_timer":             {"SAP Privileges' timer stopped while someone holds admin rights", SeverityHigh},
	"agent_version":                {"Altiward agent was downgraded", SeverityHigh},
	"privileges_blocked":           {"SAP Privileges blocked an attempt to tamper with it", SeverityHigh},
	"grant_claim":                  {"A SAP Privileges grant claim was refused or not confirmed by Privileges' log", SeverityHigh},
	"grant_confirmation":           {"Altiward can't confirm SAP Privileges grants against Privileges' log", SeverityMedium},
	"privileges_expiry_cap":        {"SAP Privileges grants have no expiry cap", SeverityMedium},
	"privileges_renewal":           {"SAP Privileges allows renewals that Altiward doesn't see", SeverityMedium},
	"privileges_give_back_hook":    {"SAP Privileges may not report give-backs to Altiward", SeverityMedium},
	"privileges_revoke_exclusions": {"SAP Privileges removes admin rights from a permanent admin account", SeverityLow},
}

// TamperSeverities names the severity a failure of each known tamper check is exported
// with, so the console can show the same word as the SIEM.
func TamperSeverities() map[string]string {
	out := make(map[string]string, len(tamperChecks))
	for check, info := range tamperChecks {
		out[check] = severityNames[info.severity]
	}
	return out
}

// outOfBandClosed closes the admin.out_of_band finding, which used the session ID as its
// uid, for the event that ends the out-of-band session; ended says how. While the rights
// stay, it is the only record: the user became a permanent admin ("permanent_admin"), so
// the rights are now expected, or a Privileges grant replaced the session
// ("privileges_grant"). A grant is reported by the hook, which the user can run by hand, so
// it closes the finding as Other, not Resolved. When the rights were removed ("removed"),
// it follows the revoke record and closes as Other, "Rights removed": they are gone, but
// nobody explained them.
func outOfBandClosed(e store.StoredEvent, tenantID, ended string) Record {
	const title = "Admin rights without a grant"
	r := base(e, tenantID, 2004, "Detection Finding", 2, "Findings", 3, "Close", SeverityInformational)
	var desc string
	switch ended {
	case "removed":
		trigger, _ := e.Detail["trigger"].(string)
		inferred, _ := e.DetailBool("inferred")
		switch {
		case e.Type == event.AdminOutOfBandRemoved:
			desc = fmt.Sprintf("Removed on %s: Altiward removed %s's admin rights, which nobody granted, after the grace period",
				e.Device.Serial, userName(e))
		case trigger == "command" && !inferred: // inferred first, as in accessMessage
			desc = fmt.Sprintf("Removed on %s: %s's admin rights, which nobody granted, were revoked from the Altiward console",
				e.Device.Serial, userName(e))
		default:
			desc = fmt.Sprintf("Removed on %s: %s no longer holds the admin rights nobody granted", e.Device.Serial, userName(e))
		}
		r["status_id"], r["status"] = 99, "Rights removed"
		r["metadata"].(map[string]any)["uid"] = e.EventID + "/finding" // a second record: its own uid
	case "privileges_grant":
		desc = fmt.Sprintf("Replaced on %s: a Privileges grant was reported for %s, who held admin rights without one",
			e.Device.Serial, userName(e))
		r["status_id"], r["status"] = 99, "Replaced by a Privileges grant"
	default:
		desc = fmt.Sprintf("Resolved on %s: %s is now a permanent admin, so their admin rights are expected",
			e.Device.Serial, userName(e))
		r["status_id"], r["status"] = 4, "Resolved"
	}
	uid := e.EventID
	if e.SessionID != nil {
		uid = *e.SessionID
	}
	ms := e.Timestamp.UnixMilli()
	r["finding_info"] = map[string]any{
		"uid": uid, "title": title, "desc": desc, "types": []string{"Privilege Escalation"},
		"created_time": ms, "first_seen_time": ms,
		"analytic": map[string]any{"name": "altiward.admin_out_of_band", "type_id": 1, "type": "Rule"},
	}
	r["message"] = desc
	if e.User != nil {
		r["observables"] = []map[string]any{{"name": "user.name", "type_id": 4, "type": "User Name", "value": e.User.LocalName}}
	}
	return r
}

// tamper maps an agent.tamper event. A failure and the recovery that resolves it share
// a finding uid, the device and check, so a SIEM can pair them; a one-off detection has its own.
func tamper(e store.StoredEvent, tenantID string) Record {
	check, _ := e.Detail["check"].(string)
	state, _ := e.Detail["state"].(string)
	problem, _ := e.Detail["problem"].(string)
	info, known := tamperChecks[check]
	if !known {
		info.title, info.severity = "Altiward tamper check failed: "+check, SeverityHigh
	}
	uid := e.Device.HardwareUUID + "/" + check
	if state == "detected" {
		uid = e.EventID
	}

	var r Record
	desc := fmt.Sprintf("%s on %s", info.title, e.Device.Serial)
	switch state {
	case "restored":
		desc = fmt.Sprintf("Resolved on %s: %s", e.Device.Serial, info.title)
		r = base(e, tenantID, 2004, "Detection Finding", 2, "Findings", 3, "Close", SeverityInformational)
		r["status_id"], r["status"] = 4, "Resolved"
	case "retired":
		// The check stopped applying while it failed (the Mac changed mode, or Privileges
		// went): close the finding without claiming it was fixed.
		desc = fmt.Sprintf("No longer checked on %s (%s): %s", e.Device.Serial, problem, info.title)
		r = base(e, tenantID, 2004, "Detection Finding", 2, "Findings", 3, "Close", SeverityInformational)
		r["status_id"], r["status"], r["status_detail"] = 99, "No longer checked", problem
	default:
		if problem != "" {
			desc += ": " + problem
		}
		r = base(e, tenantID, 2004, "Detection Finding", 2, "Findings", 1, "Create", info.severity)
		r["is_alert"] = true
		r["status_id"], r["status"] = 1, "New"
	}
	ms := e.Timestamp.UnixMilli()
	r["finding_info"] = map[string]any{
		"uid": uid, "title": info.title, "desc": desc, "types": []string{"Defense Evasion"},
		"created_time": ms, "first_seen_time": ms,
		"analytic": map[string]any{"name": "altiward.tamper." + check, "type_id": 1, "type": "Rule"},
	}
	r["message"] = desc
	return r
}

// silent maps an agent.silent event, raised by the backend. The resumed event closes the
// finding its silent event opened: both use the silent event's ID as the finding uid.
func silent(e store.StoredEvent, tenantID string) Record {
	const title = "Altiward agent stopped checking in"
	lastSeen, _ := e.Detail["last_seen_at"].(string)
	var r Record
	var uid, desc string
	if state, _ := e.Detail["state"].(string); state == event.SilentStateResumed {
		uid, _ = e.Detail["alert_event_id"].(string)
		desc = fmt.Sprintf("Resolved: %s checked in again at %s", e.Device.Serial, lastSeen)
		r = base(e, tenantID, 2004, "Detection Finding", 2, "Findings", 3, "Close", SeverityInformational)
		r["status_id"], r["status"] = 4, "Resolved"
	} else {
		uid = e.EventID
		desc = fmt.Sprintf("%s has not checked in since %s", e.Device.Serial, lastSeen)
		// A number is an int straight from the monitor and a float64 after a JSON round trip.
		var secs int
		switch v := e.Detail["silent_after_seconds"].(type) {
		case int:
			secs = v
		case float64:
			secs = int(v)
		}
		if secs > 0 {
			desc += fmt.Sprintf(" (the limit is %d hours)", secs/3600)
		}
		desc += "; the agent may have been removed, the Mac is off, or it can't reach the agent hostname " +
			"(check the hostname is reachable from outside your network)"
		r = base(e, tenantID, 2004, "Detection Finding", 2, "Findings", 1, "Create", SeverityMedium)
		r["is_alert"] = true
		r["status_id"], r["status"] = 1, "New"
	}
	ms := e.Timestamp.UnixMilli()
	r["finding_info"] = map[string]any{
		"uid": uid, "title": title, "desc": desc, "types": []string{"Defense Evasion"},
		"created_time": ms, "first_seen_time": ms,
		"analytic": map[string]any{"name": "altiward.agent_silent", "type_id": 1, "type": "Rule"},
	}
	r["message"] = desc
	return r
}

func finding(e store.StoredEvent, tenantID string) Record {
	title, desc, analytic := "Admin rights without a grant",
		fmt.Sprintf("%s holds admin rights on %s that nobody granted through SAP Privileges", userName(e), e.Device.Serial),
		"altiward.admin_out_of_band"
	severity := SeverityHigh
	types := []string{"Privilege Escalation"}
	var evidences []map[string]any
	switch e.Type {
	case event.PersistenceDetected:
		title, analytic, types = "New persistence during elevation", "altiward.persistence_detected", []string{"Persistence"}
		var what string
		what, evidences = persistence(e, persistenceItems(e, false))
		desc = fmt.Sprintf("New persistence appeared on %s while %s held admin rights: %s", e.Device.Serial, userName(e), what)
	case event.ElevationOverdue, event.ElevationExpiredEnforced:
		title, desc, analytic = "Admin rights outlived their expiry",
			fmt.Sprintf("%s still holds admin rights on %s after they expired", userName(e), e.Device.Serial),
			"altiward.rights_after_expiry"
		severity = SeverityMedium
		if failed, _ := e.DetailBool("enforcement_failed"); failed {
			// Policy said remove them and the agent could not.
			severity = SeverityHigh
			desc += "; Altiward could not remove them"
		}
		if e.Type == event.ElevationExpiredEnforced {
			desc = fmt.Sprintf("%s held admin rights on %s after they expired; Altiward removed them", userName(e), e.Device.Serial)
		}
	}
	if e.Type == event.AdminOutOfBand {
		// Privileges' system extension logged which process added them.
		if p, ok := e.Detail["instigator"].(map[string]any); ok {
			if exe, _ := p["executable"].(string); exe != "" {
				desc += "; added by " + exe
				proc := map[string]any{"file": map[string]any{"name": filepath.Base(exe), "path": exe, "type_id": 1, "type": "Regular File"}}
				if pid, ok := p["pid"].(float64); ok && pid > 0 {
					proc["pid"] = int(pid)
				}
				evidences = append(evidences, map[string]any{"process": proc})
			}
		}
	}
	uid := e.EventID
	switch {
	case e.Type == event.AdminOutOfBand && e.SessionID != nil:
		// One per session, and the session is what outOfBandClosed knows to close it by.
		uid = *e.SessionID
	case e.Type == event.ElevationExpiredEnforced:
		uid = e.EventID + "/finding" // the event's own ID is its revoke record's
	}
	r := base(e, tenantID, 2004, "Detection Finding", 2, "Findings", 1, "Create", severity)
	if e.Type == event.ElevationExpiredEnforced {
		r["metadata"].(map[string]any)["uid"] = uid // a second record: its own uid
	}
	ms := e.Timestamp.UnixMilli()
	r["finding_info"] = map[string]any{
		"uid":             uid,
		"title":           title,
		"desc":            desc,
		"types":           types,
		"created_time":    ms,
		"first_seen_time": ms,
		"analytic":        map[string]any{"name": analytic, "type_id": 1, "type": "Rule"},
	}
	if len(evidences) > 0 {
		r["evidences"] = evidences
	}
	r["is_alert"] = true
	r["status_id"], r["status"] = 1, "New"
	r["message"] = desc
	if e.User != nil {
		r["observables"] = []map[string]any{{"name": "user.name", "type_id": 4, "type": "User Name", "value": e.User.LocalName}}
	}
	return r
}

// persistenceFindings maps a persistence.detected event. A new local account is how
// someone keeps admin rights for good, so each one is its own finding a SOC can alert on;
// the rest of what was found, if anything, is one more.
func persistenceFindings(e store.StoredEvent, tenantID string) []Record {
	var records []Record
	truncated, _ := e.Detail["truncated"].(float64)
	if rest := persistenceItems(e, false); len(rest) > 0 || truncated > 0 || len(persistenceItems(e, true)) == 0 {
		records = append(records, finding(e, tenantID))
	}
	for _, f := range persistenceItems(e, true) {
		records = append(records, accountCreated(e, tenantID, f))
	}
	return records
}

// persistenceItems are a persistence.detected event's findings: the new local accounts
// when accounts is true, and everything else when it is false.
func persistenceItems(e store.StoredEvent, accounts bool) []map[string]any {
	raw, _ := e.Detail["findings"].([]any)
	var items []map[string]any
	for _, r := range raw {
		f, ok := r.(map[string]any)
		if !ok {
			continue
		}
		kind, _ := f["kind"].(string)
		change, _ := f["change"].(string)
		if (kind == "local_account" && change != "modified") == accounts {
			items = append(items, f)
		}
	}
	return items
}

// accountCreated is the finding for one new local account. The agent compares snapshots,
// so it knows the account appeared while the user held admin rights, not who made it.
func accountCreated(e store.StoredEvent, tenantID string, f map[string]any) Record {
	name, _ := f["name"].(string)
	admin, _ := f["admin"].(bool)
	title, kind, severity := "Local account created", "account", SeverityMedium
	if admin {
		title, kind, severity = "Admin account created", "admin account", SeverityHigh
	}
	desc := fmt.Sprintf("New %s %s appeared on %s while %s held admin rights", kind, name, e.Device.Serial, userName(e))
	uid := e.EventID + "/account/" + name

	r := base(e, tenantID, 2004, "Detection Finding", 2, "Findings", 1, "Create", severity)
	r["metadata"].(map[string]any)["uid"] = uid
	ms := e.Timestamp.UnixMilli()
	r["finding_info"] = map[string]any{
		"uid":             uid,
		"title":           title,
		"desc":            desc,
		"types":           []string{"Persistence"},
		"created_time":    ms,
		"first_seen_time": ms,
		"analytic":        map[string]any{"name": "altiward.account_created", "type_id": 1, "type": "Rule"},
		"attacks": []map[string]any{{
			"tactic":        map[string]any{"uid": "TA0003", "name": "Persistence"},
			"technique":     map[string]any{"uid": "T1136", "name": "Create Account"},
			"sub_technique": map[string]any{"uid": "T1136.001", "name": "Local Account"},
		}},
	}
	account := map[string]any{"name": name}
	if uid, ok := f["uid"].(float64); ok {
		account["uid"] = fmt.Sprintf("%d", int64(uid))
	}
	r["evidences"] = []map[string]any{{"user": account}}
	r["is_alert"] = true
	r["status_id"], r["status"] = 1, "New"
	r["message"] = desc
	observables := []map[string]any{{"name": "evidences.user.name", "type_id": 4, "type": "User Name", "value": name}}
	if e.User != nil {
		observables = append(observables, map[string]any{"name": "user.name", "type_id": 4, "type": "User Name", "value": e.User.LocalName})
	}
	r["observables"] = observables
	altiward := r["unmapped"].(map[string]any)["altiward"].(map[string]any)
	altiward["account"] = f
	return r
}

// persistence summarises findings from a persistence.detected event for the finding's
// description, and turns each into an evidence artifact: the file, or the new account, so
// a SIEM can join it to the EDR's record of the same file.
func persistence(e store.StoredEvent, findings []map[string]any) (string, []map[string]any) {
	var parts []string
	var evidences []map[string]any
	for _, f := range findings {
		str := func(k string) string { s, _ := f[k].(string); return s }
		change := "new"
		if str("change") == "modified" {
			change = "changed"
		}
		path := str("path")
		var part string
		switch str("kind") {
		case "launch_daemon":
			part = fmt.Sprintf("%s LaunchDaemon %s", change, path)
		case "launch_agent":
			part = fmt.Sprintf("%s LaunchAgent %s", change, path)
		case "sudoers":
			part = fmt.Sprintf("%s sudoers rules in %s", change, path)
		case "ssh_authorized_key":
			part = fmt.Sprintf("%s SSH key for %s", change, str("user"))
		case "local_account":
			part = fmt.Sprintf("%s account %s", change, str("name"))
			user := map[string]any{"name": str("name")}
			if uid, ok := f["uid"].(float64); ok {
				user["uid"] = fmt.Sprintf("%d", int64(uid))
			}
			evidences = append(evidences, map[string]any{"user": user})
		case "remote_access":
			part = map[string]string{"remote_login": "Remote Login", "screen_sharing": "Screen Sharing"}[str("service")]
			if part == "" {
				part = str("service")
			}
			part += " turned on"
		default:
			part = fmt.Sprintf("%s %s", change, str("kind"))
		}
		parts = append(parts, part)
		if path != "" {
			evidences = append(evidences, map[string]any{
				"file": map[string]any{"name": filepath.Base(path), "path": path, "type_id": 1, "type": "Regular File"},
			})
		}
	}
	if len(parts) == 0 {
		parts = []string{"details not reported"}
	}
	const shown = 3
	what := strings.Join(parts[:min(shown, len(parts))], ", ")
	more := max(0, len(parts)-shown)
	if n, ok := e.Detail["truncated"].(float64); ok {
		more += int(n)
	}
	if more > 0 {
		what += fmt.Sprintf(", and %d more", more)
	}
	return what, evidences
}

func base(e store.StoredEvent, tenantID string, classUID int, className string, categoryUID int, categoryName string,
	activityID int, activityName string, severity int) Record {
	metadata := map[string]any{
		"version":     Version,
		"uid":         e.EventID,
		"tenant_uid":  tenantID,
		"logged_time": e.ReceivedAt.UnixMilli(),
		"product":     map[string]any{"name": "Altiward", "vendor_name": "Altiward", "version": e.Device.AgentVersion},
	}
	if e.SessionID != nil {
		metadata["correlation_uid"] = *e.SessionID
	}
	if e.Delayed {
		metadata["labels"] = []string{"delayed"}
	}
	r := Record{
		"class_uid":     classUID,
		"class_name":    className,
		"category_uid":  categoryUID,
		"category_name": categoryName,
		"activity_id":   activityID,
		"activity_name": activityName,
		"type_uid":      classUID*100 + activityID,
		"type_name":     className + ": " + activityName,
		"time":          e.Timestamp.UnixMilli(),
		"metadata":      metadata,
		"device": map[string]any{
			"uid":     e.Device.HardwareUUID,
			"hw_info": map[string]any{"serial_number": e.Device.Serial},
			"os":      map[string]any{"name": "macOS", "type": "macOS", "type_id": 300, "version": e.Device.OSVersion},
		},
		"unmapped": map[string]any{"altiward": altiwardFields(e)},
	}
	if e.User != nil {
		user := map[string]any{"name": e.User.LocalName}
		if e.User.UPN != nil {
			user["email_addr"] = *e.User.UPN
		}
		r["user"] = user
	}
	setSeverity(r, severity)
	return r
}

func altiwardFields(e store.StoredEvent) map[string]any {
	f := map[string]any{"event_type": string(e.Type), "detail": e.Detail}
	if id, ok := e.Detail["command_id"].(string); ok {
		f["command_id"] = id
	}
	if e.Elevation != nil {
		f["source"] = string(e.Elevation.Source)
		if e.Elevation.Reason != nil {
			f["reason"] = *e.Elevation.Reason
		}
		if e.Elevation.Expires != nil {
			f["expires_time"] = e.Elevation.Expires.UnixMilli()
		}
	}
	return f
}

func setSeverity(r Record, s int) {
	r["severity_id"], r["severity"] = s, severityNames[s]
}

func userName(e store.StoredEvent) string {
	if e.User == nil {
		return "unknown user"
	}
	if e.User.UPN != nil {
		return *e.User.UPN
	}
	return e.User.LocalName
}
