package ocsf

import (
	"fmt"
	"slices"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
)

// adminGroup maps an agent.admin_group event, raised by the server from a Mac's health
// report. The people are Group Management records of their own, so a SIEM can alert on one
// person joining the group and join them to the EDR's record of the same account:
//
//   - changed: Add User (3) for each person added, with the session that granted the rights as
//     metadata.correlation_uid when there was one, and Remove User (4) for each removed
//   - snapshot: Other (99), "Admin group member", for each member
//
// Then one record for the Mac, Other (99), "Admin group", with both lists and their
// counts, sent even when the group is empty. A person's record carries only that person,
// not the lists. The first record's uid is the event ID; the others derive theirs from it.
func adminGroup(e store.StoredEvent, tenantID string) []Record {
	state, _ := e.Detail["state"].(string)
	members := detailStrings(e.Detail, "members")
	permanent := detailStrings(e.Detail, "permanent_admins")
	serial := e.Device.Serial

	type entry struct {
		suffix string
		record Record
	}
	var entries []entry
	seen := map[string]bool{}
	once := func(suffix string) bool {
		if seen[suffix] {
			return false
		}
		seen[suffix] = true
		return true
	}

	var added []map[string]any
	var removed []string
	if state == event.AdminGroupChanged {
		added = detailObjects(e.Detail, "added")
		removed = detailStrings(e.Detail, "removed")
		for _, a := range added {
			name, _ := a["name"].(string)
			if name == "" || !once("/added/"+name) {
				continue
			}
			r := adminGroupPerson(e, tenantID, name, 3, "Add User")
			r["message"] = fmt.Sprintf("%s was added to the admin group on %s", name, serial)
			altiward := r["unmapped"].(map[string]any)["altiward"].(map[string]any)
			if session, _ := a["session_id"].(string); session != "" {
				r["metadata"].(map[string]any)["correlation_uid"] = session
			}
			if source, _ := a["source"].(string); source != "" {
				altiward["source"] = source
			}
			entries = append(entries, entry{"/added/" + name, r})
		}
		for _, name := range removed {
			if name == "" || !once("/removed/"+name) {
				continue
			}
			r := adminGroupPerson(e, tenantID, name, 4, "Remove User")
			r["message"] = fmt.Sprintf("%s was removed from the admin group on %s", name, serial)
			entries = append(entries, entry{"/removed/" + name, r})
		}
	} else {
		for _, name := range members {
			if name == "" || !once("/member/"+name) {
				continue
			}
			isPermanent := slices.Contains(permanent, name)
			r := adminGroupPerson(e, tenantID, name, 99, "Admin group member")
			r["message"] = fmt.Sprintf("%s is in the admin group on %s", name, serial)
			if isPermanent {
				r["message"] = fmt.Sprintf("%s is in the admin group on %s, as a permanent admin", name, serial)
			}
			r["unmapped"].(map[string]any)["altiward"].(map[string]any)["permanent"] = isPermanent
			entries = append(entries, entry{"/member/" + name, r})
		}
	}

	mac := base(e, tenantID, 3006, "Group Management", 3, "Identity & Access Management", 99, "Admin group", SeverityInformational)
	mac["group"] = map[string]any{"name": "admin"}
	mac["status_id"], mac["status"] = 1, "Success"
	altiward := mac["unmapped"].(map[string]any)["altiward"].(map[string]any)
	altiward["member_count"] = len(members)
	altiward["permanent_admin_count"] = len(permanent)
	if state == event.AdminGroupChanged {
		altiward["added_count"] = len(added)
		altiward["removed_count"] = len(removed)
		mac["message"] = fmt.Sprintf("The admin group on %s changed: %d added, %d removed, %d in it now",
			serial, len(added), len(removed), len(members))
	} else {
		mac["message"] = fmt.Sprintf("The admin group on %s has %d members, %d of them permanent admins",
			serial, len(members), len(permanent))
	}
	entries = append(entries, entry{"/group", mac})

	records := make([]Record, len(entries))
	for i, en := range entries {
		uid := e.EventID
		if i > 0 {
			uid += en.suffix
		}
		en.record["metadata"].(map[string]any)["uid"] = uid
		records[i] = en.record
	}
	return records
}

// adminGroupPerson is the record for one person in the admin group. It carries the
// event's state and when the Mac reported it, not the lists, which are the Mac's record's.
func adminGroupPerson(e store.StoredEvent, tenantID, name string, activityID int, activity string) Record {
	r := base(e, tenantID, 3006, "Group Management", 3, "Identity & Access Management", activityID, activity, SeverityInformational)
	r["group"] = map[string]any{"name": "admin"}
	r["user"] = map[string]any{"name": name}
	r["status_id"], r["status"] = 1, "Success"
	r["observables"] = []map[string]any{{"name": "user.name", "type_id": 4, "type": "User Name", "value": name}}
	detail := map[string]any{}
	for _, k := range []string{"state", "health_event_id", "as_of"} {
		if v, ok := e.Detail[k]; ok {
			detail[k] = v
		}
	}
	r["unmapped"].(map[string]any)["altiward"].(map[string]any)["detail"] = detail
	return r
}

// detailStrings is a detail field that is a list of strings, from the store (a JSON
// array) or a server that raised the event in Go.
func detailStrings(detail map[string]any, key string) []string {
	switch v := detail[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// detailObjects is a detail field that is a list of objects.
func detailObjects(detail map[string]any, key string) []map[string]any {
	switch v := detail[key].(type) {
	case []map[string]any:
		return v
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}
