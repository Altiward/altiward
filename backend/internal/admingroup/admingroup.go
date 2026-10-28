// Package admingroup raises agent.admin_group: a Mac's admin group, which the server sends
// to the SIEM so that it keeps who was in the group after the health readings that recorded
// it expire. It decides from a new reading and the group last reported for the Mac; the
// stores keep that report (devices.admin_group) and store what it raises.
package admingroup

import (
	"encoding/hex"
	"encoding/json"
	"regexp"
	"slices"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
)

// Report is the admin group last reported for a Mac, by a changed or snapshot event: what
// the stores keep in devices.admin_group.
type Report struct {
	// Members is the reading's admin_members, everyone in the group, sorted.
	Members []string `json:"members"`
	// PermanentAdmins is the reading's configured standing admins, sorted. It is not
	// membership: a change to it alone raises nothing.
	PermanentAdmins []string `json:"permanent_admins"`
	// HealthEventID and AsOf are the reading's event ID and its time by the Mac's clock.
	HealthEventID string    `json:"health_event_id"`
	AsOf          time.Time `json:"as_of"`
	// Truncated is how many names the lists left out, so a snapshot of the report says so
	// as the event that made it did.
	Truncated int `json:"truncated"`
}

// FromHealth is the group a health reading reports. Names that are empty or longer than
// event.MaxNameLength are dropped and duplicates removed, and each list is sorted and cut
// to event.MaxAdminGroupPeople names. truncated counts the names the cut left out, as
// r.Truncated does.
func FromHealth(e event.Event) (r Report, truncated int) {
	members, cutMembers := names(e.Detail["admin_members"])
	permanent, cutPermanent := names(e.Detail["permanent_admins"])
	r = Report{
		Members: members, PermanentAdmins: permanent, HealthEventID: e.EventID, AsOf: e.Timestamp,
		Truncated: cutMembers + cutPermanent,
	}
	return r, r.Truncated
}

// ID is the event ID of an agent.admin_group event, a name-based UUID of what it reports.
// The installation's secret, which is never shown, makes it unguessable: the organisation
// and serial aren't secret, so without it root on one Mac could send events with another
// Mac's IDs and have that Mac's records dropped as duplicates.
func ID(secret []byte, tenantID, serial, key string) string {
	return event.RaisedID(hex.EncodeToString(secret) + "/" + tenantID + "/" + serial + "/admin_group/" + key)
}

// OnHealth is what a newly stored health reading raises, given the group last reported for
// its Mac (prev, nil when none has been). The first reading raises a snapshot, so the SIEM
// isn't told that everyone was just added. A reading whose members differ raises changed,
// with who was added (each with the session the reading's open_sessions has for them, when
// there is one) and who was removed. ok is false when the members are the same, whatever
// else changed. next is the group last reported after the reading: prev when nothing is
// raised. The caller passes readings in the order they arrive, not by the Mac's clock, which
// a Mac's clock pushed ahead would otherwise freeze. The event's timestamp is now, the
// server's time, and its device is the reading's.
func OnHealth(prev *Report, health event.Event, tenantID string, secret []byte, now time.Time) (raised event.Event, next Report, ok bool) {
	next, _ = FromHealth(health)
	if prev == nil {
		d := detail(event.AdminGroupSnapshot, next, next.Truncated)
		return raise(secret, tenantID, "first/"+health.EventID, health.Device, now, d), next, true
	}
	before := set(prev.Members)
	after := set(next.Members)
	var addedNames, removed []string
	for _, name := range next.Members {
		if !before[name] {
			addedNames = append(addedNames, name)
		}
	}
	for _, name := range prev.Members {
		if !after[name] {
			removed = append(removed, name)
		}
	}
	if len(addedNames) == 0 && len(removed) == 0 {
		return event.Event{}, *prev, false
	}
	// The group last reported was read back from the store, so sort and cut it too.
	slices.Sort(removed)
	removed, cutRemoved := capped(slices.Compact(removed))
	addedNames, cutAdded := capped(addedNames)
	sessions := openSessions(health.Detail["open_sessions"])
	added := make([]any, 0, len(addedNames))
	for _, name := range addedNames {
		a := map[string]any{"name": name}
		if s, ok := sessions[name]; ok {
			a["session_id"] = s.id
			if s.source != "" {
				a["source"] = s.source
			}
		}
		added = append(added, a)
	}
	d := detail(event.AdminGroupChanged, next, next.Truncated+cutAdded+cutRemoved)
	d["added"], d["removed"] = added, list(removed)
	return raise(secret, tenantID, "changed/"+health.EventID, health.Device, now, d), next, true
}

// Refreshed is the group last reported, prev, updated with a newer reading whose members
// are the same (OnHealth raised nothing for it): the reading's standing admins, event ID,
// time and truncated count, with the members as they were compared. The stores keep it, so
// that a daily snapshot says which reading it comes from and what that reading showed, not
// those of the last change.
func Refreshed(prev Report, health event.Event) Report {
	next, _ := FromHealth(health)
	next.Members = prev.Members
	return next
}

// Snapshot is the daily snapshot of the group last reported for a Mac, r, keyed by the
// day it is for (the database's UTC date, YYYY-MM-DD), so a Mac has one a day. d is the
// Mac's last known identity and versions.
func Snapshot(r Report, d event.Device, tenantID, day string, secret []byte, now time.Time) event.Event {
	return raise(secret, tenantID, "snapshot/"+day, d, now, detail(event.AdminGroupSnapshot, r, r.Truncated))
}

// raise is the event, its detail fitted to the size an event may have.
func raise(secret []byte, tenantID, key string, d event.Device, now time.Time, detail map[string]any) event.Event {
	fit(detail)
	return event.Event{
		SchemaVersion: event.SchemaVersion,
		EventID:       ID(secret, tenantID, d.Serial, key),
		Type:          event.AgentAdminGroup,
		Timestamp:     now.UTC(),
		Device:        d,
		Detail:        detail,
	}
}

// detail is the detail every agent.admin_group event carries, with values as JSON decodes
// them ([]any, float64), so it reads the same from either store and to Validate. A changed
// event adds added and removed.
func detail(state string, r Report, truncated int) map[string]any {
	return map[string]any{
		"state":            state,
		"members":          list(r.Members),
		"permanent_admins": list(r.PermanentAdmins),
		"health_event_id":  r.HealthEventID,
		"as_of":            r.AsOf.UTC().Format(time.RFC3339Nano),
		"truncated":        float64(truncated),
	}
}

// fit leaves people out of the detail's lists, from the end of the longest, until it is
// small enough to store (event.MaxDetailBytes), and counts them in truncated. Only lists of
// names near the length limit, or that JSON escapes, come near it, and mostly in a changed
// event, which can carry the same people in two lists and their predecessors in a third.
func fit(d map[string]any) {
	for {
		b, err := json.Marshal(d)
		if err != nil {
			return
		}
		over := len(b) - event.MaxDetailBytes
		longest := ""
		for _, k := range []string{"members", "permanent_admins", "added", "removed"} {
			if l, ok := d[k].([]any); ok && (longest == "" || len(l) > len(d[longest].([]any))) {
				longest = k
			}
		}
		l, _ := d[longest].([]any)
		if over <= 0 || len(l) == 0 {
			return
		}
		n := len(l)
		for n > 0 && over > 0 {
			item, _ := json.Marshal(l[n-1])
			over -= len(item) + 1 // and the comma before it
			n--
		}
		d[longest] = l[:n]
		d["truncated"] = d["truncated"].(float64) + float64(len(l)-n)
	}
}

// names reads a list of names from a reading's detail, a JSON array as the API decodes it.
func names(v any) (out []string, cut int) {
	items, _ := v.([]any)
	out = []string{}
	for _, item := range items {
		if s, ok := item.(string); ok && s != "" && len(s) <= event.MaxNameLength {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return capped(slices.Compact(out))
}

func capped(l []string) ([]string, int) {
	if len(l) <= event.MaxAdminGroupPeople {
		return l, 0
	}
	return slices.Clone(l[:event.MaxAdminGroupPeople]), len(l) - event.MaxAdminGroupPeople
}

func list(l []string) []any {
	out := make([]any, len(l))
	for i, s := range l {
		out[i] = s
	}
	return out
}

func set(l []string) map[string]bool {
	out := make(map[string]bool, len(l))
	for _, s := range l {
		out[s] = true
	}
	return out
}

type openSession struct{ id, source string }

var sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// openSessions reads a reading's open_sessions ([{user, session_id, source}]) by user,
// keeping only entries whose session ID is a lower-case UUID, as every session ID is, and
// a source only when it is one the schema names. The agent keeps one per user; if a
// reading had two, the first wins.
func openSessions(v any) map[string]openSession {
	out := map[string]openSession{}
	items, _ := v.([]any)
	for _, item := range items {
		entry, _ := item.(map[string]any)
		user, _ := entry["user"].(string)
		id, _ := entry["session_id"].(string)
		if _, seen := out[user]; seen || user == "" || !sessionIDPattern.MatchString(id) {
			continue
		}
		s := openSession{id: id}
		switch source, _ := entry["source"].(string); event.Source(source) {
		case event.SourcePrivileges, event.SourceOutOfBand:
			s.source = source
		}
		out[user] = s
	}
	return out
}
