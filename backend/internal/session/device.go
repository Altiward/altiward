package session

import (
	"slices"
	"strings"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
)

// Device is the fleet-inventory record for one Mac and its current admins.
type Device struct {
	TenantID          string    `json:"tenant_id"`
	Serial            string    `json:"serial"`
	HardwareUUID      string    `json:"hardware_uuid"`
	OSVersion         string    `json:"os_version"`
	AgentVersion      string    `json:"agent_version"`
	PrivilegesVersion *string   `json:"privileges_version"`
	FirstSeenAt       time.Time `json:"first_seen_at"`
	LastSeenAt        time.Time `json:"last_seen_at"` // newest event, by the Mac's clock
	// LastReceivedAt is when the server last received an event from the Mac, by the
	// server's clock, so a Mac whose clock is wrong isn't silent or late by mistake. Zero
	// when unknown; see CheckedInAt.
	LastReceivedAt  time.Time      `json:"last_received_at,omitzero"`
	LastHealthAt    *time.Time     `json:"last_health_at"`
	AdminMembers    []string       `json:"admin_members"`
	PermanentAdmins []string       `json:"permanent_admins"` // never demoted or revoked by the agent
	QueueDepth      *int           `json:"queue_depth"`
	Privileges      map[string]any `json:"privileges"`
	// Integrity is the newest agent.health's tamper check results, check → passing.
	// Nil until the agent reports it.
	Integrity map[string]bool `json:"integrity"`
	// PersistenceUnreadable are the places the agent's newest persistence snapshot
	// couldn't read: findings there go unreported. Empty when it read them all; nil when
	// unknown (before the agent's first snapshot).
	PersistenceUnreadable []string `json:"persistence_unreadable"`
	// RecentTamper are the newest agent.tamper events, newest first, at most MaxRecentAlerts.
	RecentTamper []TamperAlert `json:"recent_tamper"`
	// RecentPermanentUses are recent uses of the permanent admin accounts: every open
	// sign-in first (at most MaxRecentAlerts, newest start first), then the newest
	// MaxRecentAlerts ended and single uses, newest first by PermanentUse.NewestAt. Nil in
	// state stored before agent 0.3.0 reported them; nil means none recorded.
	RecentPermanentUses []PermanentUse `json:"recent_permanent_uses"`
	// Silence is the newest agent.silent the backend raised for this Mac, or nil if none.
	// The Mac is reported silent while its State is silent.
	Silence *Silence `json:"silence"`
}

// Silence is the backend noticing a Mac stopped checking in, or that it came back.
type Silence struct {
	EventID    string    `json:"event_id"`
	At         time.Time `json:"at"`           // when the backend raised it
	State      string    `json:"state"`        // silent or resumed
	LastSeenAt time.Time `json:"last_seen_at"` // the Mac's last check-in when it was raised
}

// CheckedInAt is when the Mac last checked in, by the server's clock when it is known.
func (d Device) CheckedInAt() time.Time {
	if !d.LastReceivedAt.IsZero() {
		return d.LastReceivedAt
	}
	return d.LastSeenAt
}

// Received records that the server received e at at. The latest time wins, so the order
// events arrive in doesn't matter. Events the backend raises itself aren't a check-in.
func (d *Device) Received(e event.Event, at time.Time) {
	if e.Type.IsServerRaised() || !at.After(d.LastReceivedAt) {
		return
	}
	d.LastReceivedAt = at
}

// Silent reports whether an agent.silent alert is open for this Mac.
func (d Device) Silent() bool { return d.Silence != nil && d.Silence.State == event.SilentStateSilent }

// TamperAlert is one change in a tamper check: failed, restored, retired (a failing check
// that stopped applying), or a one-off detected.
type TamperAlert struct {
	EventID string    `json:"event_id"`
	At      time.Time `json:"at"`
	Check   string    `json:"check"`
	State   string    `json:"state"`
	Problem *string   `json:"problem"`
}

// PermanentUse is one use of a permanent admin account (admin.permanent_use). A sign-in
// is one entry from its started event to its ended one; a prompt, sudo or su is a single.
type PermanentUse struct {
	UseID       string     `json:"use_id"`
	Account     string     `json:"account"`
	Method      string     `json:"method"`
	State       string     `json:"state"` // started, ended or single
	StartedAt   time.Time  `json:"started_at"`
	EndedAt     *time.Time `json:"ended_at"`
	LastAt      *time.Time `json:"last_at"` // the newest use grouped into a single; nil otherwise
	OnSessionOf *string    `json:"on_session_of"`
	RemoteHost  *string    `json:"remote_host"`
	Right       *string    `json:"right"`
	RunAs       *string    `json:"run_as"` // the user a sudo ran as; nil when unknown
	Count       int        `json:"count"`  // single uses grouped into this entry; 1 for a sign-in
}

// NewestAt is the newest time the use is known for: when it ended, else the newest use
// grouped into it, else when it began.
func (u PermanentUse) NewestAt() time.Time {
	switch {
	case u.EndedAt != nil:
		return *u.EndedAt
	case u.LastAt != nil:
		return *u.LastAt
	}
	return u.StartedAt
}

// MaxRecentAlerts is how many tamper alerts a device keeps for the console, and how many
// open sign-ins and how many other uses of permanent admins; the SIEM gets them all.
const MaxRecentAlerts = 20

func NewDevice(tenantID, serial string) Device {
	return Device{
		TenantID: tenantID, Serial: serial, AdminMembers: []string{}, PermanentAdmins: []string{},
		RecentTamper: []TamperAlert{}, RecentPermanentUses: []PermanentUse{},
	}
}

// Apply updates the device from any event; the newest reading wins. Events the backend
// raises itself are not a check-in, so they leave the seen times and the versions alone.
// Only agent.silent changes the device, by its Silence.
func (d *Device) Apply(e event.Event) {
	if e.Type.IsServerRaised() {
		if e.Type == event.AgentSilent {
			d.applySilence(e)
		}
		return
	}
	if d.FirstSeenAt.IsZero() || e.Timestamp.Before(d.FirstSeenAt) {
		d.FirstSeenAt = e.Timestamp
	}
	if !e.Timestamp.Before(d.LastSeenAt) {
		d.LastSeenAt = e.Timestamp
		d.HardwareUUID = e.Device.HardwareUUID
		d.OSVersion = e.Device.OSVersion
		d.AgentVersion = e.Device.AgentVersion
		d.PrivilegesVersion = e.Device.PrivilegesVersion
	}
	if e.Type == event.AgentTamper {
		d.addTamper(e)
		return
	}
	if e.Type == event.AdminPermanentUse {
		d.addPermanentUse(e)
		return
	}
	if e.Type != event.AgentHealth || (d.LastHealthAt != nil && e.Timestamp.Before(*d.LastHealthAt)) {
		return
	}
	t := e.Timestamp
	d.LastHealthAt = &t
	d.AdminMembers = stringList(e.Detail["admin_members"])
	d.PermanentAdmins = stringList(e.Detail["permanent_admins"])
	if n, ok := e.Detail["queue_depth"].(float64); ok {
		depth := int(n)
		d.QueueDepth = &depth
	}
	if p, ok := e.Detail["privileges"].(map[string]any); ok {
		d.Privileges = p
	}
	if checks, ok := e.Detail["integrity"].(map[string]any); ok {
		d.Integrity = map[string]bool{}
		for name, v := range checks {
			if passing, ok := v.(bool); ok {
				d.Integrity[name] = passing
			}
		}
	}
	d.PersistenceUnreadable = nil
	if places, ok := e.Detail["persistence_unreadable"].([]any); ok {
		d.PersistenceUnreadable = stringList(places)
	}
}

func (d *Device) applySilence(e event.Event) {
	if d.Silence != nil && (e.Timestamp.Before(d.Silence.At) ||
		e.Timestamp.Equal(d.Silence.At) && e.EventID <= d.Silence.EventID) {
		return
	}
	s := &Silence{EventID: e.EventID, At: e.Timestamp}
	s.State, _ = e.Detail["state"].(string)
	if v, ok := e.Detail["last_seen_at"].(string); ok {
		s.LastSeenAt, _ = time.Parse(time.RFC3339Nano, v)
	}
	d.Silence = s
}

func (d *Device) addTamper(e event.Event) {
	a := TamperAlert{EventID: e.EventID, At: e.Timestamp}
	a.Check, _ = e.Detail["check"].(string)
	a.State, _ = e.Detail["state"].(string)
	if p, ok := e.Detail["problem"].(string); ok {
		a.Problem = &p
	}
	d.RecentTamper = keepRecent(d.RecentTamper, a, MaxRecentAlerts, func(a TamperAlert) (string, time.Time) {
		return a.EventID, a.At
	})
}

// addPermanentUse keeps e's use by its use ID. Open sign-ins (started) are kept apart from
// the cap on the rest, so any number of newer uses can't push an open sign-in off the list:
// up to MaxRecentAlerts of them, newest start first. Ended and single uses are capped at
// MaxRecentAlerts, newest first by NewestAt. An ended replaces the started it ends, and a
// started is dropped while its ended is listed, so the order they arrive in doesn't matter,
// with two exceptions that need more uses than a Mac sees between two heartbeats:
//   - A started that arrives after its ended was trimmed (MaxRecentAlerts finished uses
//     newer than it arrived in between) is listed as open. The agent sends oldest first,
//     so a started reaching the server after its ended is already rare.
//   - With more than MaxRecentAlerts sign-ins open at once, the oldest open one is trimmed,
//     and stays off the list even if newer ones end later.
func (d *Device) addPermanentUse(e event.Event) {
	u := PermanentUse{Count: 1}
	u.UseID, _ = e.Detail["use_id"].(string)
	u.Method, _ = e.Detail["method"].(string)
	u.State, _ = e.Detail["state"].(string)
	if e.User != nil {
		u.Account = e.User.LocalName
	}
	u.StartedAt = detailTime(e.Detail["started"])
	if u.StartedAt.IsZero() {
		u.StartedAt = e.Timestamp
	}
	if t := detailTime(e.Detail["ended"]); !t.IsZero() {
		u.EndedAt = &t
	}
	if t := detailTime(e.Detail["last"]); !t.IsZero() {
		u.LastAt = &t
	}
	u.OnSessionOf = detailString(e.Detail["on_session_of"])
	u.RemoteHost = detailString(e.Detail["remote_host"])
	u.Right = detailString(e.Detail["right"])
	u.RunAs = detailString(e.Detail["run_as"])
	if n, ok := e.Detail["count"].(float64); ok && n >= 1 {
		u.Count = int(n)
	}
	var open, done []PermanentUse
	for _, x := range d.RecentPermanentUses {
		if x.State == event.UseStateStarted {
			open = append(open, x)
		} else {
			done = append(done, x)
		}
	}
	byID := func(x PermanentUse) bool { return x.UseID == u.UseID }
	switch {
	case u.State == event.UseStateStarted:
		if !slices.ContainsFunc(done, byID) {
			open = keepRecent(open, u, MaxRecentAlerts, func(u PermanentUse) (string, time.Time) {
				return u.UseID, u.StartedAt
			})
		}
	default:
		if u.State == event.UseStateEnded {
			open = slices.DeleteFunc(open, byID)
		}
		done = keepRecent(done, u, MaxRecentAlerts, func(u PermanentUse) (string, time.Time) {
			return u.UseID, u.NewestAt()
		})
	}
	d.RecentPermanentUses = append(append(make([]PermanentUse, 0, len(open)+len(done)), open...), done...)
}

func detailString(v any) *string {
	if s, ok := v.(string); ok && s != "" {
		return &s
	}
	return nil
}

func detailTime(v any) time.Time {
	s, _ := v.(string)
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// keepRecent adds item unless its event ID is already there, and keeps the newest max by
// time, then event ID: the same result whatever order the events arrive in.
func keepRecent[T any](list []T, item T, max int, key func(T) (string, time.Time)) []T {
	id, _ := key(item)
	if slices.ContainsFunc(list, func(x T) bool { xid, _ := key(x); return xid == id }) {
		return list
	}
	list = append(list, item)
	slices.SortFunc(list, func(a, b T) int {
		aid, at := key(a)
		bid, bt := key(b)
		if c := bt.Compare(at); c != 0 {
			return c
		}
		return strings.Compare(bid, aid)
	})
	if len(list) > max {
		list = list[:max]
	}
	return list
}

func stringList(v any) []string {
	out := []string{}
	items, _ := v.([]any)
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
