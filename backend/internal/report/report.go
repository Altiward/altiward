// Package report works out the console's overview from the session and device state the
// reducers produce, never raw events. It is pure: the same state always gives the same
// figures.
package report

import (
	"cmp"
	"maps"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/release"
	"github.com/Altiward/altiward/backend/internal/session"
	"github.com/Altiward/altiward/backend/internal/store"
)

const (
	// TopN is how many people and Macs the overview ranks.
	TopN = 5
	// EarlyBy is how long before its expiry an elevation must end to count as given back early.
	EarlyBy = time.Minute
	// BehindAfter is how long the oldest queued event waits before a SIEM counts as behind.
	BehindAfter = 15 * time.Minute
)

// ValidDays reports whether days is a period the overview offers.
func ValidDays(days int) bool { return days == 7 || days == 30 || days == 90 }

// Input is what the overview is worked out from.
type Input struct {
	Now  time.Time
	Days int
	// Sessions holds every session that is open or started in the period (Store.ReportSessions).
	Sessions []session.Session
	Devices  []store.Device
	Sinks    []store.ExportBacklog // each configured SIEM's export status
}

type Overview struct {
	GeneratedAt time.Time `json:"generated_at"`
	Days        int       `json:"days"`
	Since       time.Time `json:"since"`
	Now         Now       `json:"now"`
	Period      Period    `json:"period"`
	Health      Health    `json:"health"`
}

// Now is who holds admin rights and what needs a look. Admins are counted per open
// session, as Admins now lists them, so one person on two Macs counts twice.
type Now struct {
	// Admins is every open session.
	Admins            int `json:"admins"`
	Privileges        int `json:"privileges"`
	WithoutGrant      int `json:"without_grant"`
	PastExpiry        int `json:"past_expiry"` // open sessions held past their expiry
	MacsFailingChecks int `json:"macs_failing_checks"`
	MacsSilent        int `json:"macs_silent"` // an agent.silent alert is open
}

// Period covers the sessions that started in the last Days days.
type Period struct {
	Elevations   int         `json:"elevations"`
	WithoutGrant int         `json:"without_grant"`
	BucketDays   int         `json:"bucket_days"` // 1, or 7 for periods over 30 days
	Buckets      []Bucket    `json:"buckets"`     // from Since; the last one ends now and may be short
	Durations    []Duration  `json:"durations"`   // Privileges
	TopUsers     []UserCount `json:"top_users"`
	TopMacs      []MacCount  `json:"top_macs"`
}

type Bucket struct {
	Start        time.Time `json:"start"`
	Privileges   int       `json:"privileges"`
	WithoutGrant int       `json:"without_grant"`
}

// Duration compares time held with time allowed, over a source's elevations that ended
// and had an expiry. Medians are nil when there were none.
type Duration struct {
	Source               event.Source `json:"source"`
	Ended                int          `json:"ended"`
	GivenBackEarly       int          `json:"given_back_early"` // ended at least EarlyBy before expiry
	MedianHeldSeconds    *float64     `json:"median_held_seconds"`
	MedianAllowedSeconds *float64     `json:"median_allowed_seconds"`
}

// UserCount is one person's elevations. Name is the UPN when known; otherwise it is the
// local name and Serial its Mac, since the same local name on two Macs is two people.
type UserCount struct {
	Name       string `json:"name"`
	Serial     string `json:"serial,omitempty"`
	Elevations int    `json:"elevations"`
	Macs       int    `json:"macs"`
}

type MacCount struct {
	Serial     string `json:"serial"`
	Elevations int    `json:"elevations"`
	People     int    `json:"people"`
}

type Health struct {
	Macs           int            `json:"macs"`
	AgentsOutdated int            `json:"agents_outdated"`
	AgentVersions  []AgentVersion `json:"agent_versions"` // newest first; unreadable last
	Sinks          []Sink         `json:"sinks"`
}

type AgentVersion struct {
	Version   string `json:"version"`
	Macs      int    `json:"macs"`
	Supported bool   `json:"supported"`
}

// Sink is a SIEM's export status. State is delivering, behind (the oldest queued event
// has waited BehindAfter), failing (queued events have failed) or idle (nothing sent yet).
type Sink struct {
	store.ExportBacklog
	State string `json:"state"`
}

func Build(in Input) Overview {
	since := in.Now.Add(-time.Duration(in.Days) * 24 * time.Hour)
	return Overview{
		GeneratedAt: in.Now, Days: in.Days, Since: since,
		Now:    now(in),
		Period: period(in, since),
		Health: health(in),
	}
}

func now(in Input) Now {
	var n Now
	for _, s := range in.Sessions {
		if !s.Open() {
			continue
		}
		n.Admins++
		switch s.Source {
		case event.SourcePrivileges:
			n.Privileges++
		case event.SourceOutOfBand:
			n.WithoutGrant++
		}
		if s.ExpiresAt != nil && in.Now.After(*s.ExpiresAt) {
			n.PastExpiry++
		}
	}
	for _, d := range in.Devices {
		if slices.Contains(slices.Collect(maps.Values(d.Integrity)), false) {
			n.MacsFailingChecks++
		}
		if d.Silent() {
			n.MacsSilent++
		}
	}
	return n
}

func period(in Input, since time.Time) Period {
	p := Period{BucketDays: 1, TopUsers: []UserCount{}, TopMacs: []MacCount{}}
	if in.Days > 30 {
		p.BucketDays = 7
	}
	size := time.Duration(p.BucketDays) * 24 * time.Hour
	n := int(math.Ceil(float64(in.Days) / float64(p.BucketDays)))
	p.Buckets = make([]Bucket, n)
	for i := range p.Buckets {
		p.Buckets[i].Start = since.Add(time.Duration(i) * size)
	}

	var durations durationSample // Privileges grants only
	type userKey struct{ name, serial string }
	users := map[userKey]map[string]bool{} // → Macs
	userCounts := map[userKey]int{}
	macs := map[string]map[userKey]bool{} // → people
	macCounts := map[string]int{}
	for _, s := range in.Sessions {
		if s.StartedAt == nil || s.StartedAt.Before(since) || s.StartedAt.After(in.Now) {
			continue
		}
		p.Elevations++
		b := &p.Buckets[min(int(s.StartedAt.Sub(since)/size), n-1)]
		switch s.Source {
		case event.SourcePrivileges:
			b.Privileges++
			durations.add(s)
		case event.SourceOutOfBand:
			b.WithoutGrant++
			p.WithoutGrant++
		}

		k := userKey{name: s.LocalUser, serial: s.DeviceSerial}
		if s.UPN != nil && *s.UPN != "" {
			k = userKey{name: *s.UPN}
		}
		if users[k] == nil {
			users[k] = map[string]bool{}
		}
		users[k][s.DeviceSerial] = true
		userCounts[k]++
		if macs[s.DeviceSerial] == nil {
			macs[s.DeviceSerial] = map[userKey]bool{}
		}
		macs[s.DeviceSerial][k] = true
		macCounts[s.DeviceSerial]++
	}

	p.Durations = []Duration{durations.result(event.SourcePrivileges)}
	for k, n := range userCounts {
		p.TopUsers = append(p.TopUsers, UserCount{Name: k.name, Serial: k.serial, Elevations: n, Macs: len(users[k])})
	}
	slices.SortFunc(p.TopUsers, func(a, b UserCount) int {
		return cmp.Or(b.Elevations-a.Elevations, strings.Compare(a.Name, b.Name), strings.Compare(a.Serial, b.Serial))
	})
	for serial, n := range macCounts {
		p.TopMacs = append(p.TopMacs, MacCount{Serial: serial, Elevations: n, People: len(macs[serial])})
	}
	slices.SortFunc(p.TopMacs, func(a, b MacCount) int {
		return cmp.Or(b.Elevations-a.Elevations, strings.Compare(a.Serial, b.Serial))
	})
	p.TopUsers = p.TopUsers[:min(len(p.TopUsers), TopN)]
	p.TopMacs = p.TopMacs[:min(len(p.TopMacs), TopN)]
	return p
}

type durationSample struct {
	held, allowed []float64
	early         int
}

func (d *durationSample) add(s session.Session) {
	if s.EndedAt == nil || s.ExpiresAt == nil {
		return
	}
	d.held = append(d.held, s.EndedAt.Sub(*s.StartedAt).Seconds())
	d.allowed = append(d.allowed, s.ExpiresAt.Sub(*s.StartedAt).Seconds())
	if !s.EndedAt.After(s.ExpiresAt.Add(-EarlyBy)) {
		d.early++
	}
}

func (d *durationSample) result(source event.Source) Duration {
	return Duration{Source: source, Ended: len(d.held), GivenBackEarly: d.early,
		MedianHeldSeconds: median(d.held), MedianAllowedSeconds: median(d.allowed)}
}

func median(xs []float64) *float64 {
	if len(xs) == 0 {
		return nil
	}
	s := slices.Sorted(slices.Values(xs))
	m := s[len(s)/2]
	if len(s)%2 == 0 {
		m = (s[len(s)/2-1] + s[len(s)/2]) / 2
	}
	return &m
}

func health(in Input) Health {
	h := Health{Macs: len(in.Devices), AgentVersions: []AgentVersion{}, Sinks: []Sink{}}
	byVersion := map[string]int{}
	for _, d := range in.Devices {
		byVersion[d.AgentVersion]++
	}
	for v, n := range byVersion {
		supported := release.AgentSupported(v)
		if !supported {
			h.AgentsOutdated += n
		}
		h.AgentVersions = append(h.AgentVersions, AgentVersion{Version: v, Macs: n, Supported: supported})
	}
	sort.Slice(h.AgentVersions, func(i, j int) bool { return newer(h.AgentVersions[i].Version, h.AgentVersions[j].Version) })
	for _, b := range in.Sinks {
		h.Sinks = append(h.Sinks, Sink{ExportBacklog: b, State: sinkState(b, in.Now)})
	}
	return h
}

func sinkState(b store.ExportBacklog, now time.Time) string {
	switch {
	case b.Failing > 0:
		return "failing"
	case b.Pending > 0 && b.OldestAt != nil && now.Sub(*b.OldestAt) >= BehindAfter:
		return "behind"
	case b.Pending == 0 && b.LastDeliveredAt == nil:
		return "idle"
	}
	return "delivering"
}

// newer orders versions newest first by their numbers, with ones that can't be read last.
func newer(a, b string) bool {
	va, okA := numbers(a)
	vb, okB := numbers(b)
	if okA != okB {
		return okA
	}
	if !okA {
		return a < b
	}
	if c := slices.Compare(va, vb); c != 0 {
		return c > 0
	}
	return a < b
}

func numbers(version string) ([]int, bool) {
	parts := strings.Split(version, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}
