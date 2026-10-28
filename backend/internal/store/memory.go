package store

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Altiward/altiward/backend/internal/admingroup"
	"github.com/Altiward/altiward/backend/internal/command"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/session"
)

// Memory is an in-process Store for tests and local development. Not durable.
type Memory struct {
	mu       sync.Mutex
	sinks    []string
	events   map[key]StoredEvent
	order    []key // insertion order, for timelines
	sessions map[key]session.Session
	devices  map[key]session.Device
	// retired is when an admin retired each device in devices (see Device.RetiredAt).
	retired map[key]time.Time
	// adminGroups is the admin group last reported for each device in devices that has
	// one (devices.admin_group in Postgres). It records what the server sent, not what the
	// Mac reported, so like retired it sits beside the reduced state.
	adminGroups map[key]admingroup.Report

	exports  []*memExport
	nextID   int64
	creds    map[string]DeviceCredential // by device ID
	settings map[string]TenantSettings
	// delivered is each tenant and sink's last delivery.
	delivered map[[2]string]time.Time
	commands  map[string]command.Command // by command ID
	watchers  commandWatchers
	audit     []AuditEntry // in the order recorded

	// staleUseReported is when a use of each stale key was last reported, by device ID.
	staleUseReported map[string]time.Time

	consoleSessions map[string]ConsoleSession // by token hash
	// coverage is each SIEM sink's covered-from time (export_sinks in Postgres).
	coverage map[string]time.Time
	// installation starts when the store does: a memory store is a new server each run.
	installation Installation

	mdm map[key]*memMDM // by tenant and source
}

type key struct{ tenant, id string }

type memExport struct {
	ExportItem
	queuedAt    time.Time
	nextAttempt time.Time
	leasedUntil time.Time
	lastError   string
	done        bool
}

// NewMemory returns an empty store that queues every ingested event for each sink.
func NewMemory(exportSinks []string) *Memory {
	return &Memory{
		sinks:     exportSinks,
		events:    map[key]StoredEvent{},
		sessions:  map[key]session.Session{},
		devices:   map[key]session.Device{},
		retired:   map[key]time.Time{},
		creds:     map[string]DeviceCredential{},
		settings:  map[string]TenantSettings{},
		delivered: map[[2]string]time.Time{},
		commands:  map[string]command.Command{},

		staleUseReported: map[string]time.Time{},

		adminGroups:     map[key]admingroup.Report{},
		consoleSessions: map[string]ConsoleSession{},
		coverage:        map[string]time.Time{},
		installation:    newMemoryInstallation(),

		mdm: map[key]*memMDM{},
	}
}

func (m *Memory) Ingest(_ context.Context, tenantID string, events []event.Event, receivedAt time.Time) (IngestResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ingest(tenantID, events, receivedAt)
}

// ingest expects m.mu held, so a contest can store its alert with it.
func (m *Memory) ingest(tenantID string, events []event.Event, receivedAt time.Time) (IngestResult, error) {
	res := IngestResult{Accepted: []string{}, Duplicate: []string{}}
	// Validate the whole batch before committing any event, device or export state.
	// BindOwner changes only value ownership fields on these session copies.
	owners := map[key]session.Session{}
	seen := map[string]bool{}
	for _, e := range events {
		if _, duplicate := m.events[key{tenantID, e.EventID}]; duplicate || seen[e.EventID] {
			continue
		}
		seen[e.EventID] = true
		if e.SessionID == nil {
			continue
		}
		sk := key{tenantID, *e.SessionID}
		s, ok := owners[sk]
		if !ok {
			s, ok = m.sessions[sk]
			if !ok {
				s = session.New(tenantID, *e.SessionID)
			}
		}
		if err := s.BindOwner(e); err != nil {
			return res, fmt.Errorf("event %s: %w", e.EventID, err)
		}
		owners[sk] = s
	}
	for _, e := range events {
		k := key{tenantID, e.EventID}
		if _, dup := m.events[k]; dup {
			res.Duplicate = append(res.Duplicate, e.EventID)
			continue
		}
		m.store(tenantID, e, receivedAt)

		if e.SessionID != nil {
			sk := key{tenantID, *e.SessionID}
			s, ok := m.sessions[sk]
			if !ok {
				s = session.New(tenantID, *e.SessionID)
			}
			// The preflight and reduction share this mutex, so ownership cannot change.
			_ = s.Apply(e)
			m.sessions[sk] = s
		}
		// An event the server raised is no check-in, so it doesn't make a Mac it hasn't heard
		// from appear as a device. It is stored and exported all the same.
		dk := key{tenantID, e.Device.Serial}
		if d, ok := m.devices[dk]; ok || !e.Type.IsServerRaised() {
			if !ok {
				d = session.NewDevice(tenantID, e.Device.Serial)
			}
			d.Apply(e)
			d.Received(e, receivedAt)
			m.devices[dk] = d
		}
		res.Accepted = append(res.Accepted, e.EventID)
		if e.Type == event.AgentHealth {
			m.raiseAdminGroup(tenantID, e, receivedAt, &res)
		}
	}
	return res, nil
}

// store keeps e and queues it for every sink. It expects m.mu held.
func (m *Memory) store(tenantID string, e event.Event, receivedAt time.Time) {
	k := key{tenantID, e.EventID}
	stored := StoredEvent{Event: e, ReceivedAt: receivedAt}
	m.events[k] = stored
	m.order = append(m.order, k)
	for _, sink := range m.sinks {
		m.nextID++
		m.exports = append(m.exports, &memExport{
			ExportItem:  ExportItem{ID: m.nextID, TenantID: tenantID, Sink: sink, Event: stored},
			queuedAt:    receivedAt,
			nextAttempt: receivedAt,
		})
	}
}

// raiseAdminGroup is Postgres.raiseAdminGroup: it stores what a newly stored health
// reading raises, compared with the group last reported, and records it. It expects m.mu
// held, so readings are compared in the order they arrive.
func (m *Memory) raiseAdminGroup(tenantID string, health event.Event, receivedAt time.Time, res *IngestResult) {
	if len(m.installation.RaisedIDSecret) == 0 {
		return
	}
	dk := key{tenantID, health.Device.Serial}
	var prev *admingroup.Report
	if r, ok := m.adminGroups[dk]; ok {
		prev = &r
	}
	raised, next, ok := admingroup.OnHealth(prev, health, tenantID, m.installation.RaisedIDSecret, receivedAt)
	if !ok {
		// Nothing to raise, but the report still takes the reading's details, so a daily
		// snapshot says which reading it comes from.
		next = admingroup.Refreshed(*prev, health)
	} else if raised.Validate(receivedAt) != nil {
		return
	} else if had, taken := m.events[key{tenantID, raised.EventID}]; !taken {
		m.store(tenantID, raised, receivedAt)
	} else if had.Type != raised.Type || had.Device.Serial != raised.Device.Serial {
		res.RaisedIDTaken = append(res.RaisedIDTaken, raised.EventID)
		return
	}
	m.adminGroups[dk] = next
}

func (m *Memory) ListSessions(_ context.Context, tenantID string, f SessionFilter) ([]session.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []session.Session{}
	for k, s := range m.sessions {
		if k.tenant != tenantID || !matches(s, f) {
			continue
		}
		out = append(out, s)
	}
	sortSessions(out)
	if limit := clampLimit(f.Limit); len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) ReportSessions(_ context.Context, tenantID string, since time.Time) ([]session.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []session.Session{}
	for k, s := range m.sessions {
		if k.tenant == tenantID && (s.Open() || s.StartedAt != nil && !s.StartedAt.Before(since)) {
			out = append(out, s)
		}
	}
	sortSessions(out)
	return out, nil
}

func matches(s session.Session, f SessionFilter) bool {
	if f.DeviceSerial != "" && s.DeviceSerial != f.DeviceSerial {
		return false
	}
	if f.LocalUser != "" && s.LocalUser != f.LocalUser {
		return false
	}
	if f.OpenOnly && !s.Open() {
		return false
	}
	if f.Since != nil && (s.StartedAt == nil || s.StartedAt.Before(*f.Since)) {
		return false
	}
	if f.Until != nil && (s.StartedAt == nil || !s.StartedAt.Before(*f.Until)) {
		return false
	}
	return true
}

// sortSessions orders newest first; sessions with no start (only a revoke seen) sort last.
func sortSessions(ss []session.Session) {
	sort.SliceStable(ss, func(i, j int) bool {
		a, b := ss[i].StartedAt, ss[j].StartedAt
		switch {
		case a == nil:
			return false
		case b == nil:
			return true
		case !a.Equal(*b):
			return a.After(*b)
		}
		return ss[i].SessionID < ss[j].SessionID
	})
}

func (m *Memory) GetSession(_ context.Context, tenantID, sessionID string) (session.Session, []StoredEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[key{tenantID, sessionID}]
	if !ok {
		return session.Session{}, nil, ErrNotFound
	}
	evs := []StoredEvent{}
	for _, k := range m.order {
		e := m.events[k]
		if k.tenant == tenantID && e.SessionID != nil && *e.SessionID == sessionID {
			evs = append(evs, e)
		}
	}
	sortEvents(evs)
	return s, evs, nil
}

func sortEvents(evs []StoredEvent) {
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Timestamp.Before(evs[j].Timestamp) })
}

// device is the store's view of a device row. It expects m.mu held.
func (m *Memory) device(k key, d session.Device) Device {
	out := Device{Device: d}
	if at, ok := m.retired[k]; ok {
		out.RetiredAt = ptr(at)
	}
	return out
}

func (m *Memory) ListDevices(_ context.Context, tenantID string) ([]Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Device{}
	for k, d := range m.devices {
		if k.tenant == tenantID {
			out = append(out, m.device(k, d))
		}
	}
	slices.SortFunc(out, func(a, b Device) int {
		if a.Serial < b.Serial {
			return -1
		}
		if a.Serial > b.Serial {
			return 1
		}
		return 0
	})
	return out, nil
}

func (m *Memory) SilenceCandidates(_ context.Context, seenBefore time.Time) ([]Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Device{}
	for k, d := range m.devices {
		if !d.CheckedInAt().After(seenBefore) || d.Silent() {
			out = append(out, m.device(k, d))
		}
	}
	slices.SortFunc(out, func(a, b Device) int {
		return strings.Compare(a.TenantID+"/"+a.Serial, b.TenantID+"/"+b.Serial)
	})
	return out, nil
}

func (m *Memory) ClaimExports(_ context.Context, sink string, limit int, lease time.Duration, now time.Time) ([]ExportItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ExportItem{}
	for _, x := range m.exports {
		if len(out) == limit {
			break
		}
		if x.done || x.Sink != sink || x.nextAttempt.After(now) || x.leasedUntil.After(now) {
			continue
		}
		x.leasedUntil = now.Add(lease)
		out = append(out, x.ExportItem)
	}
	return out, nil
}

func (m *Memory) CompleteExports(_ context.Context, ids []int64, deliveredAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.exports {
		if slices.Contains(ids, x.ID) && !x.done {
			x.done = true
			key := [2]string{x.TenantID, x.Sink}
			if deliveredAt.After(m.delivered[key]) {
				m.delivered[key] = deliveredAt
			}
		}
	}
	return nil
}

func (m *Memory) RetryExports(_ context.Context, ids []int64, lastError string, retryAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.exports {
		if slices.Contains(ids, x.ID) {
			x.Attempts++
			x.nextAttempt = retryAt
			x.leasedUntil = time.Time{}
			x.lastError = lastError
		}
	}
	return nil
}

func (m *Memory) ExportStatus(_ context.Context, tenantID string) ([]ExportBacklog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	bySink := map[string]*ExportBacklog{}
	for _, x := range m.exports { // in the order queued, so the last error seen is the newest
		if x.done || x.TenantID != tenantID {
			continue
		}
		b := bySink[x.Sink]
		if b == nil {
			queued := x.queuedAt
			b = &ExportBacklog{Sink: x.Sink, OldestAt: &queued}
			bySink[x.Sink] = b
		}
		b.Pending++
		if x.Attempts > 0 {
			b.Failing++
		}
		b.MaxAttempts = max(b.MaxAttempts, x.Attempts)
		if x.lastError != "" {
			b.LastError = truncate(x.lastError, 500)
		}
	}
	out := []ExportBacklog{}
	for _, b := range bySink {
		out = append(out, *b)
	}
	slices.SortFunc(out, func(a, b ExportBacklog) int { return strings.Compare(a.Sink, b.Sink) })
	for key, at := range m.delivered {
		if key[0] == tenantID {
			out = withDelivery(out, key[1], at)
		}
	}
	return out, nil
}

func (m *Memory) RetryExportsNow(_ context.Context, tenantID, sink string, now time.Time, a AuditEntry) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, x := range m.exports {
		if !x.done && x.TenantID == tenantID && x.Sink == sink && x.nextAttempt.After(now) && !x.leasedUntil.After(now) {
			x.nextAttempt = now
			n++
		}
	}
	m.record(a)
	return n, nil
}

func (m *Memory) Close() {}

func (m *Memory) Tenants(context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for k := range m.devices {
		out = append(out, k.tenant)
	}
	for tenant := range m.settings {
		out = append(out, tenant)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// ExpireHistory is Postgres.ExpireHistory, with the database's 90-day floor taken from this
// process's clock. A session's updated_at there is the received time of the last event
// applied to it, which here is its last event in m.order.
func (m *Memory) ExpireHistory(_ context.Context, tenantID string, c HistoryCutoff, limit int) (ExpiryCounts, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	limit = max(limit, 1)
	floor := time.Now().AddDate(0, 0, -MinHistoryDays)
	waiting := m.waiting()
	removable := func(k key, e StoredEvent) bool {
		return e.ReceivedAt.Before(c.Before) && e.ReceivedAt.Before(floor) &&
			(c.NotBefore == nil || !e.ReceivedAt.Before(*c.NotBefore)) && !waiting[k]
	}
	type sessionEvents struct {
		events  []key
		updated time.Time
		held    bool // an event that can't go holds the whole session
	}
	bySession := map[string]*sessionEvents{}
	for _, k := range m.order {
		e := m.events[k]
		if k.tenant != tenantID || e.SessionID == nil {
			continue
		}
		se := bySession[*e.SessionID]
		if se == nil {
			se = &sessionEvents{}
			bySession[*e.SessionID] = se
		}
		se.events = append(se.events, k)
		se.updated = e.ReceivedAt
		se.held = se.held || !removable(k, e)
	}
	type due struct {
		k  key
		at time.Time
	}
	oldest := func(ds []due) []due {
		slices.SortStableFunc(ds, func(a, b due) int { return a.at.Compare(b.at) })
		return ds[:min(limit, len(ds))]
	}

	var n ExpiryCounts
	removed := map[key]bool{}
	sessions := []due{}
	for sk, s := range m.sessions {
		se := bySession[sk.id]
		if sk.tenant != tenantID || s.Open() || se == nil || se.held ||
			!se.updated.Before(c.Before) || !se.updated.Before(floor) {
			continue
		}
		sessions = append(sessions, due{sk, se.updated})
	}
	for _, d := range oldest(sessions) {
		delete(m.sessions, d.k)
		n.Sessions++
		for _, k := range bySession[d.k.id].events {
			removed[k] = true
			n.Events++
		}
	}
	events := []due{}
	for _, k := range m.order {
		e := m.events[k]
		if k.tenant != tenantID || removed[k] || !removable(k, e) {
			continue
		}
		if e.SessionID != nil {
			if _, ok := m.sessions[key{tenantID, *e.SessionID}]; ok {
				continue // it goes with its session
			}
		}
		events = append(events, due{k, e.ReceivedAt})
	}
	for _, d := range oldest(events) {
		removed[d.k] = true
		n.Events++
	}
	for k := range removed {
		delete(m.events, k)
	}
	m.order = slices.DeleteFunc(m.order, func(k key) bool { return removed[k] })
	// Postgres deletes an item once it is delivered; here it stays, marked done, until its
	// event goes.
	m.exports = slices.DeleteFunc(m.exports, func(x *memExport) bool {
		return x.done && x.Audit == nil && removed[key{x.TenantID, x.Event.EventID}]
	})

	commands := []due{}
	for id, cmd := range m.commands {
		if cmd.TenantID == tenantID && cmd.CreatedAt.Before(c.Before) && cmd.CreatedAt.Before(floor) {
			commands = append(commands, due{key{tenantID, id}, cmd.CreatedAt})
		}
	}
	for _, d := range oldest(commands) {
		delete(m.commands, d.k.id)
		n.Commands++
	}
	return n, nil
}

// waiting is the events some sink is still waiting for. It expects m.mu held.
func (m *Memory) waiting() map[key]bool {
	out := map[key]bool{}
	for _, x := range m.exports {
		if !x.done && x.Audit == nil {
			out[key{x.TenantID, x.Event.EventID}] = true
		}
	}
	return out
}

func (m *Memory) RemovalCandidates(_ context.Context, tenantID string, before time.Time) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for k, d := range m.devices {
		if k.tenant == tenantID && d.CheckedInAt().Before(before) {
			out = append(out, k.id)
		}
	}
	slices.Sort(out)
	return out, nil
}

// RemoveDevice is Postgres.RemoveDevice, with the database's 90-day floor taken from this
// process's clock. It works out everything it will remove first, so that nothing changes
// when it fails.
func (m *Memory) RemoveDevice(_ context.Context, tenantID, serial string, c HistoryCutoff, now time.Time) (RemovedDevice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dk := key{tenantID, serial}
	d, ok := m.devices[dk]
	if !ok {
		return RemovedDevice{}, nil // removed already
	}
	before := time.Now().AddDate(0, 0, -MinHistoryDays) // the cutoff, never later than the floor
	if c.Before.Before(before) {
		before = c.Before
	}
	if why := m.keepsDevice(dk, d, c.NotBefore, before); why != "" {
		return RemovedDevice{Skipped: why}, nil
	}

	res := RemovedDevice{Removed: true, RevokedKeys: []string{}}
	for _, k := range m.creds {
		if k.TenantID == tenantID && k.Serial == serial && k.Status != CredentialRevoked {
			res.RevokedKeys = append(res.RevokedKeys, k.DeviceID)
		}
	}
	slices.Sort(res.RevokedKeys)
	commands := []string{}
	for id, cmd := range m.commands {
		// A command from within the period stays until expiry reaches it.
		if cmd.TenantID == tenantID && cmd.Serial == serial && cmd.CreatedAt.Before(before) {
			commands = append(commands, id)
		}
	}
	sessions := []key{}
	for k, s := range m.sessions {
		if k.tenant == tenantID && s.DeviceSerial == serial {
			sessions = append(sessions, k)
		}
	}
	events := map[key]bool{}
	for k, e := range m.events {
		if k.tenant == tenantID && e.Device.Serial == serial {
			events[k] = true
		}
	}
	res.Counts = ExpiryCounts{Events: int64(len(events)), Sessions: int64(len(sessions)), Commands: int64(len(commands)), Macs: 1}
	entries, err := removalEntries(tenantID, d, res.RevokedKeys, c, now, res.Counts)
	if err != nil {
		return RemovedDevice{}, err
	}

	for _, id := range res.RevokedKeys {
		m.revoke(m.creds[id], now)
	}
	for _, id := range commands {
		delete(m.commands, id)
	}
	for _, k := range sessions {
		delete(m.sessions, k)
	}
	for k := range events {
		delete(m.events, k)
	}
	m.order = slices.DeleteFunc(m.order, func(k key) bool { return events[k] })
	m.exports = slices.DeleteFunc(m.exports, func(x *memExport) bool {
		return x.done && x.Audit == nil && events[key{x.TenantID, x.Event.EventID}]
	})
	// What sits beside the reduced state goes with it, as the columns go with the row.
	delete(m.devices, dk)
	delete(m.retired, dk)
	delete(m.adminGroups, dk)
	for _, a := range entries {
		m.record(a)
	}
	return res, nil
}

// keepsDevice is why RemoveDevice keeps the Mac d, at k, with before as the cutoff, or ""
// when nothing does. A session's last change is its newest event's arrival, so the events
// cover sessions too. It expects m.mu held.
func (m *Memory) keepsDevice(k key, d session.Device, notBefore *time.Time, before time.Time) string {
	if d.LastReceivedAt.IsZero() {
		return SkippedOwnClock
	}
	waiting := m.waiting()
	recent, notSent := !d.CheckedInAt().Before(before), false
	for ek, e := range m.events {
		if ek.tenant == k.tenant && e.Device.Serial == k.id {
			recent = recent || !e.ReceivedAt.Before(before)
			notSent = notSent || waiting[ek] || notBefore != nil && e.ReceivedAt.Before(*notBefore)
		}
	}
	open := false
	for sk, s := range m.sessions {
		open = open || sk.tenant == k.tenant && s.DeviceSerial == k.id && s.Open()
	}
	newKey := false
	for _, c := range m.creds {
		newKey = newKey || c.TenantID == k.tenant && c.Serial == k.id &&
			(!c.CreatedAt.Before(before) || c.ActivatedAt != nil && !c.ActivatedAt.Before(before))
	}
	switch {
	case recent:
		return SkippedRecentEvent
	case notSent:
		return SkippedNotSent
	case open:
		return SkippedOpenSession
	case newKey:
		return SkippedRecentKey
	}
	return ""
}
