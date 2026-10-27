package store

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

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
		creds:     map[string]DeviceCredential{},
		settings:  map[string]TenantSettings{},
		delivered: map[[2]string]time.Time{},
		commands:  map[string]command.Command{},

		staleUseReported: map[string]time.Time{},

		consoleSessions: map[string]ConsoleSession{},
		installation:    Installation{CreatedAt: time.Now().UTC()},

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
		stored := StoredEvent{Event: e, ReceivedAt: receivedAt}
		m.events[k] = stored
		m.order = append(m.order, k)

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

		for _, sink := range m.sinks {
			m.nextID++
			m.exports = append(m.exports, &memExport{
				ExportItem:  ExportItem{ID: m.nextID, TenantID: tenantID, Sink: sink, Event: stored},
				queuedAt:    receivedAt,
				nextAttempt: receivedAt,
			})
		}
		res.Accepted = append(res.Accepted, e.EventID)
	}
	return res, nil
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

func (m *Memory) ListDevices(_ context.Context, tenantID string) ([]session.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []session.Device{}
	for k, d := range m.devices {
		if k.tenant == tenantID {
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b session.Device) int {
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

func (m *Memory) SilenceCandidates(_ context.Context, seenBefore time.Time) ([]session.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []session.Device{}
	for _, d := range m.devices {
		if !d.CheckedInAt().After(seenBefore) || d.Silent() {
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b session.Device) int {
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
