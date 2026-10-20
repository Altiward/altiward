package store

import (
	"context"
	"sort"
	"time"

	"github.com/Altiward/altiward/backend/internal/command"
)

func (m *Memory) CreateCommand(_ context.Context, c command.Command, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.commands[c.CommandID]; dup {
		return ErrConflict
	}
	m.commands[c.CommandID] = c
	m.record(a)
	m.watchers.notify(c.TenantID, c.Serial)
	return nil
}

func (m *Memory) WatchCommands(tenantID, serial string) (<-chan struct{}, func()) {
	return m.watchers.watch(tenantID, serial)
}

func (m *Memory) PendingCommands(_ context.Context, tenantID, serial string, now time.Time) ([]command.Command, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []command.Command{}
	for id, c := range m.commands {
		if c.TenantID != tenantID || c.Serial != serial || c.Status(now) != command.StatusPending {
			continue
		}
		if c.DeliveredAt == nil {
			c.DeliveredAt = ptr(now)
			m.commands[id] = c
		}
		out = append(out, c)
	}
	sortCommands(out, false)
	return out, nil
}

func (m *Memory) RecordCommandResult(_ context.Context, tenantID, serial, commandID string, r command.Result, receivedAt time.Time) (command.Command, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.commands[commandID]
	if !ok || c.TenantID != tenantID || c.Serial != serial {
		return command.Command{}, ErrNotFound
	}
	if c.Result == nil {
		c.Result, c.ResultAt = &r, ptr(receivedAt)
		m.commands[commandID] = c
	}
	return c, nil
}

func (m *Memory) GetCommand(_ context.Context, tenantID, commandID string) (command.Command, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.commands[commandID]
	if !ok || c.TenantID != tenantID {
		return command.Command{}, ErrNotFound
	}
	return c, nil
}

func (m *Memory) ListCommands(_ context.Context, tenantID string, f CommandFilter, now time.Time) ([]command.Command, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []command.Command{}
	for _, c := range m.commands {
		if c.TenantID == tenantID && (f.Serial == "" || c.Serial == f.Serial) && (f.Status == "" || c.Status(now) == f.Status) {
			out = append(out, c)
		}
	}
	sortCommands(out, true)
	return out, nil
}

func sortCommands(cs []command.Command, newestFirst bool) {
	sort.Slice(cs, func(i, j int) bool {
		if !cs[i].CreatedAt.Equal(cs[j].CreatedAt) {
			return cs[i].CreatedAt.After(cs[j].CreatedAt) == newestFirst
		}
		return cs[i].CommandID < cs[j].CommandID
	})
}
