package store

import (
	"context"
	"slices"
	"strings"
	"time"
)

func (m *Memory) CreateConsoleSession(_ context.Context, s ConsoleSession, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, old := range m.consoleSessions {
		if !old.ExpiresAt.After(s.CreatedAt) {
			delete(m.consoleSessions, k)
		}
	}
	m.consoleSessions[string(s.TokenHash)] = s
	m.record(a)
	return nil
}

func (m *Memory) ConsoleSession(_ context.Context, tokenHash []byte, now time.Time) (ConsoleSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.consoleSessions[string(tokenHash)]
	if !ok || !s.ExpiresAt.After(now) {
		return ConsoleSession{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) ExtendConsoleSession(_ context.Context, tokenHash []byte, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.consoleSessions[string(tokenHash)]; ok {
		s.ExpiresAt = expiresAt
		if s.ExpiresAt.After(s.EndsAt) {
			s.ExpiresAt = s.EndsAt
		}
		m.consoleSessions[string(tokenHash)] = s
	}
	return nil
}

func (m *Memory) EndConsoleSession(_ context.Context, tenantID string, tokenHash []byte, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.consoleSessions[string(tokenHash)]; !ok || s.TenantID != tenantID {
		return ErrNotFound
	}
	delete(m.consoleSessions, string(tokenHash))
	m.record(a)
	return nil
}

func (m *Memory) ListConsoleSessions(_ context.Context, tenantID string, now time.Time) ([]ConsoleSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ConsoleSession{}
	for _, s := range m.consoleSessions {
		if s.TenantID == tenantID && s.ExpiresAt.After(now) {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b ConsoleSession) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.Actor, b.Actor)
	})
	return out, nil
}
