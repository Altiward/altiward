package store

import (
	"bytes"
	"context"
	"sort"
	"time"
)

func (m *Memory) Enroll(_ context.Context, c DeviceCredential) (EnrollResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.creds {
		if bytes.Equal(existing.PublicKey, c.PublicKey) {
			if existing.TenantID != c.TenantID {
				return EnrollResult{}, ErrConflict
			}
			return EnrollResult{Credential: existing}, nil
		}
	}
	var res EnrollResult
	active, hasActive := m.activeFor(c.TenantID, c.Serial)
	if m.settings[c.TenantID].ReenrollmentRequiresApproval && m.enrolledBefore(c.TenantID, c.Serial) {
		c.Status = CredentialPending
	} else {
		c.Status = CredentialActive
		c.ActivatedAt = ptr(c.CreatedAt)
		if hasActive {
			m.revoke(active, c.CreatedAt)
			res.Replaced = active.DeviceID
		}
	}
	m.creds[c.DeviceID] = c
	res.Credential = c
	return res, nil
}

func (m *Memory) Credential(_ context.Context, deviceID string) (DeviceCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[deviceID]
	if !ok {
		return DeviceCredential{}, ErrNotFound
	}
	return c, nil
}

func (m *Memory) ApproveCredential(_ context.Context, tenantID, deviceID string, now time.Time, a AuditEntry) (DeviceCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[deviceID]
	if !ok || c.TenantID != tenantID {
		return DeviceCredential{}, ErrNotFound
	}
	if c.Status != CredentialPending {
		return DeviceCredential{}, ErrInvalidState
	}
	if active, ok := m.activeFor(tenantID, c.Serial); ok {
		m.revoke(active, now)
	}
	c.Status, c.ActivatedAt = CredentialActive, ptr(now)
	m.creds[deviceID] = c
	m.record(a)
	return c, nil
}

func (m *Memory) RevokeCredential(_ context.Context, tenantID, deviceID string, now time.Time, a AuditEntry) (DeviceCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[deviceID]
	if !ok || c.TenantID != tenantID {
		return DeviceCredential{}, ErrNotFound
	}
	if c.Status != CredentialRevoked {
		m.revoke(c, now)
	}
	m.record(a)
	return m.creds[deviceID], nil
}

func (m *Memory) ListCredentials(_ context.Context, tenantID string, f CredentialFilter) ([]DeviceCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []DeviceCredential{}
	for _, c := range m.creds {
		if c.TenantID == tenantID && (f.Status == "" || c.Status == f.Status) && (f.Serial == "" || c.Serial == f.Serial) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].DeviceID < out[j].DeviceID
	})
	return out, nil
}

func (m *Memory) TenantSettings(_ context.Context, tenantID string) (TenantSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings[tenantID], nil
}

func (m *Memory) PutTenantSettings(_ context.Context, tenantID string, s TenantSettings, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings[tenantID] = s
	m.record(a)
	return nil
}

// activeFor and revoke expect m.mu held.
func (m *Memory) activeFor(tenantID, serial string) (DeviceCredential, bool) {
	for _, c := range m.creds {
		if c.TenantID == tenantID && c.Serial == serial && c.Status == CredentialActive {
			return c, true
		}
	}
	return DeviceCredential{}, false
}

func (m *Memory) enrolledBefore(tenantID, serial string) bool {
	for _, c := range m.creds {
		if c.TenantID == tenantID && c.Serial == serial {
			return true
		}
	}
	return false
}

func (m *Memory) revoke(c DeviceCredential, now time.Time) {
	c.Status, c.RevokedAt = CredentialRevoked, ptr(now)
	m.creds[c.DeviceID] = c
}

func ptr[T any](v T) *T { return &v }
