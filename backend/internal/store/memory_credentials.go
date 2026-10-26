package store

import (
	"bytes"
	"context"
	"sort"
	"time"
)

func (m *Memory) Enroll(_ context.Context, c DeviceCredential, limits EnrollLimits) (EnrollResult, error) {
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
	if err := m.enforceEnrollLimits(c, limits); err != nil {
		return EnrollResult{}, err
	}
	var res EnrollResult
	active, hasActive := m.activeFor(c.TenantID, c.Serial)
	if hasActive {
		res.Previous = ptr(active)
	}
	if holdsForApproval(m.tenantSettings(c.TenantID).ReenrollmentRequiresApproval, m.enrolledBefore(c.TenantID, c.Serial),
		res.Previous, c.HardwareUUID) {
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
	return m.tenantSettings(tenantID), nil
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

// enforceEnrollLimits expects m.mu held. It counts the tenant's serials by their earliest
// credential, and the serial's own credentials, over the windows ending at c.CreatedAt.
func (m *Memory) enforceEnrollLimits(c DeviceCredential, limits EnrollLimits) error {
	if limits == (EnrollLimits{}) {
		return nil
	}
	newMacsSince, keysSince := c.CreatedAt.Add(-NewMacsWindow), c.CreatedAt.Add(-KeysPerMacWindow)
	firstKey := map[string]time.Time{}
	keys := 0
	for _, o := range m.creds {
		if o.TenantID != c.TenantID {
			continue
		}
		if first, ok := firstKey[o.Serial]; !ok || o.CreatedAt.Before(first) {
			firstKey[o.Serial] = o.CreatedAt
		}
		if o.Serial == c.Serial && o.CreatedAt.After(keysSince) {
			keys++
		}
	}
	if _, known := firstKey[c.Serial]; !known {
		newMacs := 0
		for _, first := range firstKey {
			if first.After(newMacsSince) {
				newMacs++
			}
		}
		if limits.refusesNewMac(newMacs) {
			return ErrNewMacsLimited
		}
	}
	if limits.refusesKey(keys) {
		return ErrKeysPerMacLimited
	}
	return nil
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

// tenantSettings expects m.mu held and distinguishes absent settings from an explicit opt-out.
func (m *Memory) tenantSettings(tenantID string) TenantSettings {
	if settings, ok := m.settings[tenantID]; ok {
		return settings
	}
	return DefaultTenantSettings()
}
