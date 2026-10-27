package store

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
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
	if holdsForApproval(m.tenantSettings(c.TenantID), m.enrolledBefore(c.TenantID, c.Serial),
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
	return m.withSuccessor(c), nil
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
	// A rotated key is already revoked; the key to revoke is its lineage's active one.
	if active, ok := m.lineageActive(deviceID); ok && active.DeviceID != deviceID {
		return DeviceCredential{}, ErrRotated
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
			out = append(out, m.withSuccessor(c))
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
		// Keys made by rotation aren't enrolments, so they don't count.
		if o.Serial == c.Serial && o.RotatedFrom == "" && o.CreatedAt.After(keysSince) {
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

// successor, withSuccessor and lineageActive expect m.mu held. successor is id's direct
// successor.
func (m *Memory) successor(id string) (DeviceCredential, bool) {
	for _, c := range m.creds {
		if c.RotatedFrom == id {
			return c, true
		}
	}
	return DeviceCredential{}, false
}

func (m *Memory) withSuccessor(c DeviceCredential) DeviceCredential {
	c.RotatedTo = ""
	if next, ok := m.successor(c.DeviceID); ok {
		c.RotatedTo = next.DeviceID
	}
	return c
}

// lineageActive returns the active key among id's key and its successors.
func (m *Memory) lineageActive(id string) (DeviceCredential, bool) {
	seen := map[string]bool{}
	for c, ok := m.creds[id]; ok && !seen[c.DeviceID]; c, ok = m.successor(c.DeviceID) {
		seen[c.DeviceID] = true
		if c.Status == CredentialActive {
			return c, true
		}
	}
	return DeviceCredential{}, false
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

func (m *Memory) Rotate(_ context.Context, r RotateRequest) (RotateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.creds[r.FromDeviceID]
	if !ok || cur.TenantID != r.TenantID {
		return RotateResult{}, ErrNotFound
	}
	cur = m.withSuccessor(cur)
	res := RotateResult{Previous: cur}
	if cur.Status == CredentialRevoked && cur.RotatedTo != "" {
		next := m.withSuccessor(m.creds[cur.RotatedTo])
		if bytes.Equal(next.PublicKey, r.PublicKey) {
			res.Credential, res.Retry = next, true
			return res, nil
		}
		c := m.contest(cur, next, r.Now, r.Alert)
		res.Contest = &c
		return res, ErrRotatedElsewhere
	}
	switch {
	case cur.Status == CredentialRevoked:
		return res, ErrRevoked
	case cur.Status != CredentialActive:
		return res, ErrInvalidState
	case cur.KeyStorage == KeyStorageSecureEnclave:
		return res, ErrRotationNotAllowed
	case cur.ActivatedAt != nil && r.Now.Before(cur.ActivatedAt.Add(MinRotationInterval)):
		return res, ErrRotationTooSoon
	}
	for _, o := range m.creds {
		if bytes.Equal(o.PublicKey, r.PublicKey) {
			return res, ErrKeyInUse
		}
	}
	m.revoke(cur, r.Now)
	next := DeviceCredential{
		DeviceID: r.DeviceID, TenantID: cur.TenantID, Serial: cur.Serial, HardwareUUID: cur.HardwareUUID,
		PublicKey: r.PublicKey, KeyStorage: r.KeyStorage, Token: cur.Token, Status: CredentialActive,
		CreatedAt: r.Now, ActivatedAt: ptr(r.Now), RotatedFrom: cur.DeviceID, RotationSignedAt: ptr(r.SignedAt),
	}
	m.creds[next.DeviceID] = next
	res.Credential = next
	return res, nil
}

// contest expects m.mu held. It mirrors the Postgres store's contest.
func (m *Memory) contest(stale, next DeviceCredential, now time.Time, alert ContestAlert) ContestResult {
	res := ContestResult{Stale: stale}
	if withinContestWindow(next, now) {
		if active, ok := m.lineageActive(stale.DeviceID); ok {
			m.revoke(active, now)
			res.Revoked = ptr(m.creds[active.DeviceID])
		}
	}
	marked := false
	if last, ok := m.staleUseReported[stale.DeviceID]; !ok || staleUseReported(&last, now) {
		m.staleUseReported[stale.DeviceID] = now
		marked = true
	}
	res.Report = res.Revoked != nil || marked
	if res.Report && alert != nil {
		// Only a session's events can be refused, and an alert has no session.
		_, _ = m.ingest(stale.TenantID, []event.Event{alert(res)}, now)
	}
	return res
}

func (m *Memory) StaleKeyUsed(_ context.Context, deviceID string, signedAt, now time.Time, alert ContestAlert) (*ContestResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stale, ok := m.creds[deviceID]
	if !ok {
		return nil, ErrNotFound
	}
	stale = m.withSuccessor(stale)
	if stale.Status != CredentialRevoked || stale.RotatedTo == "" {
		return nil, nil
	}
	next := m.creds[stale.RotatedTo]
	if inFlight(next, signedAt, now) {
		return nil, nil
	}
	c := m.contest(stale, next, now, alert)
	return &c, nil
}

func (m *Memory) LineageActive(_ context.Context, deviceID string) (DeviceCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.lineageActive(deviceID); ok {
		return c, nil
	}
	return DeviceCredential{}, ErrNotFound
}
