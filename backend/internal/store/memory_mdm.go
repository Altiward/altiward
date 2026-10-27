package store

import (
	"context"
	"slices"
	"strings"
	"time"
)

// memMDM is one copy and its sync record. claimedAt is zero when never claimed.
type memMDM struct {
	devices   []MDMDevice
	sync      MDMSync
	claimedAt time.Time
}

// mdmCopy expects m.mu held, and makes the copy and its sync record when they don't exist
// yet, as the Postgres store inserts the mdm_sync row.
func (m *Memory) mdmCopy(tenantID, source string) *memMDM {
	k := key{tenantID, source}
	c, ok := m.mdm[k]
	if !ok {
		c = &memMDM{sync: MDMSync{TenantID: tenantID, Source: source}}
		m.mdm[k] = c
	}
	return c
}

func (m *Memory) ClaimMDMSync(_ context.Context, tenantID, source string, now time.Time, every time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.mdmCopy(tenantID, source)
	if !c.claimedAt.IsZero() && c.claimedAt.After(now.Add(-every/2)) {
		return false, nil
	}
	c.claimedAt = now
	return true, nil
}

func (m *Memory) ReplaceMDMDevices(_ context.Context, tenantID, source string, devices []MDMDevice, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.mdmCopy(tenantID, source)
	c.devices = uniqueMDMDevices(devices)
	for i := range c.devices {
		c.devices[i].TenantID, c.devices[i].Source = tenantID, source
	}
	c.sync.LastSuccessAt, c.sync.Devices = &at, len(c.devices)
	return nil
}

func (m *Memory) RecordMDMSyncError(_ context.Context, tenantID, source, msg string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.mdmCopy(tenantID, source)
	c.sync.LastErrorAt, c.sync.LastError = &at, msg
	return nil
}

func (m *Memory) RecordSilenceHeld(_ context.Context, tenantID, source string, count int, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.mdmCopy(tenantID, source)
	c.sync.SilenceHeldAt, c.sync.SilenceHeld = &at, count
	return nil
}

func (m *Memory) MDMDevicesBySerial(_ context.Context, tenantID, source, serial string) ([]MDMDevice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []MDMDevice{}
	if c, ok := m.mdm[key{tenantID, source}]; ok {
		want := mdmSerial(serial)
		for _, d := range c.devices {
			if mdmSerial(d.Serial) == want {
				out = append(out, d)
			}
		}
	}
	slices.SortFunc(out, func(a, b MDMDevice) int {
		if c := b.LastCheckIn.Compare(a.LastCheckIn); c != 0 {
			return c
		}
		return strings.Compare(a.DeviceID, b.DeviceID)
	})
	return out, nil
}

func (m *Memory) MDMDevices(_ context.Context, tenantID, source string) ([]MDMDevice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []MDMDevice{}
	if c, ok := m.mdm[key{tenantID, source}]; ok {
		out = append(out, c.devices...)
	}
	slices.SortFunc(out, func(a, b MDMDevice) int {
		if c := strings.Compare(a.Serial, b.Serial); c != 0 {
			return c
		}
		return strings.Compare(a.DeviceID, b.DeviceID)
	})
	return out, nil
}

func (m *Memory) MDMSyncStatus(_ context.Context, tenantID, source string) (MDMSync, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.mdm[key{tenantID, source}]; ok {
		return c.sync, nil
	}
	return MDMSync{}, nil
}

func (m *Memory) ClearMDM(_ context.Context, tenantID, source string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mdm, key{tenantID, source})
	return nil
}
