package store

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/Altiward/altiward/backend/internal/admingroup"
	"github.com/Altiward/altiward/backend/internal/event"
)

func (m *Memory) AdminGroupSnapshotCandidates(_ context.Context, since time.Time) ([]DeviceRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []DeviceRef{}
	for k, d := range m.devices {
		if _, reported := m.adminGroups[k]; !reported || !d.CheckedInAt().After(since) {
			continue
		}
		if _, retired := m.retired[k]; !retired {
			out = append(out, DeviceRef{TenantID: k.tenant, Serial: k.id})
		}
	}
	slices.SortFunc(out, func(a, b DeviceRef) int {
		return strings.Compare(a.TenantID+"/"+a.Serial, b.TenantID+"/"+b.Serial)
	})
	return out, nil
}

func (m *Memory) RaiseAdminGroupSnapshot(_ context.Context, tenantID, serial string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key{tenantID, serial}
	d, known := m.devices[k]
	report, reported := m.adminGroups[k]
	if _, retired := m.retired[k]; !known || !reported || retired || !d.CheckedInAt().After(now.Add(-snapshotWindow)) {
		return false, nil
	}
	e := admingroup.Snapshot(report, deviceIdentity(d), tenantID, time.Now().UTC().Format(time.DateOnly),
		m.installation.RaisedIDSecret, now)
	if e.Validate(now) != nil {
		return false, nil
	}
	if _, taken := m.events[key{tenantID, e.EventID}]; taken {
		return false, nil
	}
	m.store(tenantID, e, now)
	return true, nil
}

func (m *Memory) BackfillAdminGroups(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.installation.AdminGroupBackfilledAt != nil {
		return 0, nil
	}
	// Group the readings stored before the start by Mac, then sort each Mac's by arrival.
	byMac := map[key][]StoredEvent{}
	for _, k := range m.order {
		e := m.events[k]
		if e.Type == event.AgentHealth && e.ReceivedAt.Before(m.installation.AdminGroupStartedAt) {
			mac := key{k.tenant, e.Device.Serial}
			byMac[mac] = append(byMac[mac], e)
		}
	}
	raised := 0
	for mac, readings := range byMac {
		slices.SortFunc(readings, func(a, b StoredEvent) int {
			if c := a.ReceivedAt.Compare(b.ReceivedAt); c != 0 {
				return c
			}
			return strings.Compare(a.EventID, b.EventID)
		})
		n, _ := backfillMac(readings, mac.tenant, m.installation.RaisedIDSecret,
			func(e event.Event, at time.Time) (recorded, stored bool, err error) {
				had, taken := m.events[key{mac.tenant, e.EventID}]
				if taken {
					return had.Type == e.Type && had.Device.Serial == e.Device.Serial, false, nil
				}
				m.store(mac.tenant, e, at)
				return true, true, nil
			})
		raised += n
	}
	done := now
	m.installation.AdminGroupBackfilledAt = &done
	return raised, nil
}
