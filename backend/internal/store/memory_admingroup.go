package store

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/Altiward/altiward/backend/internal/admingroup"
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
