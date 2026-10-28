package store

import (
	"cmp"
	"context"
	"encoding/json"
	"slices"
	"time"
)

// record appends a and queues it for every export sink; it expects m.mu held. The detail
// goes through JSON, as it does in Postgres, so both stores hand back the same types.
func (m *Memory) record(a AuditEntry) {
	a.normalize()
	if b, err := json.Marshal(a.Detail); err == nil {
		var detail map[string]any
		if json.Unmarshal(b, &detail) == nil {
			a.Detail = detail
		}
	}
	a.Seq = int64(len(m.audit) + 1)
	m.audit = append(m.audit, a)
	for _, sink := range m.sinks {
		m.nextID++
		queued := a
		m.exports = append(m.exports, &memExport{
			ExportItem:  ExportItem{ID: m.nextID, TenantID: a.TenantID, Sink: sink, Audit: &queued},
			queuedAt:    a.At,
			nextAttempt: a.At,
		})
	}
}

func (m *Memory) RecordAudit(_ context.Context, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record(a)
	return nil
}

func (m *Memory) RecordTokenSignIn(_ context.Context, a AuditEntry, within time.Duration) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var covered time.Time
	for _, e := range m.audit {
		if e.TenantID == a.TenantID && e.Action == AuditSignIn && e.Actor == a.Actor && e.Detail["method"] == "token" &&
			!e.At.Before(a.At.Add(-within)) && !e.At.After(a.At.Add(tokenSignInSkew)) && e.At.After(covered) {
			covered = e.At
		}
	}
	if !covered.IsZero() {
		return covered, nil
	}
	m.record(a)
	return a.At, nil
}

func (m *Memory) ListAudit(_ context.Context, tenantID string, f AuditFilter) ([]AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []AuditEntry{}
	for _, a := range m.audit {
		if a.TenantID == tenantID && (f.Before == nil || a.At.Before(*f.Before) ||
			f.BeforeSeq != nil && a.At.Equal(*f.Before) && a.Seq < *f.BeforeSeq) {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, func(a, b AuditEntry) int {
		if c := b.At.Compare(a.At); c != 0 {
			return c
		}
		return cmp.Compare(b.Seq, a.Seq)
	})
	if limit := auditLimit(f.Limit); len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) PurgeAudit(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	queued := map[string]bool{}
	for _, x := range m.exports {
		if x.Audit != nil && !x.done {
			queued[x.Audit.ID] = true
		}
	}
	n := len(m.audit)
	m.audit = slices.DeleteFunc(m.audit, func(a AuditEntry) bool { return a.At.Before(before) && !queued[a.ID] })
	return int64(n - len(m.audit)), nil
}
