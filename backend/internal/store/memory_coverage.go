package store

import (
	"context"
	"slices"
	"time"
)

// memCoverage is a sink's row of export_sinks.
type memCoverage struct {
	coveredFrom time.Time
	absentSince *time.Time
}

func (m *Memory) RecordSinks(_ context.Context, sinks []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for sink, c := range m.coverage {
		if !slices.Contains(sinks, sink) && c.absentSince == nil {
			c.absentSince = &now
			m.coverage[sink] = c
		}
	}
	from := now.Add(CoverageGrace)
	for _, sink := range sinks {
		c, ok := m.coverage[sink]
		switch {
		case !ok:
			m.coverage[sink] = memCoverage{coveredFrom: from}
		case c.absentSince != nil:
			if from.After(c.coveredFrom) {
				c.coveredFrom = from
			}
			c.absentSince = nil
			m.coverage[sink] = c
		}
	}
	return nil
}

func (m *Memory) SinkCoverage(_ context.Context, sinks []string) (*time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var latest *time.Time
	for _, sink := range sinks {
		if c, ok := m.coverage[sink]; ok && (latest == nil || c.coveredFrom.After(*latest)) {
			at := c.coveredFrom
			latest = &at
		}
	}
	return latest, nil
}
