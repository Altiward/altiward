package store

import (
	"context"
	"time"
)

func (m *Memory) RecordSinks(_ context.Context, sinks []string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range sinks {
		if _, ok := m.coverage[sink]; !ok {
			m.coverage[sink] = now
		}
	}
	return nil
}

func (m *Memory) SinkCoverage(_ context.Context, sinks []string) (*time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var latest *time.Time
	for _, sink := range sinks {
		if at, ok := m.coverage[sink]; ok && (latest == nil || at.After(*latest)) {
			at := at
			latest = &at
		}
	}
	return latest, nil
}
