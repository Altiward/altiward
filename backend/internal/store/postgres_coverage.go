package store

import (
	"context"
	"fmt"
	"time"
)

func (p *Postgres) RecordSinks(ctx context.Context, sinks []string, now time.Time) error {
	for _, sink := range sinks {
		if _, err := p.pool.Exec(ctx, `
			INSERT INTO export_sinks (sink, covered_from) VALUES ($1, $2)
			ON CONFLICT (sink) DO NOTHING`, sink, now); err != nil {
			return fmt.Errorf("record sink %s: %w", sink, err)
		}
	}
	return nil
}

func (p *Postgres) SinkCoverage(ctx context.Context, sinks []string) (*time.Time, error) {
	if len(sinks) == 0 {
		return nil, nil
	}
	var latest *time.Time
	if err := p.pool.QueryRow(ctx, `SELECT max(covered_from) FROM export_sinks WHERE sink = ANY($1)`, sinks).Scan(&latest); err != nil {
		return nil, fmt.Errorf("sink coverage: %w", err)
	}
	if latest != nil {
		utc := latest.UTC()
		latest = &utc
	}
	return latest, nil
}
