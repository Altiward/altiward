package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

func (p *Postgres) RecordSinks(ctx context.Context, sinks []string) error {
	if sinks == nil {
		sinks = []string{} // NULL would match no sink, and mark none absent
	}
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// Replicas starting together take turns, so each sees the others' rows.
		if _, err := tx.Exec(ctx, `LOCK TABLE export_sinks IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE export_sinks SET absent_since = now()
			WHERE absent_since IS NULL AND NOT (sink = ANY($1))`, sinks); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO export_sinks (sink, covered_from)
			SELECT sink, now() + make_interval(secs => $2) FROM unnest($1::text[]) AS sink
			ON CONFLICT (sink) DO UPDATE
			SET covered_from = GREATEST(export_sinks.covered_from, EXCLUDED.covered_from), absent_since = NULL
			WHERE export_sinks.absent_since IS NOT NULL`, sinks, CoverageGrace.Seconds())
		return err
	})
	if err != nil {
		return fmt.Errorf("record sinks: %w", err)
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
