package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Altiward/altiward/backend/internal/admingroup"
	"github.com/Altiward/altiward/backend/internal/session"
)

func (p *Postgres) AdminGroupSnapshotCandidates(ctx context.Context, since time.Time) ([]DeviceRef, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT tenant_id, serial FROM devices
		WHERE admin_group IS NOT NULL AND retired_at IS NULL AND last_seen_at > $1
		ORDER BY tenant_id, serial`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceRef{}
	for rows.Next() {
		var r DeviceRef
		if err := rows.Scan(&r.TenantID, &r.Serial); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) RaiseAdminGroupSnapshot(ctx context.Context, tenantID, serial string, now time.Time) (bool, error) {
	if len(p.raisedIDSecret) == 0 {
		return false, nil
	}
	var raised bool
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		raised = false
		// The same lock a batch of readings takes, so the group read below is the one the
		// last reading left, and the next reading waits for this snapshot.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ingestLockID(tenantID)); err != nil {
			return fmt.Errorf("lock ingestion: %w", err)
		}
		var state, group []byte
		var retired *time.Time
		var day string
		err := tx.QueryRow(ctx, `
			SELECT state, admin_group, retired_at, to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD')
			FROM devices WHERE tenant_id = $1 AND serial = $2 FOR UPDATE`,
			tenantID, serial).Scan(&state, &group, &retired, &day)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("load device: %w", err)
		}
		report := decodeReport(group)
		if retired != nil || report == nil {
			return nil
		}
		var d session.Device
		if err := json.Unmarshal(state, &d); err != nil {
			return fmt.Errorf("decode device: %w", err)
		}
		if !d.CheckedInAt().After(now.Add(-snapshotWindow)) {
			return nil
		}
		e := admingroup.Snapshot(*report, deviceIdentity(d), tenantID, day, p.raisedIDSecret, now)
		if e.Validate(now) != nil {
			return nil
		}
		stored, err := p.insertEvent(ctx, tx, tenantID, e, now)
		if err != nil || !stored {
			return err
		}
		if err := p.queueExports(ctx, tx, tenantID, e.EventID, now); err != nil {
			return err
		}
		raised = true
		return nil
	})
	return raised && err == nil, err
}
