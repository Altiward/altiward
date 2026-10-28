package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Altiward/altiward/backend/internal/admingroup"
	"github.com/Altiward/altiward/backend/internal/event"
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

func (p *Postgres) BackfillAdminGroups(ctx context.Context, now time.Time) (int, error) {
	if len(p.raisedIDSecret) == 0 {
		return 0, nil
	}
	in, err := p.Installation(ctx)
	if err != nil {
		return 0, err
	}
	if in.AdminGroupBackfilledAt != nil {
		return 0, nil
	}
	rows, err := p.pool.Query(ctx, `
		SELECT DISTINCT tenant_id, device_serial FROM events
		WHERE type = $1 AND received_at < $2
		ORDER BY tenant_id, device_serial`, string(event.AgentHealth), in.AdminGroupStartedAt)
	if err != nil {
		return 0, fmt.Errorf("list Macs: %w", err)
	}
	macs := []DeviceRef{}
	for rows.Next() {
		var r DeviceRef
		if err := rows.Scan(&r.TenantID, &r.Serial); err != nil {
			rows.Close()
			return 0, err
		}
		macs = append(macs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	raised := 0
	for _, mac := range macs {
		// One transaction a Mac. It takes no lock: it reads readings that are stored already
		// and adds events whose IDs are fixed, so a second server doing the same, or ingest
		// raising one of them, leaves a single copy.
		err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
			n, err := p.backfillMac(ctx, tx, mac, in.AdminGroupStartedAt, now.Add(BackfillHold))
			raised += n
			return err
		})
		if err != nil {
			return raised, fmt.Errorf("backfill %s/%s: %w", mac.TenantID, mac.Serial, err)
		}
	}
	if _, err := p.pool.Exec(ctx, `UPDATE installation SET admin_group_backfilled_at = $1
		WHERE admin_group_backfilled_at IS NULL`, now); err != nil {
		return raised, fmt.Errorf("record the backfill: %w", err)
	}
	return raised, nil
}

// backfillPage is how many readings the backfill reads at a time, so a Mac with years of
// readings never has them all in memory. A variable so a test can make pages small.
var backfillPage = 500

// backfillMac stores what the Mac's readings from before start would have raised, queued
// for every sink from due. It returns how many it stored; a transaction that fails stores
// none of them.
func (p *Postgres) backfillMac(ctx context.Context, tx pgx.Tx, mac DeviceRef, start, due time.Time) (int, error) {
	return backfillMac(p.readingsBefore(ctx, tx, mac, start), mac.TenantID, p.raisedIDSecret,
		func(e event.Event, at time.Time) (recorded, stored bool, err error) {
			stored, err = p.insertEvent(ctx, tx, mac.TenantID, e, at)
			if err != nil {
				return false, false, err
			}
			if stored {
				return true, true, p.queueExports(ctx, tx, mac.TenantID, e.EventID, due)
			}
			var typ, serial string
			if err := tx.QueryRow(ctx, `SELECT type, device_serial FROM events WHERE tenant_id = $1 AND event_id = $2`,
				mac.TenantID, e.EventID).Scan(&typ, &serial); err != nil {
				return false, false, fmt.Errorf("load raised event: %w", err)
			}
			return typ == string(e.Type) && serial == e.Device.Serial, false, nil
		})
}

// readingsBefore yields the Mac's health readings received before start in arrival order
// (received time, then event ID), a page at a time: the transaction can't run the walk's
// inserts while a query's rows are open, so each page is read and closed before it is
// walked. Each reading carries only what admingroup.OnHealth reads: its ID, time, device and
// the three lists of its detail. A reading that can't be read is skipped, as it raised
// nothing at ingest either.
func (p *Postgres) readingsBefore(ctx context.Context, tx pgx.Tx, mac DeviceRef, start time.Time) iter.Seq2[StoredEvent, error] {
	return func(yield func(StoredEvent, error) bool) {
		var afterAt *time.Time // the last reading read, nil before the first page
		var afterID *string
		for {
			rows, err := tx.Query(ctx, `
				SELECT event_id::text, received_at, jsonb_build_object(
					'event_id', body->'event_id', 'timestamp', body->'timestamp', 'device', body->'device',
					'detail', jsonb_build_object(
						'admin_members', body->'detail'->'admin_members',
						'permanent_admins', body->'detail'->'permanent_admins',
						'open_sessions', body->'detail'->'open_sessions'))
				FROM events
				WHERE tenant_id = $1 AND device_serial = $2 AND type = $3 AND received_at < $4
				  AND (received_at, event_id) > (COALESCE($5::timestamptz, '-infinity'),
				                                 COALESCE($6::uuid, '00000000-0000-0000-0000-000000000000'))
				ORDER BY received_at, event_id
				LIMIT $7`, mac.TenantID, mac.Serial, string(event.AgentHealth), start, afterAt, afterID, backfillPage)
			if err != nil {
				yield(StoredEvent{}, fmt.Errorf("load readings: %w", err))
				return
			}
			page := make([]StoredEvent, 0, backfillPage)
			read := 0
			for rows.Next() {
				var id string
				var at time.Time
				var body []byte
				if err := rows.Scan(&id, &at, &body); err != nil {
					rows.Close()
					yield(StoredEvent{}, err)
					return
				}
				read++
				afterAt, afterID = &at, &id
				r := StoredEvent{ReceivedAt: at}
				if json.Unmarshal(body, &r.Event) != nil {
					continue
				}
				r.Type = event.AgentHealth
				page = append(page, r)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				yield(StoredEvent{}, err)
				return
			}
			for _, r := range page {
				if !yield(r, nil) {
					return
				}
			}
			if read < backfillPage {
				return
			}
		}
	}
}
