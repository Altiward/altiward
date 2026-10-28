package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// mdmColumns reads a record of mdm_devices, '-infinity' (never checked in) as nil.
const mdmColumns = `tenant_id, source, device_id, serial, entra_device_id, primary_upn, name,
	NULLIF(last_check_in, '-infinity')`

func (p *Postgres) ClaimMDMSync(ctx context.Context, tenantID, source string, now time.Time, every time.Duration) (bool, error) {
	// An update that finds the claim held returns no row. Claims racing for the same row
	// wait for each other, and the losers then see it held.
	var won bool
	err := p.pool.QueryRow(ctx, `
		INSERT INTO mdm_sync (tenant_id, source, claimed_at) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, source) DO UPDATE SET claimed_at = EXCLUDED.claimed_at
			WHERE mdm_sync.claimed_at <= $4
		RETURNING true`, tenantID, source, now, now.Add(-every/2)).Scan(&won)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return won, err
}

func (p *Postgres) ReplaceMDMDevices(ctx context.Context, tenantID, source string, devices []MDMDevice, at time.Time) error {
	devices = uniqueMDMDevices(devices)
	var ids, serials, entraIDs, upns, names []string
	seen := make([]*time.Time, 0, len(devices))
	for _, d := range devices {
		ids, serials, entraIDs = append(ids, d.DeviceID), append(serials, d.Serial), append(entraIDs, d.EntraDeviceID)
		upns, names = append(upns, d.PrimaryUPN), append(names, d.Name)
		var t *time.Time
		if !d.LastCheckIn.IsZero() {
			t = &d.LastCheckIn
		}
		seen = append(seen, t)
	}
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// Recording the success first locks the sync's row, so two replacements of the same
		// copy run one after the other.
		if _, err := tx.Exec(ctx, `
			INSERT INTO mdm_sync (tenant_id, source, last_success_at, devices) VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, source) DO UPDATE SET last_success_at = EXCLUDED.last_success_at,
				devices = EXCLUDED.devices`, tenantID, source, at, len(devices)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mdm_devices WHERE tenant_id = $1 AND source = $2`, tenantID, source); err != nil {
			return err
		}
		if len(devices) == 0 {
			return nil
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO mdm_devices (tenant_id, source, device_id, serial, entra_device_id, primary_upn, name, last_check_in)
			SELECT $1, $2, d.id, d.serial, d.entra, d.upn, d.name, COALESCE(d.seen, '-infinity')
			FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::timestamptz[])
				AS d (id, serial, entra, upn, name, seen)`,
			tenantID, source, ids, serials, entraIDs, upns, names, seen)
		return err
	})
}

func (p *Postgres) RecordMDMSyncError(ctx context.Context, tenantID, source, msg string, at time.Time) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO mdm_sync (tenant_id, source, last_error_at, last_error) VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, source) DO UPDATE SET last_error_at = EXCLUDED.last_error_at,
			last_error = EXCLUDED.last_error`, tenantID, source, at, msg)
	return err
}

func (p *Postgres) RecordSilenceHeld(ctx context.Context, tenantID, source string, count int, at time.Time) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO mdm_sync (tenant_id, source, silence_held_at, silence_held) VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, source) DO UPDATE SET silence_held_at = EXCLUDED.silence_held_at,
			silence_held = EXCLUDED.silence_held`, tenantID, source, at, count)
	return err
}

func (p *Postgres) MDMDevicesBySerial(ctx context.Context, tenantID, source, serial string) ([]MDMDevice, error) {
	return p.mdmDevices(ctx, `SELECT `+mdmColumns+` FROM mdm_devices
		WHERE tenant_id = $1 AND source = $2 AND upper(btrim(serial)) = $3
		ORDER BY last_check_in DESC, device_id COLLATE "C"`, tenantID, source, MDMSerial(serial))
}

func (p *Postgres) MDMDevices(ctx context.Context, tenantID, source string) ([]MDMDevice, error) {
	return p.mdmDevices(ctx, `SELECT `+mdmColumns+` FROM mdm_devices WHERE tenant_id = $1 AND source = $2
		ORDER BY serial COLLATE "C", device_id COLLATE "C"`, tenantID, source)
}

func (p *Postgres) mdmDevices(ctx context.Context, sql string, args ...any) ([]MDMDevice, error) {
	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MDMDevice{}
	for rows.Next() {
		var d MDMDevice
		var seen *time.Time
		if err := rows.Scan(&d.TenantID, &d.Source, &d.DeviceID, &d.Serial, &d.EntraDeviceID, &d.PrimaryUPN, &d.Name, &seen); err != nil {
			return nil, err
		}
		if seen != nil {
			d.LastCheckIn = *seen
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

const mdmSyncColumns = `tenant_id, source, last_success_at, last_error_at, silence_held_at, last_error, devices, silence_held`

func scanMDMSync(row pgx.Row) (MDMSync, error) {
	var s MDMSync
	err := row.Scan(&s.TenantID, &s.Source, &s.LastSuccessAt, &s.LastErrorAt, &s.SilenceHeldAt, &s.LastError, &s.Devices, &s.SilenceHeld)
	return s, err
}

func (p *Postgres) MDMSyncStatus(ctx context.Context, tenantID, source string) (MDMSync, error) {
	s, err := scanMDMSync(p.pool.QueryRow(ctx, `SELECT `+mdmSyncColumns+` FROM mdm_sync
		WHERE tenant_id = $1 AND source = $2`, tenantID, source))
	if errors.Is(err, pgx.ErrNoRows) {
		return MDMSync{}, nil
	}
	return s, err
}

func (p *Postgres) ClearMDM(ctx context.Context, tenantID, source string) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		for _, table := range []string{"mdm_devices", "mdm_sync"} {
			if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = $1 AND source = $2`, tenantID, source); err != nil {
				return err
			}
		}
		return nil
	})
}
