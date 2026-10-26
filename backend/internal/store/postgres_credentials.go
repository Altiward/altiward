package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const credentialColumns = `device_id::text, tenant_id, serial, hardware_uuid, public_key, key_storage, status, created_at, activated_at, revoked_at`

func scanCredential(row pgx.Row) (DeviceCredential, error) {
	var c DeviceCredential
	var keyStorage, status string
	err := row.Scan(&c.DeviceID, &c.TenantID, &c.Serial, &c.HardwareUUID, &c.PublicKey, &keyStorage, &status,
		&c.CreatedAt, &c.ActivatedAt, &c.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceCredential{}, ErrNotFound
	}
	c.KeyStorage = KeyStorage(keyStorage)
	c.Status = CredentialStatus(status)
	return c, err
}

// lockSerial serialises enrollment and approval for one Mac so two requests cannot
// both see "no active credential" and race on the unique index.
func lockSerial(ctx context.Context, tx pgx.Tx, tenantID, serial string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 7243100002))`, tenantID+"/"+serial)
	return err
}

// lockTenantNewMacs serialises the enrolments of a tenant's new serials, whose count is
// taken across serials, which the serial lock doesn't cover: without it two new serials could
// each see room for one more. It is always taken after the serial lock, and nothing takes
// the two the other way round, so they can't deadlock.
func lockTenantNewMacs(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 7243100003))`, tenantID)
	return err
}

// countNewMacs counts the tenant's serials whose first credential is under an hour old at
// c.CreatedAt, from the rows committed when it runs. It reads only the hour's credentials
// and, for each, whether its serial has an older one, so its cost follows the hour's
// enrolments, which the limits bound, not the tenant's whole history.
func countNewMacs(ctx context.Context, tx pgx.Tx, c DeviceCredential) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(DISTINCT d.serial) FROM device_credentials d
		WHERE d.tenant_id = $1 AND d.created_at > $2 AND NOT EXISTS (
			SELECT 1 FROM device_credentials e
			WHERE e.tenant_id = d.tenant_id AND e.serial = d.serial AND e.created_at <= $2
		)`, c.TenantID, c.CreatedAt.Add(-NewMacsWindow)).Scan(&n)
	return n, err
}

// enforceEnrollLimits counts, in tx and under the serial's lock, what c would add to: the
// tenant's serials whose first credential is under an hour old, if c is the first for its
// serial, and the serial's credentials under 24 hours old.
func enforceEnrollLimits(ctx context.Context, tx pgx.Tx, c DeviceCredential, enrolledBefore bool, limits EnrollLimits) error {
	if !enrolledBefore && limits.NewMacsPerHour > 0 {
		// A refusal doesn't need the tenant's lock: the count sees committed rows only, and
		// those stay, so a count already at the limit is exactly what the count under the
		// lock would find, or less. Without the lock, a flood of serials over the limit is
		// refused at once instead of queueing behind each other. Only a Mac with room takes
		// the lock and counts again, so two can't both take the last place.
		newMacs, err := countNewMacs(ctx, tx, c)
		if err != nil {
			return err
		}
		if limits.refusesNewMac(newMacs) {
			return ErrNewMacsLimited
		}
		if err := lockTenantNewMacs(ctx, tx, c.TenantID); err != nil {
			return err
		}
		if newMacs, err = countNewMacs(ctx, tx, c); err != nil {
			return err
		}
		if limits.refusesNewMac(newMacs) {
			return ErrNewMacsLimited
		}
	}
	if enrolledBefore && limits.KeysPerMacPerDay > 0 {
		var keys int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_credentials WHERE tenant_id = $1 AND serial = $2 AND created_at > $3`,
			c.TenantID, c.Serial, c.CreatedAt.Add(-KeysPerMacWindow)).Scan(&keys); err != nil {
			return err
		}
		if limits.refusesKey(keys) {
			return ErrKeysPerMacLimited
		}
	}
	return nil
}

func (p *Postgres) Enroll(ctx context.Context, c DeviceCredential, limits EnrollLimits) (EnrollResult, error) {
	var res EnrollResult
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		res = EnrollResult{}
		if err := lockSerial(ctx, tx, c.TenantID, c.Serial); err != nil {
			return err
		}
		existing, err := scanCredential(tx.QueryRow(ctx,
			`SELECT `+credentialColumns+` FROM device_credentials WHERE key_digest = $1`, keyDigest(c.PublicKey)))
		switch {
		case err == nil && existing.TenantID != c.TenantID:
			return ErrConflict
		case err == nil:
			res.Credential = existing
			return nil
		case !errors.Is(err, ErrNotFound):
			return err
		}

		var enrolledBefore bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_credentials WHERE tenant_id = $1 AND serial = $2)`,
			c.TenantID, c.Serial).Scan(&enrolledBefore); err != nil {
			return err
		}
		if err := enforceEnrollLimits(ctx, tx, c, enrolledBefore, limits); err != nil {
			return err
		}

		active, err := scanCredential(tx.QueryRow(ctx,
			`SELECT `+credentialColumns+` FROM device_credentials WHERE tenant_id = $1 AND serial = $2 AND status = 'active'`,
			c.TenantID, c.Serial))
		hasActive := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if hasActive {
			res.Previous = &active
		}
		settings, err := tenantSettings(ctx, tx, c.TenantID)
		if err != nil {
			return err
		}
		if holdsForApproval(settings.ReenrollmentRequiresApproval, enrolledBefore, res.Previous, c.HardwareUUID) {
			c.Status = CredentialPending
		} else {
			c.Status, c.ActivatedAt = CredentialActive, ptr(c.CreatedAt)
			if hasActive {
				if _, err := tx.Exec(ctx, `UPDATE device_credentials SET status = 'revoked', revoked_at = $2 WHERE device_id = $1`,
					active.DeviceID, c.CreatedAt); err != nil {
					return err
				}
				res.Replaced = active.DeviceID
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_credentials (device_id, tenant_id, serial, hardware_uuid, public_key, key_digest, key_storage, status, created_at, activated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			c.DeviceID, c.TenantID, c.Serial, c.HardwareUUID, c.PublicKey, keyDigest(c.PublicKey), string(c.KeyStorage),
			string(c.Status), c.CreatedAt, c.ActivatedAt); err != nil {
			return fmt.Errorf("insert credential: %w", err)
		}
		res.Credential = c
		return nil
	})
	return res, err
}

func (p *Postgres) Credential(ctx context.Context, deviceID string) (DeviceCredential, error) {
	if !isUUID(deviceID) {
		return DeviceCredential{}, ErrNotFound
	}
	return scanCredential(p.pool.QueryRow(ctx, `SELECT `+credentialColumns+` FROM device_credentials WHERE device_id = $1`, deviceID))
}

func (p *Postgres) ApproveCredential(ctx context.Context, tenantID, deviceID string, now time.Time, a AuditEntry) (DeviceCredential, error) {
	if !isUUID(deviceID) {
		return DeviceCredential{}, ErrNotFound
	}
	var out DeviceCredential
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		c, err := scanCredential(tx.QueryRow(ctx,
			`SELECT `+credentialColumns+` FROM device_credentials WHERE device_id = $1 AND tenant_id = $2`, deviceID, tenantID))
		if err != nil {
			return err
		}
		if err := lockSerial(ctx, tx, tenantID, c.Serial); err != nil {
			return err
		}
		// Re-read under the lock: a concurrent approval may have got there first.
		if c, err = scanCredential(tx.QueryRow(ctx,
			`SELECT `+credentialColumns+` FROM device_credentials WHERE device_id = $1`, deviceID)); err != nil {
			return err
		}
		if c.Status != CredentialPending {
			return ErrInvalidState
		}
		if _, err := tx.Exec(ctx, `
			UPDATE device_credentials SET status = 'revoked', revoked_at = $3
			WHERE tenant_id = $1 AND serial = $2 AND status = 'active'`, tenantID, c.Serial, now); err != nil {
			return err
		}
		if out, err = scanCredential(tx.QueryRow(ctx, `
			UPDATE device_credentials SET status = 'active', activated_at = $2 WHERE device_id = $1
			RETURNING `+credentialColumns, deviceID, now)); err != nil {
			return err
		}
		return p.insertAudit(ctx, tx, a)
	})
	return out, err
}

func (p *Postgres) RevokeCredential(ctx context.Context, tenantID, deviceID string, now time.Time, a AuditEntry) (DeviceCredential, error) {
	if !isUUID(deviceID) {
		return DeviceCredential{}, ErrNotFound
	}
	var out DeviceCredential
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var err error
		if out, err = scanCredential(tx.QueryRow(ctx, `
			UPDATE device_credentials
			SET status = 'revoked', revoked_at = COALESCE(revoked_at, $3)
			WHERE device_id = $1 AND tenant_id = $2
			RETURNING `+credentialColumns, deviceID, tenantID, now)); err != nil {
			return err
		}
		return p.insertAudit(ctx, tx, a)
	})
	return out, err
}

func (p *Postgres) ListCredentials(ctx context.Context, tenantID string, f CredentialFilter) ([]DeviceCredential, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT `+credentialColumns+` FROM device_credentials
		WHERE tenant_id = $1 AND ($2 = '' OR status = $2) AND ($3 = '' OR serial = $3)
		ORDER BY created_at DESC, device_id`, tenantID, string(f.Status), f.Serial)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceCredential{}
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) TenantSettings(ctx context.Context, tenantID string) (TenantSettings, error) {
	return tenantSettings(ctx, p.pool, tenantID)
}

func (p *Postgres) PutTenantSettings(ctx context.Context, tenantID string, s TenantSettings, a AuditEntry) error {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenant_settings (tenant_id, settings, updated_at) VALUES ($1, $2, now())
			ON CONFLICT (tenant_id) DO UPDATE SET settings = excluded.settings, updated_at = now()`, tenantID, body); err != nil {
			return err
		}
		return p.insertAudit(ctx, tx, a)
	})
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func tenantSettings(ctx context.Context, q querier, tenantID string) (TenantSettings, error) {
	var body []byte
	err := q.QueryRow(ctx, `SELECT settings FROM tenant_settings WHERE tenant_id = $1`, tenantID).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultTenantSettings(), nil
	}
	if err != nil {
		return TenantSettings{}, err
	}
	s := DefaultTenantSettings()
	if err := json.Unmarshal(body, &s); err != nil {
		return TenantSettings{}, err
	}
	return s, nil
}
