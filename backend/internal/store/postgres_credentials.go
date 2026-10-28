package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Altiward/altiward/backend/internal/event"
)

const credentialColumns = `device_id::text, tenant_id, serial, hardware_uuid, public_key, key_storage, token, status, created_at, activated_at, revoked_at, rotated_from::text, rotation_signed_at`

// credentialColumnsWithSuccessor adds the key's direct successor to credentialColumns. It is
// for a SELECT from device_credentials itself, by that name, not for UPDATE ... RETURNING.
const credentialColumnsWithSuccessor = credentialColumns +
	`, (SELECT s.device_id::text FROM device_credentials s WHERE s.rotated_from = device_credentials.device_id) AS rotated_to`

func scanCredential(row pgx.Row) (DeviceCredential, error) { return scanCredentialRow(row, false) }

// scanCredentialWithSuccessor scans credentialColumnsWithSuccessor.
func scanCredentialWithSuccessor(row pgx.Row) (DeviceCredential, error) {
	return scanCredentialRow(row, true)
}

func scanCredentialRow(row pgx.Row, withSuccessor bool) (DeviceCredential, error) {
	var c DeviceCredential
	var keyStorage, status string
	var rotatedFrom, rotatedTo *string
	dest := []any{&c.DeviceID, &c.TenantID, &c.Serial, &c.HardwareUUID, &c.PublicKey, &keyStorage, &c.Token, &status,
		&c.CreatedAt, &c.ActivatedAt, &c.RevokedAt, &rotatedFrom, &c.RotationSignedAt}
	if withSuccessor {
		dest = append(dest, &rotatedTo)
	}
	err := row.Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceCredential{}, ErrNotFound
	}
	c.KeyStorage = KeyStorage(keyStorage)
	c.Status = CredentialStatus(status)
	if rotatedFrom != nil {
		c.RotatedFrom = *rotatedFrom
	}
	if rotatedTo != nil {
		c.RotatedTo = *rotatedTo
	}
	return c, err
}

// credentialWithSuccessor reads a credential with its direct successor.
func credentialWithSuccessor(ctx context.Context, q querier, deviceID string) (DeviceCredential, error) {
	return scanCredentialWithSuccessor(q.QueryRow(ctx,
		`SELECT `+credentialColumnsWithSuccessor+` FROM device_credentials WHERE device_id = $1`, deviceID))
}

// lineageActive returns the active key among deviceID's key and its successors, walking
// forward along rotated_from. UNION, not UNION ALL, ends the walk even on a cycle.
func lineageActive(ctx context.Context, q querier, deviceID string) (DeviceCredential, error) {
	return scanCredential(q.QueryRow(ctx, `
		WITH RECURSIVE lineage (device_id) AS (
			SELECT device_id FROM device_credentials WHERE device_id = $1
			UNION
			SELECT d.device_id FROM device_credentials d JOIN lineage l ON d.rotated_from = l.device_id
		)
		SELECT `+credentialColumns+` FROM device_credentials
		WHERE device_id IN (SELECT device_id FROM lineage) AND status = 'active'
		LIMIT 1`, deviceID))
}

// lockSerial serialises every writer to one Mac's keys (enrolment, approval, revoke,
// rotation and contests), so two requests cannot both see "no active credential" and race
// on the unique index, and each re-reads the keys under it.
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
		// Keys made by rotation aren't enrolments, so they don't count.
		var keys int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_credentials WHERE tenant_id = $1 AND serial = $2 AND created_at > $3 AND rotated_from IS NULL`,
			c.TenantID, c.Serial, c.CreatedAt.Add(-KeysPerMacWindow)).Scan(&keys); err != nil {
			return err
		}
		if limits.refusesKey(keys) {
			return ErrKeysPerMacLimited
		}
	}
	return nil
}

// clearRetired takes the Mac back into Fleet: any new key for it, pending or active, does.
func clearRetired(ctx context.Context, tx pgx.Tx, tenantID, serial string) error {
	_, err := tx.Exec(ctx, `UPDATE devices SET retired_at = NULL WHERE tenant_id = $1 AND serial = $2 AND retired_at IS NOT NULL`,
		tenantID, serial)
	return err
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
		if holdsForApproval(settings, enrolledBefore, res.Previous, c.HardwareUUID) {
			c.Status = CredentialPending
		} else {
			c.Status, c.ActivatedAt = CredentialActive, ptr(c.CreatedAt)
			if hasActive {
				// The serial lock is held, so the key read above is still active.
				tag, err := tx.Exec(ctx, `UPDATE device_credentials SET status = 'revoked', revoked_at = $2 WHERE device_id = $1 AND status = 'active'`,
					active.DeviceID, c.CreatedAt)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 1 {
					return fmt.Errorf("replace credential %s: no longer active", active.DeviceID)
				}
				res.Replaced = active.DeviceID
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_credentials (device_id, tenant_id, serial, hardware_uuid, public_key, key_digest, key_storage, token, status, created_at, activated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			c.DeviceID, c.TenantID, c.Serial, c.HardwareUUID, c.PublicKey, keyDigest(c.PublicKey), string(c.KeyStorage), c.Token,
			string(c.Status), c.CreatedAt, c.ActivatedAt); err != nil {
			return fmt.Errorf("insert credential: %w", err)
		}
		res.Credential = c
		return clearRetired(ctx, tx, c.TenantID, c.Serial)
	})
	return res, err
}

func (p *Postgres) Credential(ctx context.Context, deviceID string) (DeviceCredential, error) {
	if !isUUID(deviceID) {
		return DeviceCredential{}, ErrNotFound
	}
	return credentialWithSuccessor(ctx, p.pool, deviceID)
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
		// Only a pending key activates. A row that is no longer pending (revoked in the
		// meantime) answers as a refused approval, never as an active key.
		if out, err = scanCredential(tx.QueryRow(ctx, `
			UPDATE device_credentials SET status = 'active', activated_at = $2
			WHERE device_id = $1 AND status = 'pending'
			RETURNING `+credentialColumns, deviceID, now)); err != nil {
			if errors.Is(err, ErrNotFound) {
				return ErrInvalidState
			}
			return err
		}
		if err := clearRetired(ctx, tx, tenantID, c.Serial); err != nil {
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
		c, err := scanCredential(tx.QueryRow(ctx,
			`SELECT `+credentialColumns+` FROM device_credentials WHERE device_id = $1 AND tenant_id = $2`, deviceID, tenantID))
		if err != nil {
			return err
		}
		// Take the Mac's lock, as approval and enrolment do, so a revoke can't run between an
		// approval's check and its update. The statements below then read the key afresh.
		if err := lockSerial(ctx, tx, tenantID, c.Serial); err != nil {
			return err
		}
		// A rotated key is already revoked; the key to revoke is its lineage's active one.
		active, err := lineageActive(ctx, tx, deviceID)
		switch {
		case err == nil && active.DeviceID != deviceID:
			return ErrRotated
		case err != nil && !errors.Is(err, ErrNotFound):
			return err
		}
		// Only this key's own change from active to revoked can retire the Mac; a pending
		// key rejected, or a key already revoked, never does.
		wasActive := err == nil
		if out, err = scanCredential(tx.QueryRow(ctx, `
			UPDATE device_credentials
			SET status = 'revoked', revoked_at = COALESCE(revoked_at, $3)
			WHERE device_id = $1 AND tenant_id = $2
			RETURNING `+credentialColumns, deviceID, tenantID, now)); err != nil {
			return err
		}
		if wasActive {
			var left bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_credentials WHERE tenant_id = $1 AND serial = $2 AND status <> 'revoked')`,
				tenantID, c.Serial).Scan(&left); err != nil {
				return err
			}
			if !left {
				if _, err := tx.Exec(ctx, `UPDATE devices SET retired_at = $3 WHERE tenant_id = $1 AND serial = $2`,
					tenantID, c.Serial, now); err != nil {
					return err
				}
				a = withRetired(a)
			}
		}
		return p.insertAudit(ctx, tx, a)
	})
	return out, err
}

func (p *Postgres) ListCredentials(ctx context.Context, tenantID string, f CredentialFilter) ([]DeviceCredential, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT `+credentialColumnsWithSuccessor+` FROM device_credentials
		WHERE tenant_id = $1 AND ($2 = '' OR status = $2) AND ($3 = '' OR serial = $3)
		ORDER BY created_at DESC, device_id`, tenantID, string(f.Status), f.Serial)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceCredential{}
	for rows.Next() {
		c, err := scanCredentialWithSuccessor(rows)
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

func (p *Postgres) Rotate(ctx context.Context, r RotateRequest) (RotateResult, error) {
	if !isUUID(r.FromDeviceID) {
		return RotateResult{}, ErrNotFound
	}
	var res RotateResult
	// refused is a refusal that still commits: a contest's changes stand.
	var refused error
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		res, refused = RotateResult{}, nil
		cur, err := scanCredential(tx.QueryRow(ctx,
			`SELECT `+credentialColumns+` FROM device_credentials WHERE device_id = $1 AND tenant_id = $2`, r.FromDeviceID, r.TenantID))
		if err != nil {
			return err
		}
		if err := lockSerial(ctx, tx, cur.TenantID, cur.Serial); err != nil {
			return err
		}
		if cur, err = credentialWithSuccessor(ctx, tx, r.FromDeviceID); err != nil {
			return err
		}
		res.Previous = cur

		if cur.Status == CredentialRevoked && cur.RotatedTo != "" {
			next, err := credentialWithSuccessor(ctx, tx, cur.RotatedTo)
			if err != nil {
				return err
			}
			// The same request again, perhaps long after: its answer was lost. This comes
			// before every limit.
			if bytes.Equal(next.PublicKey, r.PublicKey) {
				res.Credential, res.Retry = next, true
				return nil
			}
			// Someone else holds this stale key.
			c, err := p.contest(ctx, tx, cur, next, r.Now, r.Alert)
			if err != nil {
				return err
			}
			res.Contest, refused = &c, ErrRotatedElsewhere
			return nil
		}
		switch {
		case cur.Status == CredentialRevoked:
			return ErrRevoked
		case cur.Status != CredentialActive:
			return ErrInvalidState
		case cur.KeyStorage == KeyStorageSecureEnclave:
			return ErrRotationNotAllowed
		case cur.ActivatedAt != nil && r.Now.Before(cur.ActivatedAt.Add(MinRotationInterval)):
			return ErrRotationTooSoon
		}
		var inUse bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_credentials WHERE key_digest = $1)`,
			keyDigest(r.PublicKey)).Scan(&inUse); err != nil {
			return err
		}
		if inUse {
			return ErrKeyInUse
		}
		tag, err := tx.Exec(ctx, `UPDATE device_credentials SET status = 'revoked', revoked_at = $2 WHERE device_id = $1 AND status = 'active'`,
			cur.DeviceID, r.Now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("rotate credential %s: no longer active", cur.DeviceID)
		}
		next := DeviceCredential{
			DeviceID: r.DeviceID, TenantID: cur.TenantID, Serial: cur.Serial, HardwareUUID: cur.HardwareUUID,
			PublicKey: r.PublicKey, KeyStorage: r.KeyStorage, Token: cur.Token, Status: CredentialActive,
			CreatedAt: r.Now, ActivatedAt: ptr(r.Now), RotatedFrom: cur.DeviceID, RotationSignedAt: ptr(r.SignedAt),
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_credentials (device_id, tenant_id, serial, hardware_uuid, public_key, key_digest, key_storage, token,
				status, created_at, activated_at, rotated_from, rotation_signed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			next.DeviceID, next.TenantID, next.Serial, next.HardwareUUID, next.PublicKey, keyDigest(next.PublicKey),
			string(next.KeyStorage), next.Token, string(next.Status), next.CreatedAt, next.ActivatedAt, next.RotatedFrom,
			next.RotationSignedAt); err != nil {
			// An enrolment of the same key, on another Mac, committed after the check above.
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "device_credentials_key_digest_key" {
				return ErrKeyInUse
			}
			return fmt.Errorf("insert credential: %w", err)
		}
		res.Credential = next
		return clearRetired(ctx, tx, next.TenantID, next.Serial)
	})
	if err != nil {
		return res, err
	}
	return res, refused
}

// contest resolves a use of stale, whose direct successor is next, in tx under the Mac's
// lock. It revokes the Mac's active key if that descends from stale and next is within
// ContestWindow, and moves stale's report marker on if it is NULL or a day old. When that
// calls for a report, it stores alert's event in tx too.
func (p *Postgres) contest(ctx context.Context, tx pgx.Tx, stale, next DeviceCredential, now time.Time, alert ContestAlert) (ContestResult, error) {
	res := ContestResult{Stale: stale}
	if withinContestWindow(next, now) {
		active, err := lineageActive(ctx, tx, stale.DeviceID)
		switch {
		case err == nil:
			revoked, err := scanCredential(tx.QueryRow(ctx, `
				UPDATE device_credentials SET status = 'revoked', revoked_at = $2
				WHERE device_id = $1 AND status = 'active'
				RETURNING `+credentialColumns, active.DeviceID, now))
			if err != nil {
				return res, err
			}
			res.Revoked = &revoked
		case !errors.Is(err, ErrNotFound):
			return res, err
		}
	}
	tag, err := tx.Exec(ctx, `
		UPDATE device_credentials SET stale_use_reported_at = $2
		WHERE device_id = $1 AND (stale_use_reported_at IS NULL OR stale_use_reported_at < $3)`,
		stale.DeviceID, now, now.Add(-staleUseReportInterval))
	if err != nil {
		return res, err
	}
	res.Report = res.Revoked != nil || tag.RowsAffected() == 1
	if res.Report && alert != nil {
		if _, err := p.ingest(ctx, tx, stale.TenantID, []event.Event{alert(res)}, now); err != nil {
			return res, fmt.Errorf("store the rotated key's use: %w", err)
		}
	}
	return res, nil
}

func (p *Postgres) StaleKeyUsed(ctx context.Context, deviceID string, signedAt, now time.Time, alert ContestAlert) (*ContestResult, error) {
	if !isUUID(deviceID) {
		return nil, ErrNotFound
	}
	var out *ContestResult
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		out = nil
		stale, err := scanCredential(tx.QueryRow(ctx, `SELECT `+credentialColumns+` FROM device_credentials WHERE device_id = $1`, deviceID))
		if err != nil {
			return err
		}
		if err := lockSerial(ctx, tx, stale.TenantID, stale.Serial); err != nil {
			return err
		}
		if stale, err = credentialWithSuccessor(ctx, tx, deviceID); err != nil {
			return err
		}
		if stale.Status != CredentialRevoked || stale.RotatedTo == "" {
			return nil
		}
		next, err := scanCredential(tx.QueryRow(ctx, `SELECT `+credentialColumns+` FROM device_credentials WHERE device_id = $1`, stale.RotatedTo))
		if err != nil {
			return err
		}
		if inFlight(next, signedAt, now) {
			return nil
		}
		c, err := p.contest(ctx, tx, stale, next, now, alert)
		if err != nil {
			return err
		}
		out = &c
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *Postgres) LineageActive(ctx context.Context, deviceID string) (DeviceCredential, error) {
	if !isUUID(deviceID) {
		return DeviceCredential{}, ErrNotFound
	}
	return lineageActive(ctx, p.pool, deviceID)
}
