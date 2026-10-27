package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// insertAudit records a and queues it for every export sink, inside the transaction that
// makes the change it records.
func (p *Postgres) insertAudit(ctx context.Context, tx pgx.Tx, a AuditEntry) error {
	a.normalize()
	if !isUUID(a.ID) {
		return fmt.Errorf("audit entry: id %q is not a UUID", a.ID)
	}
	detail, err := json.Marshal(a.Detail)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (tenant_id, id, at, actor, action, target, detail) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		a.TenantID, a.ID, a.At, a.Actor, a.Action, a.Target, detail); err != nil {
		return fmt.Errorf("record audit entry: %w", err)
	}
	for _, sink := range p.sinks {
		if _, err := tx.Exec(ctx, `
			INSERT INTO export_outbox (tenant_id, sink, audit_id, next_attempt_at) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING`, a.TenantID, sink, a.ID, a.At); err != nil {
			return fmt.Errorf("queue audit export: %w", err)
		}
	}
	return nil
}

func (p *Postgres) RecordAudit(ctx context.Context, a AuditEntry) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error { return p.insertAudit(ctx, tx, a) })
}

func (p *Postgres) RecordTokenSignIn(ctx context.Context, a AuditEntry, within time.Duration) (time.Time, error) {
	covered := a.At
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// SET LOCAL ends with the transaction, so the pooled connection keeps its setting.
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
			return err
		}
		// Calls for one actor queue here, so the first records and the rest find it.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 7243100004))`,
			a.TenantID+"/"+a.Actor); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `
			SELECT at FROM audit_log
			WHERE tenant_id = $1 AND action = 'sign_in' AND actor = $2 AND detail->>'method' = 'token'
			AND at >= $3 AND at <= $4 ORDER BY at DESC LIMIT 1`,
			a.TenantID, a.Actor, a.At.Add(-within), a.At.Add(tokenSignInSkew)).Scan(&covered)
		if errors.Is(err, pgx.ErrNoRows) {
			covered = a.At
			return p.insertAudit(ctx, tx, a)
		}
		return err
	})
	if err != nil {
		return time.Time{}, err
	}
	return covered, nil
}

func (p *Postgres) ListAudit(ctx context.Context, tenantID string, f AuditFilter) ([]AuditEntry, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT tenant_id, id::text, at, actor, action, target, detail, seq FROM audit_log
		WHERE tenant_id = $1 AND ($2::timestamptz IS NULL OR at < $2 OR (at = $2 AND seq < $3::bigint))
		ORDER BY at DESC, seq DESC LIMIT $4`, tenantID, f.Before, f.BeforeSeq, auditLimit(f.Limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		var detail []byte
		if err := rows.Scan(&a.TenantID, &a.ID, &a.At, &a.Actor, &a.Action, &a.Target, &detail, &a.Seq); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(detail, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) PurgeAudit(ctx context.Context, before time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx, `
		DELETE FROM audit_log a WHERE a.at < $1 AND a.at < now() - interval '365 days'
		AND NOT EXISTS (SELECT 1 FROM export_outbox o WHERE o.tenant_id = a.tenant_id AND o.audit_id = a.id)`, before)
	if err != nil {
		return 0, fmt.Errorf("purge audit log: %w", err)
	}
	return tag.RowsAffected(), nil
}
