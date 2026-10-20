package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func (p *Postgres) CreateConsoleSession(ctx context.Context, s ConsoleSession, a AuditEntry) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM console_sessions WHERE expires_at <= $1`, s.CreatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO console_sessions (token_hash, tenant_id, subject, actor, name, role, csrf_token, created_at, ends_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			s.TokenHash, s.TenantID, s.Subject, s.Actor, s.Name, s.Role, s.CSRFToken, s.CreatedAt, s.EndsAt, s.ExpiresAt); err != nil {
			return err
		}
		return p.insertAudit(ctx, tx, a)
	})
}

func (p *Postgres) ConsoleSession(ctx context.Context, tokenHash []byte, now time.Time) (ConsoleSession, error) {
	var s ConsoleSession
	err := p.pool.QueryRow(ctx, `
		SELECT token_hash, tenant_id, subject, actor, name, role, csrf_token, created_at, ends_at, expires_at
		FROM console_sessions WHERE token_hash = $1 AND expires_at > $2`, tokenHash, now).Scan(
		&s.TokenHash, &s.TenantID, &s.Subject, &s.Actor, &s.Name, &s.Role, &s.CSRFToken, &s.CreatedAt, &s.EndsAt, &s.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, err
}

func (p *Postgres) ExtendConsoleSession(ctx context.Context, tokenHash []byte, expiresAt time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE console_sessions SET expires_at = LEAST(ends_at, $2) WHERE token_hash = $1`,
		tokenHash, expiresAt)
	return err
}

func (p *Postgres) EndConsoleSession(ctx context.Context, tenantID string, tokenHash []byte, a AuditEntry) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM console_sessions WHERE token_hash = $1 AND tenant_id = $2`, tokenHash, tenantID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return p.insertAudit(ctx, tx, a)
	})
}

func (p *Postgres) ListConsoleSessions(ctx context.Context, tenantID string, now time.Time) ([]ConsoleSession, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT token_hash, tenant_id, subject, actor, name, role, csrf_token, created_at, ends_at, expires_at
		FROM console_sessions WHERE tenant_id = $1 AND expires_at > $2 ORDER BY created_at DESC, actor`, tenantID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ConsoleSession{}
	for rows.Next() {
		var s ConsoleSession
		if err := rows.Scan(&s.TokenHash, &s.TenantID, &s.Subject, &s.Actor, &s.Name, &s.Role, &s.CSRFToken,
			&s.CreatedAt, &s.EndsAt, &s.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
