package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Altiward/altiward/backend/internal/command"
)

const commandColumns = `command_id::text, tenant_id, serial, type, user_name, session_id::text, issued_by,
	created_at, expires_at, delivered_at, result, result_at`

func scanCommand(row pgx.Row) (command.Command, error) {
	var c command.Command
	var result []byte
	err := row.Scan(&c.CommandID, &c.TenantID, &c.Serial, &c.Type, &c.User, &c.SessionID, &c.IssuedBy,
		&c.CreatedAt, &c.ExpiresAt, &c.DeliveredAt, &result, &c.ResultAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return command.Command{}, ErrNotFound
	}
	if err != nil {
		return command.Command{}, err
	}
	if result != nil {
		c.Result = &command.Result{}
		if err := json.Unmarshal(result, c.Result); err != nil {
			return command.Command{}, fmt.Errorf("decode result: %w", err)
		}
	}
	return c, nil
}

func collectCommands(rows pgx.Rows, err error) ([]command.Command, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []command.Command{}
	for rows.Next() {
		c, err := scanCommand(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) CreateCommand(ctx context.Context, c command.Command, a AuditEntry) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO agent_commands (command_id, tenant_id, serial, type, user_name, session_id, issued_by, created_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			c.CommandID, c.TenantID, c.Serial, c.Type, c.User, c.SessionID, c.IssuedBy, c.CreatedAt, c.ExpiresAt); err != nil {
			return err
		}
		// Delivered at commit, to every API instance listening.
		payload, _ := json.Marshal(commandNotice{TenantID: c.TenantID, Serial: c.Serial})
		if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, commandChannel, string(payload)); err != nil {
			return err
		}
		return p.insertAudit(ctx, tx, a)
	})
}

// commandChannel is the Postgres NOTIFY channel that says a command was queued.
const commandChannel = "altiward_commands"

type commandNotice struct {
	TenantID string `json:"tenant_id"`
	Serial   string `json:"serial"`
}

// WatchCommands starts this instance's listener on first use.
func (p *Postgres) WatchCommands(tenantID, serial string) (<-chan struct{}, func()) {
	p.listenOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		p.stopListen, p.listenerDone = cancel, make(chan struct{})
		go p.listen(ctx)
	})
	return p.watchers.watch(tenantID, serial)
}

// listen holds one connection of its own on LISTEN and wakes this instance's watchers,
// reconnecting with backoff until Close. After each (re)connect it wakes everyone, since
// commands may have been queued while it wasn't listening.
func (p *Postgres) listen(ctx context.Context) {
	defer close(p.listenerDone)
	backoff := time.Second
	for ctx.Err() == nil {
		if p.listenUntilBroken(ctx) {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}

// listenUntilBroken listens on one connection until it fails or ctx ends, and says
// whether it got as far as listening.
func (p *Postgres) listenUntilBroken(ctx context.Context) bool {
	conn, err := pgx.ConnectConfig(ctx, p.pool.Config().ConnConfig.Copy())
	if err != nil {
		return false
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `LISTEN `+commandChannel); err != nil {
		return false
	}
	p.watchers.notifyAll()
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return true
		}
		var notice commandNotice
		if json.Unmarshal([]byte(n.Payload), &notice) == nil {
			p.watchers.notify(notice.TenantID, notice.Serial)
		}
	}
}

func (p *Postgres) PendingCommands(ctx context.Context, tenantID, serial string, now time.Time) ([]command.Command, error) {
	cs, err := collectCommands(p.pool.Query(ctx, `
		UPDATE agent_commands SET delivered_at = COALESCE(delivered_at, $3)
		WHERE tenant_id = $1 AND serial = $2 AND result IS NULL AND expires_at >= $3
		RETURNING `+commandColumns, tenantID, serial, now))
	if err != nil {
		return nil, err
	}
	sortCommands(cs, false) // RETURNING has no order
	return cs, nil
}

func (p *Postgres) RecordCommandResult(ctx context.Context, tenantID, serial, commandID string, r command.Result, receivedAt time.Time) (command.Command, error) {
	if !isUUID(commandID) {
		return command.Command{}, ErrNotFound
	}
	body, err := json.Marshal(r)
	if err != nil {
		return command.Command{}, err
	}
	return scanCommand(p.pool.QueryRow(ctx, `
		UPDATE agent_commands SET result = COALESCE(result, $4), result_at = COALESCE(result_at, $5)
		WHERE command_id = $1 AND tenant_id = $2 AND serial = $3
		RETURNING `+commandColumns, commandID, tenantID, serial, body, receivedAt))
}

func (p *Postgres) GetCommand(ctx context.Context, tenantID, commandID string) (command.Command, error) {
	if !isUUID(commandID) {
		return command.Command{}, ErrNotFound
	}
	return scanCommand(p.pool.QueryRow(ctx,
		`SELECT `+commandColumns+` FROM agent_commands WHERE command_id = $1 AND tenant_id = $2`, commandID, tenantID))
}

func (p *Postgres) ListCommands(ctx context.Context, tenantID string, f CommandFilter, now time.Time) ([]command.Command, error) {
	// Mirrors command.Command.Status: a result wins; otherwise pending until expires_at.
	return collectCommands(p.pool.Query(ctx, `
		SELECT `+commandColumns+` FROM agent_commands
		WHERE tenant_id = $1 AND ($2 = '' OR serial = $2) AND (
			$3 = ''
			OR ($3 = 'pending' AND result IS NULL AND expires_at >= $4)
			OR ($3 = 'expired' AND result IS NULL AND expires_at < $4)
			OR result->>'status' = $3)
		ORDER BY created_at DESC, command_id
		LIMIT 500`, tenantID, f.Serial, string(f.Status), now))
}
