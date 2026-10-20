package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/session"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Postgres is the production Store.
type Postgres struct {
	pool  *pgxpool.Pool
	sinks []string

	watchers     commandWatchers
	listenOnce   sync.Once
	stopListen   context.CancelFunc // nil until the first WatchCommands
	listenerDone chan struct{}
}

// OpenPostgres connects, applies pending migrations and returns the store.
func OpenPostgres(ctx context.Context, url string, exportSinks []string) (*Postgres, error) {
	p, err := ConnectPostgres(ctx, url, exportSinks)
	if err != nil {
		return nil, err
	}
	if err := p.migrate(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// ConnectPostgres connects without applying migrations, for tools that must not change
// the database, such as diagnostics.
func ConnectPostgres(ctx context.Context, url string, exportSinks []string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Postgres{pool: pool, sinks: exportSinks}, nil
}

func (p *Postgres) Close() {
	// Settles the once, so a WatchCommands racing Close can't start a listener after it.
	p.listenOnce.Do(func() {})
	if p.stopListen != nil {
		p.stopListen()
		<-p.listenerDone
	}
	p.pool.Close()
}

// migrate applies migrations/NNNN_*.sql in order, once each, under an advisory lock
// so several API replicas starting together don't race.
func (p *Postgres) migrate(ctx context.Context) error {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7243100001)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			return err
		}
		for _, name := range names {
			version := strings.TrimSuffix(strings.TrimPrefix(name, "migrations/"), ".sql")
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&exists); err != nil {
				return err
			}
			if exists {
				continue
			}
			sql, err := migrations.ReadFile(name)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("migration %s: %w", version, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
				return err
			}
		}
		return nil
	})
}

func (p *Postgres) Ingest(ctx context.Context, tenantID string, events []event.Event, receivedAt time.Time) (IngestResult, error) {
	res := IngestResult{Accepted: []string{}, Duplicate: []string{}}
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		res = IngestResult{Accepted: []string{}, Duplicate: []string{}}
		for _, e := range events {
			body, err := json.Marshal(e)
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `
				INSERT INTO events (tenant_id, event_id, type, session_id, device_serial, occurred_at, received_at, body)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				ON CONFLICT (tenant_id, event_id) DO NOTHING`,
				tenantID, e.EventID, string(e.Type), e.SessionID, e.Device.Serial, e.Timestamp, receivedAt, body)
			if err != nil {
				return fmt.Errorf("insert event: %w", err)
			}
			if tag.RowsAffected() == 0 {
				res.Duplicate = append(res.Duplicate, e.EventID)
				continue
			}
			if e.SessionID != nil {
				if err := p.applySession(ctx, tx, tenantID, *e.SessionID, e, receivedAt); err != nil {
					return err
				}
			}
			if err := p.applyDevice(ctx, tx, tenantID, e, receivedAt); err != nil {
				return err
			}
			for _, sink := range p.sinks {
				if _, err := tx.Exec(ctx, `
					INSERT INTO export_outbox (tenant_id, sink, event_id, next_attempt_at) VALUES ($1, $2, $3, $4)
					ON CONFLICT DO NOTHING`, tenantID, sink, e.EventID, receivedAt); err != nil {
					return fmt.Errorf("queue export: %w", err)
				}
			}
			res.Accepted = append(res.Accepted, e.EventID)
		}
		return nil
	})
	return res, err
}

func (p *Postgres) applySession(ctx context.Context, tx pgx.Tx, tenantID, sessionID string, e event.Event, now time.Time) error {
	s := session.New(tenantID, sessionID)
	var state []byte
	err := tx.QueryRow(ctx, `SELECT state FROM sessions WHERE tenant_id = $1 AND session_id = $2 FOR UPDATE`,
		tenantID, sessionID).Scan(&state)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return fmt.Errorf("load session: %w", err)
	default:
		if err := json.Unmarshal(state, &s); err != nil {
			return fmt.Errorf("decode session: %w", err)
		}
	}
	s.Apply(e)
	state, err = json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO sessions (tenant_id, session_id, device_serial, local_user, started_at, ended_at, state, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, session_id) DO UPDATE SET
			device_serial = excluded.device_serial, local_user = excluded.local_user,
			started_at = excluded.started_at, ended_at = excluded.ended_at,
			state = excluded.state, updated_at = excluded.updated_at`,
		tenantID, sessionID, s.DeviceSerial, s.LocalUser, s.StartedAt, s.EndedAt, state, now)
	if err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

func (p *Postgres) applyDevice(ctx context.Context, tx pgx.Tx, tenantID string, e event.Event, receivedAt time.Time) error {
	d := session.NewDevice(tenantID, e.Device.Serial)
	var state []byte
	err := tx.QueryRow(ctx, `SELECT state FROM devices WHERE tenant_id = $1 AND serial = $2 FOR UPDATE`,
		tenantID, e.Device.Serial).Scan(&state)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return fmt.Errorf("load device: %w", err)
	default:
		if err := json.Unmarshal(state, &d); err != nil {
			return fmt.Errorf("decode device: %w", err)
		}
	}
	d.Apply(e)
	d.Received(e, receivedAt)
	state, err = json.Marshal(d)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO devices (tenant_id, serial, state, last_seen_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, serial) DO UPDATE SET state = excluded.state, last_seen_at = excluded.last_seen_at`,
		tenantID, d.Serial, state, d.CheckedInAt())
	if err != nil {
		return fmt.Errorf("save device: %w", err)
	}
	return nil
}

func (p *Postgres) ListSessions(ctx context.Context, tenantID string, f SessionFilter) ([]session.Session, error) {
	where := []string{"tenant_id = $1"}
	args := []any{tenantID}
	add := func(clause string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.DeviceSerial != "" {
		add("device_serial = $%d", f.DeviceSerial)
	}
	if f.LocalUser != "" {
		add("local_user = $%d", f.LocalUser)
	}
	if f.OpenOnly {
		where = append(where, "ended_at IS NULL")
	}
	if f.Since != nil {
		add("started_at >= $%d", *f.Since)
	}
	if f.Until != nil {
		add("started_at < $%d", *f.Until)
	}
	args = append(args, clampLimit(f.Limit))
	sql := fmt.Sprintf(`SELECT state FROM sessions WHERE %s ORDER BY started_at DESC NULLS LAST, session_id LIMIT $%d`,
		strings.Join(where, " AND "), len(args))
	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return collectJSON[session.Session](rows)
}

func (p *Postgres) ReportSessions(ctx context.Context, tenantID string, since time.Time) ([]session.Session, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT state FROM sessions WHERE tenant_id = $1 AND (ended_at IS NULL OR started_at >= $2)
		ORDER BY started_at DESC NULLS LAST, session_id`, tenantID, since)
	if err != nil {
		return nil, err
	}
	return collectJSON[session.Session](rows)
}

func (p *Postgres) GetSession(ctx context.Context, tenantID, sessionID string) (session.Session, []StoredEvent, error) {
	var s session.Session
	var state []byte
	err := p.pool.QueryRow(ctx, `SELECT state FROM sessions WHERE tenant_id = $1 AND session_id = $2`,
		tenantID, sessionID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil, ErrNotFound
	}
	if err != nil {
		return s, nil, err
	}
	if err := json.Unmarshal(state, &s); err != nil {
		return s, nil, err
	}
	rows, err := p.pool.Query(ctx, `
		SELECT body, received_at FROM events WHERE tenant_id = $1 AND session_id = $2
		ORDER BY occurred_at, received_at, event_id`, tenantID, sessionID)
	if err != nil {
		return s, nil, err
	}
	evs := []StoredEvent{}
	for rows.Next() {
		var body []byte
		var se StoredEvent
		if err := rows.Scan(&body, &se.ReceivedAt); err != nil {
			rows.Close()
			return s, nil, err
		}
		if err := json.Unmarshal(body, &se.Event); err != nil {
			rows.Close()
			return s, nil, err
		}
		evs = append(evs, se)
	}
	return s, evs, rows.Err()
}

func (p *Postgres) ListDevices(ctx context.Context, tenantID string) ([]session.Device, error) {
	rows, err := p.pool.Query(ctx, `SELECT state FROM devices WHERE tenant_id = $1 ORDER BY serial`, tenantID)
	if err != nil {
		return nil, err
	}
	return collectJSON[session.Device](rows)
}

func (p *Postgres) SilenceCandidates(ctx context.Context, seenBefore time.Time) ([]session.Device, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT state FROM devices WHERE last_seen_at <= $1 OR state->'silence'->>'state' = 'silent'
		ORDER BY tenant_id, serial`, seenBefore)
	if err != nil {
		return nil, err
	}
	return collectJSON[session.Device](rows)
}

func (p *Postgres) ClaimExports(ctx context.Context, sink string, limit int, lease time.Duration, now time.Time) ([]ExportItem, error) {
	rows, err := p.pool.Query(ctx, `
		WITH due AS (
			SELECT id FROM export_outbox
			WHERE sink = $1 AND next_attempt_at <= $2 AND (leased_until IS NULL OR leased_until <= $2)
			ORDER BY id LIMIT $3
			FOR UPDATE SKIP LOCKED
		), leased AS (
			UPDATE export_outbox o SET leased_until = $4 FROM due WHERE o.id = due.id
			RETURNING o.id, o.tenant_id, o.sink, o.attempts, o.event_id, o.audit_id
		)
		SELECT l.id, l.tenant_id, l.sink, l.attempts, e.body, e.received_at,
			a.id::text, a.at, a.actor, a.action, a.target, a.detail, a.seq
		FROM leased l
		LEFT JOIN events e ON e.tenant_id = l.tenant_id AND e.event_id = l.event_id
		LEFT JOIN audit_log a ON a.tenant_id = l.tenant_id AND a.id = l.audit_id
		ORDER BY l.id`, sink, now, limit, now.Add(lease))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExportItem{}
	for rows.Next() {
		var it ExportItem
		var body, detail []byte
		var receivedAt, at *time.Time
		var auditID, actor, action, target *string
		var seq *int64
		if err := rows.Scan(&it.ID, &it.TenantID, &it.Sink, &it.Attempts, &body, &receivedAt,
			&auditID, &at, &actor, &action, &target, &detail, &seq); err != nil {
			return nil, err
		}
		if auditID != nil {
			it.Audit = &AuditEntry{ID: *auditID, TenantID: it.TenantID, At: *at, Actor: *actor, Action: *action,
				Target: *target, Seq: *seq}
			if err := json.Unmarshal(detail, &it.Audit.Detail); err != nil {
				return nil, err
			}
		} else {
			it.Event.ReceivedAt = *receivedAt
			if err := json.Unmarshal(body, &it.Event.Event); err != nil {
				return nil, err
			}
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (p *Postgres) CompleteExports(ctx context.Context, ids []int64, deliveredAt time.Time) error {
	_, err := p.pool.Exec(ctx, `
		WITH done AS (DELETE FROM export_outbox WHERE id = ANY($1) RETURNING tenant_id, sink)
		INSERT INTO export_deliveries (tenant_id, sink, last_delivered_at)
		SELECT DISTINCT tenant_id, sink, $2::timestamptz FROM done
		ON CONFLICT (tenant_id, sink) DO UPDATE
		SET last_delivered_at = greatest(export_deliveries.last_delivered_at, excluded.last_delivered_at)`,
		ids, deliveredAt)
	return err
}

func (p *Postgres) RetryExports(ctx context.Context, ids []int64, lastError string, retryAt time.Time) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE export_outbox SET attempts = attempts + 1, last_error = $2, next_attempt_at = $3, leased_until = NULL
		WHERE id = ANY($1)`, ids, lastError, retryAt)
	return err
}

func (p *Postgres) RetryExportsNow(ctx context.Context, tenantID, sink string, now time.Time, a AuditEntry) (int64, error) {
	var n int64
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE export_outbox SET next_attempt_at = $3
			WHERE tenant_id = $1 AND sink = $2 AND next_attempt_at > $3 AND (leased_until IS NULL OR leased_until <= $3)`,
			tenantID, sink, now)
		if err != nil {
			return fmt.Errorf("retry exports now: %w", err)
		}
		n = tag.RowsAffected()
		return p.insertAudit(ctx, tx, a)
	})
	return n, err
}

// DropExports removes everything queued for sink and returns how many items it removed.
// It is for a sink taken out of the configuration, whose queue nothing drains any more;
// the events themselves stay. The caller checks the sink isn't configured.
func (p *Postgres) DropExports(ctx context.Context, sink string) (int64, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM export_outbox WHERE sink = $1`, sink)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ReplayExports queues for sink the events received, and the console actions recorded,
// since since, oldest first, and returns how many it queued. It is for a sink added after
// they were written, which they were never queued for. Anything already waiting for sink
// stays as it is; anything sent before is sent again. The caller checks sink is configured.
func (p *Postgres) ReplayExports(ctx context.Context, sink string, since, now time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx, `
		INSERT INTO export_outbox (tenant_id, sink, event_id, audit_id, next_attempt_at)
		SELECT tenant_id, $1, event_id, audit_id, $3 FROM (
			SELECT tenant_id, event_id, NULL::uuid AS audit_id, received_at AS t, 0 AS seq
				FROM events WHERE received_at >= $2
			UNION ALL
			SELECT tenant_id, NULL::uuid, id, at, seq FROM audit_log WHERE at >= $2
		) owed ORDER BY t, seq
		ON CONFLICT DO NOTHING`, sink, since, now)
	if err != nil {
		return 0, fmt.Errorf("replay exports: %w", err)
	}
	return tag.RowsAffected(), nil
}

func collectJSON[T any](rows pgx.Rows) ([]T, error) {
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
