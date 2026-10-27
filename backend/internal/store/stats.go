package store

import (
	"context"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"time"
)

// Stats is what a support diagnosis needs from the database, across tenants. It holds
// counts and times only, never event content.
type Stats struct {
	ServerVersion      string           `json:"server_version"`
	MigrationsApplied  []string         `json:"migrations_applied"`
	MigrationsPending  []string         `json:"migrations_pending"` // shipped in this binary, not yet applied
	MigrationsUnknown  []string         `json:"migrations_unknown"` // applied by a newer binary
	Events             int64            `json:"events"`
	NewestEventAt      *time.Time       `json:"newest_event_received_at"`
	Devices            int64            `json:"devices"`
	DevicesSilent      int64            `json:"devices_silent"`
	DevicesSeenLastDay int64            `json:"devices_seen_last_day"`
	OpenSessions       int64            `json:"open_sessions"`
	Credentials        map[string]int64 `json:"credentials"` // by status
	PendingCommands    int64            `json:"pending_commands"`
	AuditEntries       int64            `json:"audit_entries"`
	Exports            []ExportBacklog  `json:"exports"`
	// MDM is each MDM copy's sync, by tenant and source.
	MDM []MDMSync `json:"mdm"`
	// InstalledAt is when this server's database was set up.
	InstalledAt *time.Time `json:"installed_at,omitempty"`
	// CountsSkipped says why the counts are missing: the schema isn't fully migrated, so
	// some tables may not exist yet.
	CountsSkipped string `json:"counts_skipped,omitempty"`
}

// ExportBacklog is one sink's share of the export outbox.
type ExportBacklog struct {
	Sink        string     `json:"sink"`
	Pending     int64      `json:"pending"`
	Failing     int64      `json:"failing"` // items that have failed at least once
	OldestAt    *time.Time `json:"oldest_queued_at"`
	MaxAttempts int        `json:"max_attempts"`
	LastError   string     `json:"last_error,omitempty"`
	// LastDeliveredAt is when the sink last delivered something for the tenant; nil for
	// never, and in the diagnostics' totals across tenants.
	LastDeliveredAt *time.Time `json:"last_delivered_at"`
}

// Stats gathers the diagnosis counts at now.
func (p *Postgres) Stats(ctx context.Context, now time.Time) (Stats, error) {
	s := Stats{
		Credentials: map[string]int64{}, Exports: []ExportBacklog{}, MDM: []MDMSync{},
		MigrationsApplied: []string{}, MigrationsPending: []string{}, MigrationsUnknown: []string{},
	}
	if err := p.pool.QueryRow(ctx, `SHOW server_version`).Scan(&s.ServerVersion); err != nil {
		return s, fmt.Errorf("server version: %w", err)
	}
	if err := p.migrationStatus(ctx, &s); err != nil {
		return s, err
	}
	if len(s.MigrationsPending) > 0 {
		s.CountsSkipped = "migrations pending: the server applies them when it starts"
		return s, nil
	}
	scalars := []struct {
		sql  string
		args []any
		into any
	}{
		{`SELECT count(*), max(received_at) FROM events`, nil, nil},
		{`SELECT count(*) FROM devices`, nil, &s.Devices},
		{`SELECT count(*) FROM devices WHERE state->'silence'->>'state' = 'silent'`, nil, &s.DevicesSilent},
		{`SELECT count(*) FROM devices WHERE last_seen_at >= $1`, []any{now.Add(-24 * time.Hour)}, &s.DevicesSeenLastDay},
		{`SELECT count(*) FROM sessions WHERE ended_at IS NULL`, nil, &s.OpenSessions},
		{`SELECT count(*) FROM agent_commands WHERE result IS NULL AND expires_at >= $1`, []any{now}, &s.PendingCommands},
		{`SELECT count(*) FROM audit_log`, nil, &s.AuditEntries},
	}
	for _, q := range scalars {
		var err error
		if q.into == nil {
			err = p.pool.QueryRow(ctx, q.sql).Scan(&s.Events, &s.NewestEventAt)
		} else {
			err = p.pool.QueryRow(ctx, q.sql, q.args...).Scan(q.into)
		}
		if err != nil {
			return s, fmt.Errorf("%s: %w", q.sql, err)
		}
	}

	rows, err := p.pool.Query(ctx, `SELECT status, count(*) FROM device_credentials GROUP BY status`)
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var status string
		var n int64
		if err := rows.Scan(&status, &n); err != nil {
			rows.Close()
			return s, err
		}
		s.Credentials[status] = n
	}
	rows.Close()

	if err := p.pool.QueryRow(ctx, `SELECT created_at FROM installation`).Scan(&s.InstalledAt); err != nil {
		return s, fmt.Errorf("installation: %w", err)
	}
	if s.Exports, err = p.exportBacklog(ctx, nil); err != nil {
		return s, err
	}
	s.MDM, err = p.mdmSyncs(ctx)
	return s, err
}

// mdmSyncs is every MDM copy's sync, by tenant and source.
func (p *Postgres) mdmSyncs(ctx context.Context) ([]MDMSync, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+mdmSyncColumns+` FROM mdm_sync ORDER BY tenant_id, source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MDMSync{}
	for rows.Next() {
		m, err := scanMDMSync(rows)
		if err != nil {
			return nil, err
		}
		m.LastError = truncate(m.LastError, 500)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p *Postgres) ExportStatus(ctx context.Context, tenantID string) ([]ExportBacklog, error) {
	out, err := p.exportBacklog(ctx, &tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `SELECT sink, last_delivered_at FROM export_deliveries WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sink string
		var at time.Time
		if err := rows.Scan(&sink, &at); err != nil {
			return nil, err
		}
		out = withDelivery(out, sink, at)
	}
	return out, rows.Err()
}

// withDelivery sets sink's last delivery in a backlog sorted by sink, adding the sink if
// nothing of it is waiting.
func withDelivery(out []ExportBacklog, sink string, at time.Time) []ExportBacklog {
	i, found := slices.BinarySearchFunc(out, sink, func(b ExportBacklog, s string) int { return strings.Compare(b.Sink, s) })
	if !found {
		out = slices.Insert(out, i, ExportBacklog{Sink: sink})
	}
	out[i].LastDeliveredAt = &at
	return out
}

// exportBacklog sums the outbox by sink, for one tenant or, with tenantID nil, all of them.
func (p *Postgres) exportBacklog(ctx context.Context, tenantID *string) ([]ExportBacklog, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT sink, count(*), count(*) FILTER (WHERE attempts > 0), min(created_at), max(attempts),
			(array_agg(last_error ORDER BY id DESC) FILTER (WHERE last_error IS NOT NULL))[1]
		FROM export_outbox WHERE $1::text IS NULL OR tenant_id = $1 GROUP BY sink ORDER BY sink`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExportBacklog{}
	for rows.Next() {
		var b ExportBacklog
		var lastError *string
		if err := rows.Scan(&b.Sink, &b.Pending, &b.Failing, &b.OldestAt, &b.MaxAttempts, &lastError); err != nil {
			return nil, err
		}
		if lastError != nil {
			b.LastError = truncate(*lastError, 500)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (p *Postgres) migrationStatus(ctx context.Context, s *Stats) error {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	shipped := map[string]bool{}
	for _, n := range names {
		shipped[strings.TrimSuffix(strings.TrimPrefix(n, "migrations/"), ".sql")] = true
	}
	applied := map[string]bool{}
	var exists bool
	if err := p.pool.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		for v := range shipped {
			s.MigrationsPending = append(s.MigrationsPending, v)
		}
		sort.Strings(s.MigrationsPending)
		return nil
	}
	rows, err := p.pool.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("schema_migrations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return err
		}
		applied[v] = true
		s.MigrationsApplied = append(s.MigrationsApplied, v)
		if !shipped[v] {
			s.MigrationsUnknown = append(s.MigrationsUnknown, v)
		}
	}
	for v := range shipped {
		if !applied[v] {
			s.MigrationsPending = append(s.MigrationsPending, v)
		}
	}
	sort.Strings(s.MigrationsPending)
	return rows.Err()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
