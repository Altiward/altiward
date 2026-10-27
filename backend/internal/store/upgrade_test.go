package store

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// TestPostgresUpgradesFromEveryMigration stands for upgrading from any release: whichever
// migration a site's database stopped at, with data written by the code of that time,
// the current server must finish migrating it, read the old data and write new data.
// It includes the newest migration, where opening applies nothing and must leave the
// bookkeeping alone. Each case runs in its own schema.
func TestPostgresUpgradesFromEveryMigration(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	ctx := context.Background()
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")

	for applied := 1; applied <= len(names); applied++ {
		from := strings.TrimSuffix(strings.TrimPrefix(names[applied-1], "migrations/"), ".sql")
		t.Run("from "+from, func(t *testing.T) {
			scoped := inSchema(t, url, "upgrade_"+randomHex(t))
			old, err := pgxpool.New(ctx, scoped)
			if err != nil {
				t.Fatal(err)
			}
			applyFirst(t, old, names[:applied])
			seedOldData(t, old, now)
			old.Close()

			s, err := OpenPostgres(ctx, scoped, nil)
			if err != nil {
				t.Fatalf("upgrade from %s: %v", from, err)
			}
			defer s.Close()

			// Old rows read back through today's code.
			devices, err := s.ListDevices(ctx, "acme")
			if err != nil || len(devices) != 1 || devices[0].AdminMembers[0] != "itadmin" || devices[0].Silent() {
				t.Fatalf("old device: %+v, %v", devices, err)
			}
			sess, evs, err := s.GetSession(ctx, "acme", oldSessionID)
			if err != nil || sess.LocalUser != "jdoe" || len(evs) != 1 {
				t.Fatalf("old session: %+v %v, %v", sess, evs, err)
			}
			cred, err := s.Credential(ctx, "7e8f90a1-b2c3-4d4e-8f5a-6b7c8d9e0f1a")
			if err != nil || cred.Status != CredentialActive || cred.KeyStorage != KeyStorageUnknown ||
				cred.RotatedFrom != "" || cred.RotatedTo != "" || cred.RotationSignedAt != nil {
				t.Fatalf("old credential: %+v, %v", cred, err)
			}
			queued, err := s.ClaimExports(ctx, "splunk", 10, time.Minute, now)
			if err != nil || len(queued) != 1 || queued[0].Audit != nil || queued[0].Event.User.LocalName != "jdoe" {
				t.Fatalf("old export: %+v, %v", queued, err)
			}
			// New writes work on top of them, including tables later migrations added.
			health := testfixture.Event(t, "agent-health")
			health.Device.Serial = "C02OLD000001"
			health.Timestamp = now
			if res, err := s.Ingest(ctx, "acme", []event.Event{health}, now); err != nil || len(res.Accepted) != 1 {
				t.Fatalf("ingest after upgrade: %+v, %v", res, err)
			}
			enrolled, err := s.Enroll(ctx, DeviceCredential{
				DeviceID: newUUID(t), TenantID: "acme", Serial: "C02NEW000001", HardwareUUID: "HW-NEW", PublicKey: newKey(t),
				KeyStorage: KeyStorageSecureEnclave, CreatedAt: now,
			}, DefaultEnrollLimits()) // the limits count the old rows too
			if err != nil || enrolled.Credential.KeyStorage != KeyStorageSecureEnclave {
				t.Fatalf("enroll after upgrade: %+v, %v", enrolled, err)
			}
			// The old key, activated an hour before now, rotates a day later.
			rotated, err := s.Rotate(ctx, RotateRequest{
				TenantID: "acme", FromDeviceID: cred.DeviceID, DeviceID: newUUID(t), PublicKey: newKey(t),
				KeyStorage: KeyStorageSecureEnclave, SignedAt: now.Add(24 * time.Hour), Now: now.Add(24 * time.Hour),
			})
			if err != nil || rotated.Credential.RotatedFrom != cred.DeviceID || rotated.Credential.Serial != "C02OLD000001" {
				t.Fatalf("rotate after upgrade: %+v, %v", rotated, err)
			}
			if old, err := s.Credential(ctx, cred.DeviceID); err != nil || old.Status != CredentialRevoked || old.RotatedTo != rotated.Credential.DeviceID {
				t.Fatalf("old credential after rotation: %+v, %v", old, err)
			}
			if err := s.PutTenantSettings(ctx, "acme", TenantSettings{SilentAfterHours: 24}, auditFor(t, "acme", AuditChangeSettings)); err != nil {
				t.Fatalf("settings after upgrade: %v", err)
			}
			audit, err := s.ListAudit(ctx, "acme", AuditFilter{})
			if err != nil || len(audit) != 2 || audit[0].Action != AuditChangeSettings {
				t.Fatalf("audit after upgrade: %+v, %v", audit, err)
			}
			if in, err := s.Installation(ctx); err != nil || in.CreatedAt.IsZero() {
				t.Fatalf("installation after upgrade: %+v, %v", in, err)
			}
			st, err := s.Stats(ctx, now)
			if err != nil || len(st.MigrationsPending) != 0 || len(st.MigrationsApplied) != len(names) ||
				st.Devices != 1 || st.AuditEntries != 2 || st.InstalledAt == nil {
				t.Fatalf("stats after upgrade: %+v, %v", st, err)
			}
		})
	}
}

const oldSessionID = "5b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"

// inSchema returns url pointing at a fresh schema, dropped when the test ends.
func inSchema(t *testing.T, url, schema string) string {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	return url + sep + "search_path=" + schema
}

// applyFirst applies migrations as migrate does, stopping early.
func applyFirst(t *testing.T, pool *pgxpool.Pool, names []string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		sql, err := migrations.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		version := strings.TrimSuffix(strings.TrimPrefix(name, "migrations/"), ".sql")
		if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			t.Fatal(err)
		}
	}
}

// seedOldData writes rows the way the first release did, with only the fields it always
// sets, so a field added later must decode from its absence: a device, an open session
// with its event and that event's export, a credential and an audit entry. It seeds only
// tables the first migration creates; when a later migration adds a table, seed that
// table only in the cases where its migration has been applied.
func seedOldData(t *testing.T, pool *pgxpool.Pool, now time.Time) {
	t.Helper()
	ctx := context.Background()
	seen := now.Add(-time.Hour).Format(time.RFC3339)
	device := fmt.Sprintf(`{"tenant_id":"acme","serial":"C02OLD000001","hardware_uuid":"HW-OLD","os_version":"15.5",
		"agent_version":"0.1.0","privileges_version":"2.4.0","first_seen_at":%q,"last_seen_at":%q,"last_health_at":%q,
		"admin_members":["itadmin"],"queue_depth":0,"privileges":{"installed":true}}`, seen, seen, seen)
	session := fmt.Sprintf(`{"tenant_id":"acme","session_id":%q,"device_serial":"C02OLD000001","hardware_uuid":"HW-OLD",
		"local_user":"jdoe","upn":null,"source":"privileges","reason":"old","started_at":%q,"expires_at":null,
		"ended_at":null,"end_reason":null,"renewals":0,"verified":true,"flags":[],"event_count":1,"last_event_at":%q}`,
		oldSessionID, seen, seen)
	body := fmt.Sprintf(`{"schema_version":1,"event_id":"6d7e8f90-a1b2-4c3d-8e4f-5a6b7c8d9e0f","type":"elevation.granted",
		"session_id":%q,"timestamp":%q,"device":{"serial":"C02OLD000001","hardware_uuid":"HW-OLD","privileges_version":"2.4.0"},
		"user":{"local_name":"jdoe","upn":null},"elevation":{"reason":"old","expires":null,"source":"privileges"},
		"delayed":false,"detail":{}}`, oldSessionID, seen)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO devices (tenant_id, serial, state, last_seen_at) VALUES ('acme', 'C02OLD000001', $1, $2)`, []any{device, seen}},
		{`INSERT INTO sessions (tenant_id, session_id, device_serial, local_user, started_at, state, updated_at)
			VALUES ('acme', $1, 'C02OLD000001', 'jdoe', $2, $3, $2)`, []any{oldSessionID, seen, session}},
		{`INSERT INTO events (tenant_id, event_id, type, session_id, device_serial, occurred_at, received_at, body)
			VALUES ('acme', '6d7e8f90-a1b2-4c3d-8e4f-5a6b7c8d9e0f', 'elevation.granted', $1, 'C02OLD000001', $2, $2, $3)`,
			[]any{oldSessionID, seen, body}},
		{`INSERT INTO export_outbox (tenant_id, sink, event_id, next_attempt_at)
			VALUES ('acme', 'splunk', '6d7e8f90-a1b2-4c3d-8e4f-5a6b7c8d9e0f', $1)`, []any{seen}},
		{`INSERT INTO device_credentials (device_id, tenant_id, serial, hardware_uuid, public_key,
			key_digest, status, created_at, activated_at) VALUES ('7e8f90a1-b2c3-4d4e-8f5a-6b7c8d9e0f1a', 'acme', 'C02OLD000001',
			'HW-OLD', '\x00', '\x01', 'active', $1, $1)`, []any{seen}},
		{`INSERT INTO audit_log (tenant_id, id, at, actor, action, target, detail)
			VALUES ('acme', '8f90a1b2-c3d4-4e5f-8a6b-7c8d9e0f1a2b', $1, 'token:3f2a9c1b', 'change_settings', 'settings', '{}')`,
			[]any{seen}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}
