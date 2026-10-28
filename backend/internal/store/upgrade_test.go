package store

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"slices"
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
			seedOldData(t, old, now, names[:applied])
			old.Close()

			s, err := OpenPostgres(ctx, scoped, nil)
			if err != nil {
				t.Fatalf("upgrade from %s: %v", from, err)
			}
			defer s.Close()

			// Old rows read back through today's code.
			// A database that predates 0008 also has the two Macs seeded for its backfill.
			beforeRetention := !slices.Contains(names[:applied], retentionMigration)
			wantDevices, wantAudit := 1, 2
			if beforeRetention {
				wantDevices, wantAudit = 5, 5
			}
			devices, err := s.ListDevices(ctx, "acme")
			if err != nil || len(devices) != wantDevices {
				t.Fatalf("old devices: %+v, %v", devices, err)
			}
			if old := deviceBySerial(devices, "C02OLD000001"); len(old.AdminMembers) != 1 || old.AdminMembers[0] != "itadmin" || old.Silent() {
				t.Fatalf("old device: %+v", old)
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
			if err != nil || len(audit) != wantAudit || audit[0].Action != AuditChangeSettings {
				t.Fatalf("audit after upgrade: %+v, %v", audit, err)
			}
			if in, err := s.Installation(ctx); err != nil || in.CreatedAt.IsZero() {
				t.Fatalf("installation after upgrade: %+v, %v", in, err)
			}
			// A copy of Intune's Macs written at 0007 reads back, with its defaults, and every
			// upgrade can sync.
			if slices.Contains(names[:applied], mdmMigration) {
				old, err := s.MDMDevicesBySerial(ctx, "acme", MDMIntune, "C02OLD000001")
				if err != nil || len(old) != 1 || old[0].DeviceID != oldMDMDeviceID || old[0].Name != "" || !old[0].LastCheckIn.IsZero() {
					t.Fatalf("old Intune copy: %+v, %v", old, err)
				}
				if st, err := s.MDMSyncStatus(ctx, "acme", MDMIntune); err != nil || st.Devices != 1 || st.LastSuccessAt == nil ||
					st.LastErrorAt != nil || st.SilenceHeldAt != nil {
					t.Fatalf("old Intune sync: %+v, %v", st, err)
				}
			}
			if ok, err := s.ClaimMDMSync(ctx, "acme", MDMIntune, now, 15*time.Minute); err != nil || !ok {
				t.Fatalf("claim the Intune sync after upgrade: %v, %v", ok, err)
			}
			if err := s.ReplaceMDMDevices(ctx, "acme", MDMIntune, []MDMDevice{
				{DeviceID: newUUID(t), Serial: "C02NEW000001", Name: "New", LastCheckIn: now},
			}, now); err != nil {
				t.Fatalf("Intune sync after upgrade: %v", err)
			}
			if beforeRetention {
				// 0008 retires a Mac whose keys an admin revoked, at the time of that revocation,
				// and leaves alone one whose key a contest revoked. The flag isn't on the Mac
				// yet (ListDevices doesn't return it), so read it from the table.
				retired := map[string]*time.Time{}
				rows, err := s.pool.Query(ctx, `SELECT serial, retired_at FROM devices WHERE tenant_id = 'acme'`)
				if err != nil {
					t.Fatal(err)
				}
				for rows.Next() {
					var serial string
					var at *time.Time
					if err := rows.Scan(&serial, &at); err != nil {
						t.Fatal(err)
					}
					retired[serial] = at
				}
				rows.Close()
				if err := rows.Err(); err != nil {
					t.Fatal(err)
				}
				if at := retired[adminRetiredSerial]; at == nil || !at.Equal(now.Add(-48*time.Hour)) {
					t.Fatalf("admin-revoked Mac retired_at = %v, want %v", at, now.Add(-48*time.Hour))
				}
				for _, serial := range []string{"C02OLD000001", rejectedSerial, noopSerial, contestedSerial} {
					if at, seeded := retired[serial]; !seeded || at != nil {
						t.Fatalf("%s retired_at = %v (seeded %v), want it not retired", serial, at, seeded)
					}
				}
			}
			// Deleting history younger than 90 days is refused by the database itself, whatever
			// the application does. The seeded event is dated by the test's clock, so make it
			// fresh by the database's.
			if _, err := s.pool.Exec(ctx, `UPDATE events SET received_at = now()`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.pool.Exec(ctx, `DELETE FROM events WHERE tenant_id = 'acme'`); err == nil ||
				!strings.Contains(err.Error(), "younger than 90 days") {
				t.Fatalf("delete of a fresh event: %v", err)
			}
			st, err := s.Stats(ctx, now)
			if err != nil || len(st.MigrationsPending) != 0 || len(st.MigrationsApplied) != len(names) ||
				st.Devices != int64(wantDevices) || st.AuditEntries != int64(wantAudit) || st.InstalledAt == nil ||
				len(st.MDM) != 1 || st.MDM[0].TenantID != "acme" || st.MDM[0].Devices != 1 {
				t.Fatalf("stats after upgrade: %+v, %v", st, err)
			}
		})
	}
}

const (
	adminRetiredSerial = "C02OLDRET001" // the one key an admin revoked: retired
	rejectedSerial     = "C02OLDREJ001" // a contest, then an admin rejected the pending key: not retired
	noopSerial         = "C02OLDNOP001" // a contest, then an admin revoked the revoked key again: not retired
	contestedSerial    = "C02OLDCON001" // a contest alone: not retired
	oldSessionID       = "5b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	oldMDMDeviceID     = "9a0b1c2d-3e4f-4a5b-8c6d-7e8f9a0b1c2d"
	mdmMigration       = "migrations/0007_mdm.sql"

	retentionMigration = "migrations/0008_retention.sql"
)

func deviceBySerial(devices []Device, serial string) Device {
	for _, d := range devices {
		if d.Serial == serial {
			return d
		}
	}
	return Device{}
}

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
// with its event and that event's export, a credential and an audit entry. A table a later
// migration adds is seeded only when that migration is in applied, the migrations already
// run: from 0007, a copy of one Mac from Intune and its sync. Before 0008, two Macs with
// revoked keys for its retired_at backfill.
func seedOldData(t *testing.T, pool *pgxpool.Pool, now time.Time, applied []string) {
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
	type seed struct {
		sql  string
		args []any
	}
	seeds := []seed{
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
	}
	if slices.Contains(applied, mdmMigration) {
		seeds = append(seeds,
			seed{`INSERT INTO mdm_devices (tenant_id, source, device_id, serial) VALUES ('acme', 'intune', $1, 'C02OLD000001')`,
				[]any{oldMDMDeviceID}},
			seed{`INSERT INTO mdm_sync (tenant_id, source, last_success_at, devices) VALUES ('acme', 'intune', $1, 1)`, []any{seen}},
		)
	}
	// Before 0008, Macs whose keys are all revoked, for its retired_at backfill. Only the
	// first was retired by an admin; the rest must not be taken for it, though an admin's
	// revoke_enrollment entry touches some of them.
	if !slices.Contains(applied, retentionMigration) {
		at := func(hours int) string { return now.Add(time.Duration(hours) * time.Hour).Format(time.RFC3339) }
		type key struct {
			id, serial string
			activated  bool   // once active; a rejected pending key never was
			revokedAt  string // when the key was revoked
			entryAt    string // when an admin's revoke_enrollment entry for it was written; "" for none
		}
		keys := []key{
			{"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", adminRetiredSerial, true, at(-48), at(-48)},
			// An active key revoked by a contest (no entry), then a pending key an admin rejected.
			{"b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e", rejectedSerial, true, at(-72), ""},
			{"d4e5f6a7-b8c9-4d0e-8f1a-2b3c4d5e6f70", rejectedSerial, false, at(-48), at(-48)},
			// A key revoked by a contest, then revoked again by an admin: the later entry
			// changed nothing, and the key keeps its first revoked_at.
			{"e5f6a7b8-c9d0-4e1f-8a2b-3c4d5e6f7081", noopSerial, true, at(-72), at(-24)},
			{"f6a7b8c9-d0e1-4f2a-8b3c-4d5e6f708192", contestedSerial, true, at(-72), ""},
		}
		serials := map[string]bool{}
		for i, k := range keys {
			if !serials[k.serial] {
				serials[k.serial] = true
				seeds = append(seeds, seed{`INSERT INTO devices (tenant_id, serial, state, last_seen_at) VALUES ('acme', $1, $2, $3)`,
					[]any{k.serial, fmt.Sprintf(`{"tenant_id":"acme","serial":%q}`, k.serial), seen}})
			}
			var activatedAt *string
			if k.activated {
				activatedAt = &k.revokedAt // any time will do; the migration only looks at whether it is set
			}
			seeds = append(seeds, seed{`INSERT INTO device_credentials (device_id, tenant_id, serial, hardware_uuid, public_key,
				key_digest, status, created_at, activated_at, revoked_at) VALUES ($1, 'acme', $2, 'HW-RET', '\x00',
				decode(md5($4), 'hex'), 'revoked', $3, $5, $3)`, []any{k.id, k.serial, k.revokedAt, k.id, activatedAt}})
			if k.entryAt != "" {
				seeds = append(seeds, seed{`INSERT INTO audit_log (tenant_id, id, at, actor, action, target, detail)
					VALUES ('acme', $1, $2, 'token:3f2a9c1b', 'revoke_enrollment', $3, '{}')`,
					[]any{fmt.Sprintf("c3d4e5f6-a7b8-4c9d-8e0f-1a2b3c4d5e%02x", i), k.entryAt, k.id}})
			}
		}
	}
	for _, q := range seeds {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}
