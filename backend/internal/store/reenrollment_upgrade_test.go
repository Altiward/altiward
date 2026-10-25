package store

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func TestPostgresReenrollmentUpgradeEnablesApprovalOnce(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	scoped := inSchema(t, url, "approval_upgrade_"+randomHex(t))
	old, err := pgxpool.New(ctx, scoped)
	if err != nil {
		t.Fatal(err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	applyFirst(t, old, names[:2])
	now := testfixture.Time(t, "2026-10-25T12:00:00Z")
	seedOldData(t, old, now)
	for name, flag := range map[string]string{"false": `false`, "missing": ``, "null": `null`, "true": `true`} {
		body := `{"silent_after_hours":24,"silent_alerts_off":true,"preserved":{"value":"keep"}`
		if flag != "" {
			body += `,"reenrollment_requires_approval":` + flag
		}
		body += `}`
		if _, err := old.Exec(ctx, `INSERT INTO tenant_settings (tenant_id, settings, updated_at) VALUES ($1, $2, $3)`, name, body, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := old.Exec(ctx, `INSERT INTO tenant_settings (tenant_id, settings, updated_at) VALUES ('null_body', 'null', $1)`, now); err != nil {
		t.Fatal(err)
	}
	old.Close()

	s, err := OpenPostgres(ctx, scoped, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, tenant := range []string{"false", "missing", "null", "true"} {
		settings, err := s.TenantSettings(ctx, tenant)
		if err != nil || !settings.ReenrollmentRequiresApproval || settings.SilentAfterHours != 24 || !settings.SilentAlertsOff {
			t.Fatalf("upgraded %s settings = %+v, %v", tenant, settings, err)
		}
		var preserved string
		if err := s.pool.QueryRow(ctx, `SELECT settings->'preserved'->>'value' FROM tenant_settings WHERE tenant_id = $1`, tenant).Scan(&preserved); err != nil || preserved != "keep" {
			t.Fatalf("other settings changed for %s: %q, %v", tenant, preserved, err)
		}
	}
	if settings, err := s.TenantSettings(ctx, "null_body"); err != nil || !settings.ReenrollmentRequiresApproval {
		t.Fatalf("null settings body: %+v, %v", settings, err)
	}
	id := "7e8f90a1-b2c3-4d4e-8f5a-6b7c8d9e0f1a"
	if cred, err := s.Credential(ctx, id); err != nil || cred.Status != CredentialActive || cred.RevokedAt != nil || cred.ActivatedAt == nil || len(cred.PublicKey) != 1 || cred.PublicKey[0] != 0 {
		t.Fatalf("migration changed an existing credential: %+v, %v", cred, err)
	}

	// Migration bookkeeping makes this a one-time upgrade, preserving a later opt-out.
	settings, _ := s.TenantSettings(ctx, "false")
	settings.ReenrollmentRequiresApproval = false
	if err := s.PutTenantSettings(ctx, "false", settings, auditFor(t, "false", AuditChangeSettings)); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := s.TenantSettings(ctx, "false"); err != nil || got.ReenrollmentRequiresApproval || got.SilentAfterHours != 24 || !got.SilentAlertsOff {
		t.Fatalf("later opt-out was not preserved: %+v, %v", got, err)
	}
}

func TestPostgresSettingsDecodeApprovalDefaults(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := OpenPostgres(ctx, inSchema(t, url, "approval_decode_"+randomHex(t)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for name, flag := range map[string]any{"missing": nil, "null": nil, "true": true, "false": false} {
		body := map[string]any{"silent_after_hours": 24, "silent_alerts_off": true}
		if name != "missing" {
			body["reenrollment_requires_approval"] = flag
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(ctx, `INSERT INTO tenant_settings (tenant_id, settings, updated_at) VALUES ($1, $2, now())`, name, encoded); err != nil {
			t.Fatal(err)
		}
		got, err := s.TenantSettings(ctx, name)
		if err != nil || got.ReenrollmentRequiresApproval != (name != "false") || got.SilentAfterHours != 24 || !got.SilentAlertsOff {
			t.Fatalf("decoded %s = %+v, %v", name, got, err)
		}
	}
}
