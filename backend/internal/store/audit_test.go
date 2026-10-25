package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/command"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// auditFor is an entry for a console action in tenant, for tests that make changes.
func auditFor(t *testing.T, tenant, action string) AuditEntry {
	t.Helper()
	return AuditEntry{ID: newUUID(t), TenantID: tenant, At: time.Now().UTC(), Actor: "token:test", Action: action, Target: "x"}
}

// auditSuite checks that changes and their audit entries are written together.
func auditSuite(t *testing.T, newStore func(t *testing.T) Store) {
	ctx := context.Background()
	t0 := testfixture.Time(t, "2026-10-16T12:00:00Z")
	entry := func(t *testing.T, tenant, action string, at time.Time) AuditEntry {
		a := auditFor(t, tenant, action)
		a.At, a.Detail = at, map[string]any{"serial": "C02TEST"}
		return a
	}

	t.Run("each change records its entry, newest first, per tenant", func(t *testing.T) {
		s, tenant := newStore(t), "tenant-"+randomHex(t)
		settings := entry(t, tenant, AuditChangeSettings, t0)
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{SilentAfterHours: 24}, settings); err != nil {
			t.Fatal(err)
		}
		cmd := command.Command{CommandID: newUUID(t), TenantID: tenant, Serial: "C02TEST", Type: command.TypeRevokeAdmin,
			IssuedBy: "token:test", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}
		revoke := entry(t, tenant, AuditRevokeDevice, t0.Add(time.Minute))
		if err := s.CreateCommand(ctx, cmd, revoke); err != nil {
			t.Fatal(err)
		}
		other := "tenant-" + randomHex(t)
		if err := s.PutTenantSettings(ctx, other, TenantSettings{}, entry(t, other, AuditChangeSettings, t0)); err != nil {
			t.Fatal(err)
		}

		got, err := s.ListAudit(ctx, tenant, AuditFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].ID != revoke.ID || got[1].ID != settings.ID {
			t.Fatalf("entries = %+v", got)
		}
		if got[0].Actor != "token:test" || got[0].Action != AuditRevokeDevice || got[0].Detail["serial"] != "C02TEST" ||
			!got[0].At.Equal(revoke.At) || got[0].TenantID != tenant {
			t.Fatalf("entry = %+v", got[0])
		}
		page, _ := s.ListAudit(ctx, tenant, AuditFilter{Limit: 1})
		if len(page) != 1 || page[0].ID != revoke.ID {
			t.Fatalf("limit = %+v", page)
		}
		before := revoke.At
		older, _ := s.ListAudit(ctx, tenant, AuditFilter{Before: &before})
		if len(older) != 1 || older[0].ID != settings.ID {
			t.Fatalf("before = %+v", older)
		}
	})

	t.Run("entries in the same instant list in the order recorded and page without gaps", func(t *testing.T) {
		s, tenant := newStore(t), "tenant-"+randomHex(t)
		var ids []string
		for range 5 {
			a := entry(t, tenant, AuditChangeSettings, t0)
			if err := s.PutTenantSettings(ctx, tenant, TenantSettings{SilentAfterHours: 24}, a); err != nil {
				t.Fatal(err)
			}
			ids = append([]string{a.ID}, ids...) // newest first
		}
		var got []string
		var f AuditFilter
		f.Limit = 2
		for {
			page, err := s.ListAudit(ctx, tenant, f)
			if err != nil {
				t.Fatal(err)
			}
			if len(page) == 0 {
				break
			}
			for _, a := range page {
				got = append(got, a.ID)
			}
			last := page[len(page)-1]
			f.Before, f.BeforeSeq = &last.At, &last.Seq
		}
		if strings.Join(got, ",") != strings.Join(ids, ",") {
			t.Fatalf("paged = %v, want %v", got, ids)
		}
	})

	t.Run("a change that fails records nothing", func(t *testing.T) {
		s, tenant := newStore(t), "tenant-"+randomHex(t)
		res, err := s.Enroll(ctx, DeviceCredential{DeviceID: newUUID(t), TenantID: tenant, Serial: "C02" + randomHex(t),
			HardwareUUID: "HW", PublicKey: newKey(t), CreatedAt: t0}, EnrollLimits{})
		if err != nil {
			t.Fatal(err)
		}
		// An active credential can't be approved.
		_, err = s.ApproveCredential(ctx, tenant, res.Credential.DeviceID, t0, entry(t, tenant, AuditApproveEnrollment, t0))
		if !errors.Is(err, ErrInvalidState) {
			t.Fatalf("err = %v", err)
		}
		if got, _ := s.ListAudit(ctx, tenant, AuditFilter{}); len(got) != 0 {
			t.Fatalf("entry for a change that failed: %+v", got)
		}
	})

	t.Run("entries are append-only", func(t *testing.T) {
		s, tenant := newStore(t), "tenant-"+randomHex(t)
		pg, ok := s.(*Postgres)
		if !ok {
			t.Skip("the memory store has no way to change entries")
		}
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{}, entry(t, tenant, AuditChangeSettings, t0)); err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{
			`UPDATE audit_log SET actor = 'someone else' WHERE tenant_id = $1`,
			`DELETE FROM audit_log WHERE tenant_id = $1`,
		} {
			if _, err := pg.pool.Exec(ctx, sql, tenant); err == nil || !strings.Contains(err.Error(), "append-only") {
				t.Fatalf("%s: err = %v", sql, err)
			}
		}
		// Past a year, an entry can be deleted (retention) but still not changed.
		old := entry(t, tenant, AuditChangeSettings, time.Now().AddDate(-2, 0, 0))
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{}, old); err != nil {
			t.Fatal(err)
		}
		if _, err := pg.pool.Exec(ctx, `UPDATE audit_log SET actor = 'x' WHERE id = $1`, old.ID); err == nil {
			t.Fatal("updated an old entry")
		}
		if tag, err := pg.pool.Exec(ctx, `DELETE FROM audit_log WHERE id = $1`, old.ID); err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("delete old entry: %v, %v", tag, err)
		}
	})

	t.Run("console sessions", func(t *testing.T) {
		s, tenant := newStore(t), "tenant-"+randomHex(t)
		hash := []byte(randomHex(t) + randomHex(t))
		sess := ConsoleSession{TokenHash: hash, TenantID: tenant, Subject: "sub-1", Actor: "jane@example.com", Name: "Jane",
			Role: "operator", CSRFToken: "csrf", CreatedAt: t0, EndsAt: t0.Add(12 * time.Hour), ExpiresAt: t0.Add(time.Hour)}
		signIn := entry(t, tenant, AuditSignIn, t0)
		if err := s.CreateConsoleSession(ctx, sess, signIn); err != nil {
			t.Fatal(err)
		}
		got, err := s.ConsoleSession(ctx, hash, t0.Add(time.Minute))
		if err != nil || got.Actor != "jane@example.com" || got.Role != "operator" || got.CSRFToken != "csrf" ||
			got.TenantID != tenant || !got.ExpiresAt.Equal(sess.ExpiresAt) || !got.EndsAt.Equal(sess.EndsAt) {
			t.Fatalf("session = %+v, %v", got, err)
		}
		if _, err := s.ConsoleSession(ctx, hash, t0.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired: %v", err)
		}
		if _, err := s.ConsoleSession(ctx, []byte("unknown"), t0); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown: %v", err)
		}
		// Extending never goes past the end.
		if err := s.ExtendConsoleSession(ctx, hash, t0.Add(48*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.ConsoleSession(ctx, hash, t0.Add(2*time.Hour)); !got.ExpiresAt.Equal(sess.EndsAt) {
			t.Fatalf("extended to %v", got.ExpiresAt)
		}
		signOut := entry(t, tenant, AuditSignOut, t0.Add(time.Minute))
		if err := s.EndConsoleSession(ctx, tenant, hash, signOut); err != nil {
			t.Fatal(err)
		}
		if err := s.EndConsoleSession(ctx, tenant, hash, entry(t, tenant, AuditSignOut, t0)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("second sign-out: %v", err)
		}
		if _, err := s.ConsoleSession(ctx, hash, t0.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("after sign-out: %v", err)
		}
		entries, _ := s.ListAudit(ctx, tenant, AuditFilter{})
		if len(entries) != 2 || entries[0].ID != signOut.ID || entries[1].ID != signIn.ID {
			t.Fatalf("audit = %+v", entries)
		}
	})

	t.Run("console sessions are listed and ended by an admin, within the tenant", func(t *testing.T) {
		s, tenant, other := newStore(t), "tenant-"+randomHex(t), "tenant-"+randomHex(t)
		session := func(tenant, actor string, created time.Time, expires time.Duration) ConsoleSession {
			return ConsoleSession{TokenHash: []byte(randomHex(t) + randomHex(t)), TenantID: tenant, Subject: actor,
				Actor: actor, Name: actor, Role: "viewer", CSRFToken: "csrf", CreatedAt: created,
				EndsAt: created.Add(12 * time.Hour), ExpiresAt: created.Add(expires)}
		}
		older := session(tenant, "ann@example.com", t0, 2*time.Hour)
		newer := session(tenant, "bob@example.com", t0.Add(time.Minute), 2*time.Hour)
		lapsed := session(tenant, "cat@example.com", t0, 30*time.Minute)
		elsewhere := session(other, "dan@example.com", t0, 2*time.Hour)
		for _, c := range []ConsoleSession{older, newer, lapsed, elsewhere} {
			if err := s.CreateConsoleSession(ctx, c, entry(t, c.TenantID, AuditSignIn, c.CreatedAt)); err != nil {
				t.Fatal(err)
			}
		}
		// Newest first, live ones only, this tenant only.
		listed, err := s.ListConsoleSessions(ctx, tenant, t0.Add(time.Hour))
		if err != nil || len(listed) != 2 || listed[0].Actor != "bob@example.com" || listed[1].Actor != "ann@example.com" {
			t.Fatalf("listed = %+v, %v", listed, err)
		}
		// Another tenant's admin can't end it, and nothing is recorded.
		if err := s.EndConsoleSession(ctx, other, older.TokenHash, entry(t, other, AuditEndConsoleSession, t0)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("ended from another tenant: %v", err)
		}
		ended := entry(t, tenant, AuditEndConsoleSession, t0.Add(time.Hour))
		if err := s.EndConsoleSession(ctx, tenant, older.TokenHash, ended); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ConsoleSession(ctx, older.TokenHash, t0.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("ended session still signs in: %v", err)
		}
		if mine, _ := s.ListAudit(ctx, other, AuditFilter{}); len(mine) != 1 {
			t.Fatalf("other tenant's audit = %+v", mine)
		}
	})

	t.Run("purge removes entries before the cutoff, never younger than a year", func(t *testing.T) {
		s, tenant := newStore(t), "tenant-"+randomHex(t)
		now := time.Now().UTC()
		ancient := entry(t, tenant, AuditChangeSettings, now.AddDate(-3, 0, 0))
		old := entry(t, tenant, AuditChangeSettings, now.AddDate(-2, 0, 0))
		recent := entry(t, tenant, AuditChangeSettings, now.Add(-24*time.Hour))
		for _, a := range []AuditEntry{ancient, old, recent} {
			if err := s.PutTenantSettings(ctx, tenant, TenantSettings{}, a); err != nil {
				t.Fatal(err)
			}
		}
		if n, err := s.PurgeAudit(ctx, now.AddDate(-2, 0, 1)); err != nil || n < 2 {
			t.Fatalf("purge = %d, %v", n, err)
		}
		left, _ := s.ListAudit(ctx, tenant, AuditFilter{})
		if len(left) != 1 || left[0].ID != recent.ID {
			t.Fatalf("left = %+v", left)
		}
		// Postgres keeps a year whatever the cutoff; the memory store trusts its caller.
		if _, ok := s.(*Postgres); ok {
			if n, err := s.PurgeAudit(ctx, now.Add(time.Hour)); err != nil {
				t.Fatalf("purge = %d, %v", n, err)
			}
			if left, _ := s.ListAudit(ctx, tenant, AuditFilter{}); len(left) != 1 {
				t.Fatalf("purged a young entry: %+v", left)
			}
		}
	})
}
