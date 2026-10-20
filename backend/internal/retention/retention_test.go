package retention_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/retention"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func TestPurgeKeepsTheRetentionPeriod(t *testing.T) {
	ctx := context.Background()
	now := testfixture.Time(t, "2026-10-17T12:00:00Z")
	s := store.NewMemory(nil)
	for i, at := range []time.Time{now.AddDate(-3, 0, 0), now.AddDate(0, 0, -400), now.AddDate(0, 0, -300)} {
		a := store.AuditEntry{ID: []string{"a", "b", "c"}[i], TenantID: "acme", At: at, Actor: "token:x",
			Action: store.AuditChangeSettings, Target: "settings"}
		if err := s.PutTenantSettings(ctx, "acme", store.TenantSettings{}, a); err != nil {
			t.Fatal(err)
		}
	}
	// Asking for less than the minimum still keeps a year.
	r := &retention.Audit{Store: s, After: 30 * 24 * time.Hour, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return now }}
	if n, err := r.Purge(ctx); err != nil || n != 2 {
		t.Fatalf("purged %d, %v", n, err)
	}
	left, _ := s.ListAudit(ctx, "acme", store.AuditFilter{})
	if len(left) != 1 || left[0].ID != "c" {
		t.Fatalf("left = %+v", left)
	}
}
