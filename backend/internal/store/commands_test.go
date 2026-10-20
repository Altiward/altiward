package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/command"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// commandSuite runs the command rules against a Store implementation.
func commandSuite(t *testing.T, newStore func(t *testing.T) Store) {
	ctx := context.Background()
	t0 := testfixture.Time(t, "2026-10-16T12:00:00Z")

	setup := func(t *testing.T) (Store, string, string) {
		return newStore(t), "tenant-" + randomHex(t), "C02" + randomHex(t)
	}
	create := func(t *testing.T, s Store, tenant, serial string, at time.Time) command.Command {
		t.Helper()
		user := "jdoe"
		c := command.Command{
			CommandID: newUUID(t), TenantID: tenant, Serial: serial, Type: command.TypeRevokeAdmin, User: &user,
			IssuedBy: "console", CreatedAt: at, ExpiresAt: at.Add(command.Lifetime),
		}
		if err := s.CreateCommand(ctx, c, auditFor(t, c.TenantID, AuditRevokeDevice)); err != nil {
			t.Fatal(err)
		}
		return c
	}
	pendingIDs := func(t *testing.T, s Store, tenant, serial string, now time.Time) []string {
		t.Helper()
		cs, err := s.PendingCommands(ctx, tenant, serial, now)
		if err != nil {
			t.Fatal(err)
		}
		ids := []string{}
		for _, c := range cs {
			ids = append(ids, c.CommandID)
		}
		return ids
	}
	result := func(at time.Time) command.Result {
		return command.Result{Status: command.StatusCompleted, Revoked: []string{"jdoe"}, Failed: []command.UserError{},
			Skipped: []command.UserSkip{}, CompletedAt: at}
	}

	t.Run("queuing a command wakes whoever is watching that Mac, and only them", func(t *testing.T) {
		s, tenant, serial := setup(t)
		// Get past any wake the store gives everyone while it starts listening.
		warm, stopWarm := s.WatchCommands(tenant, serial+"W")
		defer stopWarm()
		create(t, s, tenant, serial+"W", t0)
		select {
		case <-warm:
		case <-time.After(10 * time.Second):
			t.Fatal("warm-up watcher not woken")
		}

		mine, stopMine := s.WatchCommands(tenant, serial)
		defer stopMine()
		other, stopOther := s.WatchCommands(tenant, serial+"X")
		defer stopOther()
		stopped, stop := s.WatchCommands(tenant, serial)
		stop()

		create(t, s, tenant, serial, t0)
		select {
		case <-mine:
		case <-time.After(5 * time.Second):
			t.Fatal("watcher not woken")
		}
		select {
		case <-other:
			t.Fatal("another Mac's watcher woken")
		case <-stopped:
			t.Fatal("a stopped watch was woken")
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("pending commands are delivered oldest first and stamped once", func(t *testing.T) {
		s, tenant, serial := setup(t)
		a := create(t, s, tenant, serial, t0)
		b := create(t, s, tenant, serial, t0.Add(time.Minute))
		create(t, s, tenant, serial+"X", t0) // another Mac
		if got := pendingIDs(t, s, tenant, serial, t0.Add(2*time.Minute)); fmt.Sprint(got) != fmt.Sprint([]string{a.CommandID, b.CommandID}) {
			t.Fatalf("pending = %v", got)
		}
		pendingIDs(t, s, tenant, serial, t0.Add(time.Hour))
		got, err := s.GetCommand(ctx, tenant, a.CommandID)
		if err != nil || got.DeliveredAt == nil || !got.DeliveredAt.Equal(t0.Add(2*time.Minute)) {
			t.Fatalf("delivered_at = %v, %v", got.DeliveredAt, err)
		}
		if got := pendingIDs(t, s, tenant+"-other", serial, t0); len(got) != 0 {
			t.Fatalf("other tenant sees %v", got)
		}
	})

	t.Run("expired commands are not delivered", func(t *testing.T) {
		s, tenant, serial := setup(t)
		create(t, s, tenant, serial, t0)
		if got := pendingIDs(t, s, tenant, serial, t0.Add(command.Lifetime+time.Second)); len(got) != 0 {
			t.Fatalf("pending after expiry = %v", got)
		}
	})

	t.Run("first result wins and ends delivery", func(t *testing.T) {
		s, tenant, serial := setup(t)
		c := create(t, s, tenant, serial, t0)
		got, err := s.RecordCommandResult(ctx, tenant, serial, c.CommandID, result(t0.Add(time.Minute)), t0.Add(2*time.Minute))
		if err != nil || got.Status(t0) != command.StatusCompleted || !got.ResultAt.Equal(t0.Add(2*time.Minute)) {
			t.Fatalf("recorded = %+v, %v", got, err)
		}
		second := result(t0.Add(time.Hour))
		second.Status = command.StatusFailed
		again, err := s.RecordCommandResult(ctx, tenant, serial, c.CommandID, second, t0.Add(time.Hour))
		if err != nil || again.Result.Status != command.StatusCompleted || !again.Result.CompletedAt.Equal(t0.Add(time.Minute)) {
			t.Fatalf("second result replaced the first: %+v, %v", again.Result, err)
		}
		if got := pendingIDs(t, s, tenant, serial, t0.Add(3*time.Minute)); len(got) != 0 {
			t.Fatalf("still pending: %v", got)
		}
	})

	t.Run("a Mac can only report its own commands", func(t *testing.T) {
		s, tenant, serial := setup(t)
		c := create(t, s, tenant, serial, t0)
		if _, err := s.RecordCommandResult(ctx, tenant, serial+"X", c.CommandID, result(t0), t0); !errors.Is(err, ErrNotFound) {
			t.Fatalf("other Mac err = %v", err)
		}
		if _, err := s.RecordCommandResult(ctx, tenant, serial, "not-a-uuid", result(t0), t0); !errors.Is(err, ErrNotFound) {
			t.Fatalf("bad id err = %v", err)
		}
	})

	t.Run("list filters by serial and computed status, newest first", func(t *testing.T) {
		s, tenant, serial := setup(t)
		old := create(t, s, tenant, serial, t0)
		done := create(t, s, tenant, serial, t0.Add(25*time.Hour))
		waiting := create(t, s, tenant, serial, t0.Add(26*time.Hour))
		other := create(t, s, tenant, serial+"X", t0.Add(27*time.Hour))
		if _, err := s.RecordCommandResult(ctx, tenant, serial, done.CommandID, result(t0.Add(25*time.Hour)), t0.Add(25*time.Hour)); err != nil {
			t.Fatal(err)
		}
		now := t0.Add(28 * time.Hour) // old has expired
		ids := func(f CommandFilter) string {
			cs, err := s.ListCommands(ctx, tenant, f, now)
			if err != nil {
				t.Fatal(err)
			}
			out := []string{}
			for _, c := range cs {
				out = append(out, c.CommandID)
			}
			return fmt.Sprint(out)
		}
		want := func(got string, ids ...string) {
			t.Helper()
			if got != fmt.Sprint(ids) {
				t.Errorf("got %s, want %v", got, ids)
			}
		}
		want(ids(CommandFilter{}), other.CommandID, waiting.CommandID, done.CommandID, old.CommandID)
		want(ids(CommandFilter{Serial: serial}), waiting.CommandID, done.CommandID, old.CommandID)
		want(ids(CommandFilter{Status: command.StatusPending}), other.CommandID, waiting.CommandID)
		want(ids(CommandFilter{Status: command.StatusExpired}), old.CommandID)
		want(ids(CommandFilter{Status: command.StatusCompleted}), done.CommandID)
		if _, err := s.GetCommand(ctx, tenant+"-other", done.CommandID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-tenant get err = %v", err)
		}
	})
}
