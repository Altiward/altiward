package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// TestPostgresRetentionFloor checks the database's own refusal to delete history younger
// than 90 days, which holds whatever the application does: for each table, a fresh row is
// refused, so is one just inside the floor, and a row older than the floor goes. It also
// checks that the two times the floors trust and the application never changes,
// events.received_at and agent_commands.created_at, can't be moved by an UPDATE, while the
// two that follow a replica's clock can.
func TestPostgresRetentionFloor(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := OpenPostgres(ctx, inSchema(t, url, "floor_"+randomHex(t)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Each insert takes the row's age, a Postgres interval, and a key that tells it from
	// the table's other rows: a UUID, or for devices a serial.
	tables := []struct {
		table  string
		key    string
		insert string
		fixed  bool // the floor's column can't be updated
	}{
		{"events", "event_id", `INSERT INTO events (tenant_id, event_id, type, device_serial, occurred_at, received_at, body)
			VALUES ('acme', $2, 'elevation.granted', 'C02FLOOR001', now() - $1::interval, now() - $1::interval, '{}')`, true},
		{"sessions", "session_id", `INSERT INTO sessions (tenant_id, session_id, device_serial, local_user, state, updated_at)
			VALUES ('acme', $2, 'C02FLOOR001', 'jdoe', '{}', now() - $1::interval)`, false},
		{"devices", "serial", `INSERT INTO devices (tenant_id, serial, state, last_seen_at)
			VALUES ('acme', $2, '{}', now() - $1::interval)`, false},
		{"agent_commands", "command_id", `INSERT INTO agent_commands (command_id, tenant_id, serial, type, issued_by, created_at, expires_at)
			VALUES ($2, 'acme', 'C02FLOOR001', 'end_session', 'token:test', now() - $1::interval, now())`, true},
	}
	for _, tc := range tables {
		t.Run(tc.table, func(t *testing.T) {
			// row inserts a row of the given age and returns its key.
			row := func(age string) string {
				t.Helper()
				k := newUUID(t)
				if tc.key == "serial" {
					k = "C02" + randomHex(t)
				}
				if _, err := s.pool.Exec(ctx, tc.insert, age, k); err != nil {
					t.Fatal(err)
				}
				return k
			}
			del := func(k string) (int64, error) {
				tag, err := s.pool.Exec(ctx, `DELETE FROM `+tc.table+` WHERE `+tc.key+` = $1`, k)
				return tag.RowsAffected(), err
			}
			if _, err := del(row("1 hour")); err == nil || !strings.Contains(err.Error(), tc.table+" rows younger than 90 days") {
				t.Fatalf("delete of a fresh row: %v", err)
			}
			// A row just inside the floor is still refused, and the refused delete leaves it.
			inside := row("89 days")
			if _, err := del(inside); err == nil {
				t.Fatal("delete of a row 89 days old succeeded")
			}
			if n, err := del(row("91 days")); err != nil || n != 1 {
				t.Fatalf("delete of a row 91 days old: %d, %v", n, err)
			}

			// Moving the floor's column back would let a delete through.
			_, err := s.pool.Exec(ctx, `UPDATE `+tc.table+` SET `+floorColumn(tc.table)+` = now() - interval '91 days'
				WHERE `+tc.key+` = $1`, inside)
			switch {
			case tc.fixed && (err == nil || !strings.Contains(err.Error(), tc.table+"."+floorColumn(tc.table)+" cannot be changed")):
				t.Fatalf("moving %s back: %v", floorColumn(tc.table), err)
			case !tc.fixed && err != nil:
				t.Fatalf("moving %s back, as a replica with a slow clock may: %v", floorColumn(tc.table), err)
			}
			if tc.fixed {
				if _, err := del(inside); err == nil {
					t.Fatal("delete after a refused update succeeded")
				}
			}
		})
	}

	// Other columns of the two fixed tables still update, as the server updates commands.
	id := newUUID(t)
	if _, err := s.pool.Exec(ctx, tables[3].insert, "1 hour", id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE agent_commands SET delivered_at = now() WHERE command_id = $1`, id); err != nil {
		t.Fatalf("delivering a command: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE events SET received_at = received_at WHERE tenant_id = 'acme'`); err != nil {
		t.Fatalf("an update that leaves received_at as it was: %v", err)
	}
}

// floorColumn is the column each table's delete floor reads.
func floorColumn(table string) string {
	return map[string]string{"events": "received_at", "sessions": "updated_at", "devices": "last_seen_at", "agent_commands": "created_at"}[table]
}

// TestPostgresDeleteFloor checks the floor on an event the store itself stored: a DELETE of
// one received yesterday fails with the trigger's error, and history expiry, asked to remove
// everything up to now, removes nothing and doesn't meet the trigger.
func TestPostgresDeleteFloor(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := OpenPostgres(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tenant := "tenant-" + randomHex(t)
	health := testfixture.Event(t, "agent-health")
	if _, err := s.Ingest(ctx, tenant, []event.Event{health}, time.Now().AddDate(0, 0, -1)); err != nil {
		t.Fatal(err)
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM events WHERE tenant_id = $1`, tenant)
	if err == nil || !strings.Contains(err.Error(), "events rows younger than 90 days cannot be deleted") {
		t.Fatalf("delete of yesterday's event: %v", err)
	}
	if got, err := s.ExpireHistory(ctx, tenant, HistoryCutoff{Before: time.Now()}, 100); err != nil || got != (ExpiryCounts{}) {
		t.Fatalf("expiry removed %+v, %v", got, err)
	}
	if res, err := s.Ingest(ctx, tenant, []event.Event{health}, time.Now()); err != nil || len(res.Duplicate) != 1 {
		t.Fatalf("the event is gone: %+v, %v", res, err)
	}
}
