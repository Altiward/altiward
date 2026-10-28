package store

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestPostgresRetentionFloor checks the database's own refusal to delete history younger
// than 90 days, which holds whatever the application does: for each table, a fresh row is
// refused and a row older than the floor goes.
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

	const (
		eventID   = "6d7e8f90-a1b2-4c3d-8e4f-5a6b7c8d9e0f"
		sessionID = "5b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
		commandID = "9a0b1c2d-3e4f-4a5b-8c6d-7e8f9a0b1c2d"
	)
	// Each insert takes the row's age as its one argument, a Postgres interval.
	tables := []struct {
		table  string
		insert string
	}{
		{"events", `INSERT INTO events (tenant_id, event_id, type, device_serial, occurred_at, received_at, body)
			VALUES ('acme', '` + eventID + `', 'elevation.granted', 'C02FLOOR001', now() - $1::interval, now() - $1::interval, '{}')`},
		{"sessions", `INSERT INTO sessions (tenant_id, session_id, device_serial, local_user, state, updated_at)
			VALUES ('acme', '` + sessionID + `', 'C02FLOOR001', 'jdoe', '{}', now() - $1::interval)`},
		{"devices", `INSERT INTO devices (tenant_id, serial, state, last_seen_at)
			VALUES ('acme', 'C02FLOOR001', '{}', now() - $1::interval)`},
		{"agent_commands", `INSERT INTO agent_commands (command_id, tenant_id, serial, type, issued_by, created_at, expires_at)
			VALUES ('` + commandID + `', 'acme', 'C02FLOOR001', 'end_session', 'token:test', now() - $1::interval, now())`},
	}
	for _, tc := range tables {
		t.Run(tc.table, func(t *testing.T) {
			del := `DELETE FROM ` + tc.table
			if _, err := s.pool.Exec(ctx, tc.insert, "1 hour"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.pool.Exec(ctx, del); err == nil || !strings.Contains(err.Error(), tc.table+" rows younger than 90 days") {
				t.Fatalf("delete of a fresh row: %v", err)
			}
			// A row just inside the floor is still refused; the refused delete leaves the row.
			if _, err := s.pool.Exec(ctx, `UPDATE `+tc.table+` SET `+floorColumn(tc.table)+` = now() - interval '89 days'`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.pool.Exec(ctx, del); err == nil {
				t.Fatal("delete of a row 89 days old succeeded")
			}
			if _, err := s.pool.Exec(ctx, `UPDATE `+tc.table+` SET `+floorColumn(tc.table)+` = now() - interval '91 days'`); err != nil {
				t.Fatal(err)
			}
			if tag, err := s.pool.Exec(ctx, del); err != nil || tag.RowsAffected() != 1 {
				t.Fatalf("delete of a row 91 days old: %v, %v", tag, err)
			}
		})
	}
}

// floorColumn is the column each table's delete floor reads.
func floorColumn(table string) string {
	return map[string]string{"events": "received_at", "sessions": "updated_at", "devices": "last_seen_at", "agent_commands": "created_at"}[table]
}
