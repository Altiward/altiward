package store

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func ownershipSuite(t *testing.T, newStore func(*testing.T, string) Store) {
	ctx := context.Background()
	now := testfixture.Time(t, "2026-10-16T12:00:00Z")
	setup := func(t *testing.T) (Store, string, string) {
		t.Helper()
		sink := "ownership-" + randomHex(t)
		return newStore(t, sink), "ownership-" + randomHex(t), sink
	}
	for _, firstType := range []event.Type{event.ElevationGranted, event.ElevationRevoked, event.Activity} {
		for _, incomingType := range []event.Type{event.ElevationGranted, event.ElevationRevoked, event.Activity, event.AgentHealth} {
			for _, field := range []string{"serial", "hardware", "account"} {
				name := string(firstType) + "/" + string(incomingType) + "/" + field
				t.Run(name, func(t *testing.T) {
					s, tenant, sink := setup(t)
					first := testfixture.Event(t, "elevation-granted")
					first.Type = firstType
					if _, err := s.Ingest(ctx, tenant, []event.Event{first}, now); err != nil {
						t.Fatal(err)
					}
					before, beforeEvents, _ := s.GetSession(ctx, tenant, *first.SessionID)
					beforeDevices, _ := s.ListDevices(ctx, tenant)
					conflict := testfixture.Event(t, "elevation-revoked")
					conflict.Type = incomingType
					switch field {
					case "serial":
						conflict.Device.Serial = "OTHER-MAC"
					case "hardware":
						conflict.Device.HardwareUUID = "OTHER-HARDWARE"
					case "account":
						conflict.User = &event.User{LocalName: "other"}
					}
					if field != "account" && incomingType == event.AgentHealth {
						conflict.User = nil
					}
					conflict.Detail = map[string]any{"verified": false, "inferred": true}
					// A valid preceding event must roll back too, including its device/export.
					health := testfixture.Event(t, "agent-health")
					health.Device.Serial = "BATCH-ONLY-MAC"
					res, err := s.Ingest(ctx, tenant, []event.Event{health, conflict}, now.Add(time.Minute))
					if !errors.Is(err, ErrSessionOwnerConflict) || len(res.Accepted) != 0 || len(res.Duplicate) != 0 {
						t.Fatalf("conflict result %+v, error %v", res, err)
					}
					after, afterEvents, _ := s.GetSession(ctx, tenant, *first.SessionID)
					afterDevices, _ := s.ListDevices(ctx, tenant)
					if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(beforeEvents, afterEvents) || !reflect.DeepEqual(beforeDevices, afterDevices) {
						t.Fatalf("conflicting batch changed persisted state: %+v", after)
					}
					pending, err := s.ExportStatus(ctx, tenant)
					if err != nil || len(pending) != 1 || pending[0].Sink != sink || pending[0].Pending != 1 {
						t.Fatalf("export state changed: %+v, %v", pending, err)
					}
					// It was not stored during the rejected batch and can now be accepted.
					if res, err := s.Ingest(ctx, tenant, []event.Event{health}, now); err != nil || len(res.Accepted) != 1 {
						t.Fatalf("rolled-back health event was stored: %+v, %v", res, err)
					}
				})
			}
		}
	}
	for _, order := range []string{"revoke first", "accountless activity first"} {
		t.Run(order, func(t *testing.T) {
			s, tenant, _ := setup(t)
			grant := testfixture.Event(t, "elevation-granted")
			first := testfixture.Event(t, "elevation-revoked")
			if order == "accountless activity first" {
				first.Type, first.User, first.Elevation = event.Activity, nil, nil
			}
			if _, err := s.Ingest(ctx, tenant, []event.Event{first, grant}, now); err != nil {
				t.Fatal(err)
			}
			got, _, err := s.GetSession(ctx, tenant, *grant.SessionID)
			if err != nil || got.LocalUser != grant.User.LocalName || got.DeviceSerial != grant.Device.Serial || got.EventCount != 2 {
				t.Fatalf("owner not bound after out-of-order events: %+v, %v", got, err)
			}
			if order == "revoke first" && (got.EndedAt == nil || got.StartedAt == nil) {
				t.Fatalf("out-of-order timing lost: %+v", got)
			}
			// Retries remain idempotent, and accountless same-device activity is allowed.
			if res, err := s.Ingest(ctx, tenant, []event.Event{grant, first}, now); err != nil || len(res.Duplicate) != 2 {
				t.Fatalf("retry %+v, %v", res, err)
			}
		})
	}
	t.Run("conflict within new batch commits nothing", func(t *testing.T) {
		s, tenant, _ := setup(t)
		grant := testfixture.Event(t, "elevation-granted")
		conflict := testfixture.Event(t, "elevation-revoked")
		conflict.Device.Serial = "OTHER-MAC"
		if _, err := s.Ingest(ctx, tenant, []event.Event{grant, conflict}, now); !errors.Is(err, ErrSessionOwnerConflict) {
			t.Fatalf("error %v", err)
		}
		if _, _, err := s.GetSession(ctx, tenant, *grant.SessionID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("session was committed: %v", err)
		}
		devices, _ := s.ListDevices(ctx, tenant)
		pending, _ := s.ExportStatus(ctx, tenant)
		if len(devices) != 0 || len(pending) != 0 {
			t.Fatalf("batch state committed: devices %+v, exports %+v", devices, pending)
		}
	})
	t.Run("concurrent first writers choose one immutable owner", func(t *testing.T) {
		s, tenant, _ := setup(t)
		a := testfixture.Event(t, "elevation-granted")
		b := testfixture.Event(t, "elevation-revoked")
		b.Device.Serial, b.Device.HardwareUUID = "OTHER-MAC", "OTHER-HARDWARE"
		start := make(chan struct{})
		type result struct {
			e   event.Event
			err error
		}
		results := make(chan result, 2)
		for _, e := range []event.Event{a, b} {
			go func(e event.Event) {
				<-start
				_, err := s.Ingest(ctx, tenant, []event.Event{e}, now)
				results <- result{e, err}
			}(e)
		}
		close(start)
		var winner event.Event
		successes, conflicts := 0, 0
		for range 2 {
			r := <-results
			if r.err == nil {
				successes++
				winner = r.e
			} else if errors.Is(r.err, ErrSessionOwnerConflict) {
				conflicts++
			} else {
				t.Fatal(r.err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("successes %d, conflicts %d", successes, conflicts)
		}
		got, timeline, err := s.GetSession(ctx, tenant, *a.SessionID)
		if err != nil || got.DeviceSerial != winner.Device.Serial || got.EventCount != 1 || len(timeline) != 1 {
			t.Fatalf("race corrupted owner/state: %+v, %v", got, err)
		}
	})
	t.Run("opposite session and event orders do not deadlock", func(t *testing.T) {
		s, tenant, _ := setup(t)
		deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		a := testfixture.Event(t, "elevation-granted")
		b := testfixture.Event(t, "admin-out-of-band")
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, batch := range [][]event.Event{{a, b}, {b, a}} {
			go func(batch []event.Event) { <-start; _, err := s.Ingest(deadline, tenant, batch, now); results <- err }(batch)
		}
		close(start)
		for range 2 {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		for _, e := range []event.Event{a, b} {
			got, timeline, err := s.GetSession(ctx, tenant, *e.SessionID)
			if err != nil || got.EventCount != 1 || len(timeline) != 1 {
				t.Fatalf("concurrent resend changed session: %+v, %v", got, err)
			}
		}
	})
}

func TestMemorySessionOwnership(t *testing.T) {
	ownershipSuite(t, func(t *testing.T, sink string) Store { return NewMemory([]string{sink}) })
}

func TestPostgresSessionOwnership(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	ownershipSuite(t, func(t *testing.T, sink string) Store {
		s, err := OpenPostgres(context.Background(), url, []string{sink})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	})
}
