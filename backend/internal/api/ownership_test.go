package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func TestSignedDeviceCannotChangeAnotherSessionsOwner(t *testing.T) {
	ctx := context.Background()
	now := serverNow(t)
	st := store.NewMemory([]string{"splunk"})
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	if err != nil {
		t.Fatal(err)
	}
	h := api.New(st, tokens, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return now })
	victim := enrollAgent(t, h, fixtureSerial)
	other := enrollAgent(t, h, "OTHER-MAC")
	encode := func(events ...event.Event) []byte {
		t.Helper()
		body, err := json.Marshal(map[string]any{"events": events})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	grant := testfixture.Event(t, "elevation-granted")
	if rec, out := victim.post(t, encode(grant)); rec.Code != http.StatusOK || len(out["accepted"].([]any)) != 1 {
		t.Fatalf("grant: %d %s", rec.Code, rec.Body)
	}
	for _, kind := range []string{"other device revoke", "other device activity", "other account", "other hardware"} {
		t.Run(kind, func(t *testing.T) {
			claim := testfixture.Event(t, "elevation-revoked")
			caller := victim
			switch kind {
			case "other device revoke", "other device activity":
				caller = other
				claim.Device.Serial, claim.Device.HardwareUUID = "OTHER-MAC", "OTHER-HARDWARE"
				if kind == "other device activity" {
					claim.Type, claim.User, claim.Elevation = event.Activity, nil, nil
				}
			case "other account":
				claim.User = &event.User{LocalName: "other"}
			case "other hardware":
				claim.Device.HardwareUUID = "OTHER-HARDWARE"
			}
			health := testfixture.Event(t, "agent-health")
			health.Device = claim.Device
			rec, _ := caller.post(t, encode(health, claim))
			if rec.Code != http.StatusConflict {
				t.Fatalf("conflicting signed batch: %d %s", rec.Code, rec.Body)
			}
			got, timeline, err := st.GetSession(ctx, "acme", *grant.SessionID)
			if err != nil || !got.Open() || got.EventCount != 1 || len(timeline) != 1 || got.LocalUser != grant.User.LocalName {
				t.Fatalf("victim session changed: %+v %v", got, err)
			}
			pending, _ := st.ExportStatus(ctx, "acme")
			// The two enrolments and the grant, and nothing from the refused batch.
			if len(pending) != 1 || pending[0].Pending != 3 {
				t.Fatalf("rejected batch exported: %+v", pending)
			}
		})
	}
	// The owner can still deliver its real give-back after the refused batches.
	revoke := testfixture.Event(t, "elevation-revoked")
	if rec, out := victim.post(t, encode(revoke)); rec.Code != http.StatusOK || len(out["accepted"].([]any)) != 1 {
		t.Fatalf("owner revoke: %d %s", rec.Code, rec.Body)
	}
}
