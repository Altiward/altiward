package api_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/mdm"
	"github.com/Altiward/altiward/backend/internal/store"
)

// newServerWithIntune is newServer with Intune connected for acme, and its store exposed.
func newServerWithIntune(t *testing.T) (http.Handler, store.Store) {
	t.Helper()
	st := store.NewMemory(nil)
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken+",other="+otherConsole)
	if err != nil {
		t.Fatal(err)
	}
	now := serverNow(t)
	clock := func() time.Time { return now }
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	checker := &mdm.Checker{Store: st, TenantID: "acme", Log: log, Now: clock, LookupTimeout: 10 * time.Second}
	return api.New(st, tokens, log, clock, api.WithMDM(checker)), st
}

func TestMDMStatusWhenOff(t *testing.T) {
	h := newServer(t)
	for path, want := range map[string]string{"/v1/mdm": `{"configured":false}`, "/v1/mdm/devices": `{"devices":[]}`} {
		rec, _ := do(t, h, "GET", path, consoleToken, nil)
		if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != want {
			t.Errorf("%s: %d %s, want %s", path, rec.Code, rec.Body, want)
		}
	}
}

func TestMDMStatusAndDevices(t *testing.T) {
	h, st := newServerWithIntune(t)
	now := serverNow(t)
	ctx := context.Background()
	const (
		deviceID = "0A1B2C3D-0000-4000-8000-00000000000A"
		entraID  = "5E6F7A8B-0000-4000-8000-00000000000E"
	)
	err := st.ReplaceMDMDevices(ctx, "acme", store.MDMIntune, []store.MDMDevice{
		{DeviceID: deviceID, Serial: "C02AAA", EntraDeviceID: entraID, PrimaryUPN: "jdoe@example.com", Name: "JDOE-MBP",
			LastCheckIn: now.Add(-time.Hour)},
		{DeviceID: "0a1b2c3d-0000-4000-8000-00000000000b", Serial: "C02BBB", EntraDeviceID: "entra-b", Name: "Spare"},
	}, now.Add(-10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordMDMSyncError(ctx, "acme", store.MDMIntune, "intune: HTTP 503 ServiceUnavailable", now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}

	rec, status := do(t, h, "GET", "/v1/mdm", consoleToken, nil)
	if rec.Code != 200 || status["configured"] != true || status["source"] != "intune" || status["devices"] != 2.0 ||
		status["last_success_at"] != "2026-10-16T11:50:00Z" || status["last_error_at"] != "2026-10-16T11:55:00Z" ||
		status["last_error"] != "intune: HTTP 503 ServiceUnavailable" || status["silence_held"] != 0.0 {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	if _, ok := status["silence_held_at"]; ok {
		t.Fatalf("status shows a hold that never happened: %s", rec.Body)
	}
	bodies := rec.Body.String()

	rec, out := do(t, h, "GET", "/v1/mdm/devices", consoleToken, nil)
	devices, _ := out["devices"].([]any)
	if rec.Code != 200 || len(devices) != 2 {
		t.Fatalf("devices: %d %s", rec.Code, rec.Body)
	}
	first, second := devices[0].(map[string]any), devices[1].(map[string]any)
	if first["serial"] != "C02AAA" || first["primary_upn"] != "jdoe@example.com" || first["name"] != "JDOE-MBP" ||
		first["last_check_in"] != "2026-10-16T11:00:00Z" || len(first) != 4 {
		t.Fatalf("first device = %v", first)
	}
	if _, ok := second["last_check_in"]; ok || second["serial"] != "C02BBB" || second["primary_upn"] != "" || len(second) != 3 {
		t.Fatalf("a Mac that never checked in = %v", second)
	}
	bodies += rec.Body.String()
	// Viewers never see the IDs that identify a Mac to Intune and Entra ID.
	lower := strings.ToLower(bodies)
	for _, secret := range []string{"device_id", strings.ToLower(deviceID), strings.ToLower(entraID), "entra-b", "0000000b"} {
		if strings.Contains(lower, secret) {
			t.Errorf("the API shows %q:\n%s", secret, bodies)
		}
	}

	// Intune is connected for acme only.
	if rec, out := do(t, h, "GET", "/v1/mdm", otherConsole, nil); rec.Code != 200 || len(out) != 1 || out["configured"] != false {
		t.Fatalf("other tenant's status: %d %s", rec.Code, rec.Body)
	}
	if rec, out := do(t, h, "GET", "/v1/mdm/devices", otherConsole, nil); rec.Code != 200 || len(out["devices"].([]any)) != 0 {
		t.Fatalf("other tenant's devices: %d %s", rec.Code, rec.Body)
	}
}

func TestMDMNeedsAConsoleSignIn(t *testing.T) {
	env := newSSOServer(t, func(st *store.Memory) api.Option {
		return api.WithMDM(&mdm.Checker{Store: st, TenantID: "acme"})
	})
	b := env.browser(t)
	for _, path := range []string{"/v1/mdm", "/v1/mdm/devices"} {
		if rec, _ := b.do("GET", path, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s before signing in: %d", path, rec.Code)
		}
		if rec, _ := do(t, env.h, "GET", path, agentToken, nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s with the enrolment token: %d", path, rec.Code)
		}
	}
	// Viewers see it.
	b.signIn(env.idp, "/", person("g-view"))
	for _, path := range []string{"/v1/mdm", "/v1/mdm/devices"} {
		if rec, _ := b.do("GET", path, nil); rec.Code != http.StatusOK {
			t.Errorf("%s as a viewer: %d %s", path, rec.Code, rec.Body)
		}
	}
}
