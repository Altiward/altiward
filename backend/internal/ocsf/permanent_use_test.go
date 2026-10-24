package ocsf_test

import (
	"maps"
	"testing"

	"github.com/Altiward/altiward/backend/internal/store"
)

// useVariant is a fixture with its detail changed, so a method no fixture has gets a test
// without a fixture file of its own.
func useVariant(t *testing.T, name string, change map[string]any) store.StoredEvent {
	t.Helper()
	e := stored(t, name)
	e.Detail = maps.Clone(e.Detail)
	for k, v := range change {
		e.Detail[k] = v
	}
	return e
}

func TestPermanentUseMapsToAuthentication(t *testing.T) {
	tests := []struct {
		name  string
		event store.StoredEvent
		want  map[string]any
	}{
		{"console sign-in", stored(t, "admin-permanent-use-started"), map[string]any{
			"activity_id": 1.0, "activity_name": "Logon", "type_uid": 300201.0,
			"logon_type_id": 2.0, "logon_type": "Interactive",
			"start_time": 1792141200000.0,
			"message":    "breakglass signed in at the Mac",
		}},
		{"ssh sign-out", stored(t, "admin-permanent-use-ended"), map[string]any{
			"activity_id": 2.0, "activity_name": "Logoff", "type_uid": 300202.0,
			"logon_type_id": 10.0, "logon_type": "Remote Interactive", "is_remote": true,
			"src_endpoint.ip": "10.0.0.5",
			"start_time":      1792143000000.0, "end_time": 1792143720000.0,
			"message": "breakglass signed out of SSH from 10.0.0.5",
		}},
		{"authorisation prompt", stored(t, "admin-permanent-use-prompt"), map[string]any{
			"activity_id": 1.0, "logon_type_id": 99.0, "logon_type": "Authorisation prompt",
			"actor.user.name": "alex",
			"message":         "breakglass approved com.apple.ServiceManagement.daemons.modify on alex's session",
		}},
		{"authorisation prompt without a right", useVariant(t, "admin-permanent-use-prompt", map[string]any{
			"right": nil, "on_session_of": nil,
		}), map[string]any{
			"logon_type": "Authorisation prompt",
			"message":    "breakglass approved an authorisation prompt",
		}},
		{"terminal", useVariant(t, "admin-permanent-use-started", map[string]any{"method": "terminal", "tty": "ttys001"}), map[string]any{
			"activity_id": 1.0, "logon_type_id": 2.0, "logon_type": "Interactive",
			"message": "breakglass signed in using Terminal",
		}},
		{"screen sharing", useVariant(t, "admin-permanent-use-started", map[string]any{"method": "screen_sharing", "remote_host": "10.0.0.5"}), map[string]any{
			"logon_type_id": 10.0, "logon_type": "Remote Interactive", "is_remote": true,
			"src_endpoint.ip": "10.0.0.5",
			"message":         "breakglass shared the screen from 10.0.0.5",
		}},
		{"screen sharing from a name", useVariant(t, "admin-permanent-use-started", map[string]any{"method": "screen_sharing", "remote_host": "alex-mbp.local"}), map[string]any{
			"is_remote": true, "src_endpoint.hostname": "alex-mbp.local",
			"message": "breakglass shared the screen from alex-mbp.local",
		}},
		{"sudo", useVariant(t, "admin-permanent-use-prompt", map[string]any{
			"method": "sudo", "tty": "ttys003", "run_as": "root", "on_session_of": nil, "right": nil, "client": nil,
		}), map[string]any{
			"activity_id": 1.0, "logon_type_id": 99.0, "logon_type": "sudo",
			"message": "breakglass ran sudo as root on ttys003",
		}},
		{"su", useVariant(t, "admin-permanent-use-prompt", map[string]any{
			"method": "su", "tty": "ttys003", "right": nil, "client": nil,
		}), map[string]any{
			"logon_type_id": 99.0, "logon_type": "su", "actor.user.name": "alex",
			"message": "breakglass switched user with su on alex's session",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mapJSON(t, tt.event)
			want := map[string]any{
				"class_uid": 3002.0, "class_name": "Authentication", "category_uid": 3.0,
				"severity_id": 1.0, "severity": "Informational",
				"status_id": 1.0, "status": "Success",
				"user.name":                      "breakglass",
				"unmapped.altiward.event_type":   "admin.permanent_use",
				"metadata.correlation_uid":       tt.event.Detail["use_id"],
				"metadata.product.version":       "0.3.0",
				"device.hw_info.serial_number":   "C02XK0AAJGH5",
				"unmapped.altiward.detail.state": tt.event.Detail["state"],
			}
			for k, v := range tt.want {
				want[k] = v
			}
			for path, v := range want {
				if got := get(r, path); got != v {
					t.Errorf("%s = %v, want %v", path, got, v)
				}
			}
		})
	}
}

func TestPermanentUseOmitsWhatItDoesNotKnow(t *testing.T) {
	r := mapJSON(t, stored(t, "admin-permanent-use-started"))
	for _, k := range []string{"actor", "src_endpoint", "end_time", "is_remote"} {
		if _, ok := r[k]; ok {
			t.Errorf("%s is set on a local sign-in", k)
		}
	}
	// A remote sign-in whose client macOS did not record has no source.
	r = mapJSON(t, useVariant(t, "admin-permanent-use-ended", map[string]any{"remote_host": nil}))
	if _, ok := r["src_endpoint"]; ok {
		t.Error("src_endpoint is set without a remote_host")
	}
	if got := r["message"]; got != "breakglass signed out of SSH" {
		t.Errorf("message = %v", got)
	}
}
