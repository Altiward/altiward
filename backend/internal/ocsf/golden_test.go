package ocsf_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/ocsf"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// go test ./backend/internal/ocsf -run Golden -update rewrites integrations/ocsf-examples
// from the example events and extraExamples. Other repos (altiward-forwarder, altiward-siem) read those files
// as the server's OCSF output.
var update = flag.Bool("update", false, "rewrite integrations/ocsf-examples from docs/schema/examples")

const goldenDir = "../../../integrations/ocsf-examples"

// extraExamples are golden files for records no example event gives, so altiward-siem's
// detections have one to check their fields against: a grant the admin group contradicts,
// a new admin account (the persistence example has none), a console revoke of rights
// nobody granted, which closes their finding, and console activity, which comes from the
// audit log.
func extraExamples(t *testing.T) map[string][]ocsf.Record {
	unverified := stored(t, "elevation-granted")
	unverified.Detail = maps.Clone(unverified.Detail)
	unverified.Detail["observed_admin"], unverified.Detail["verified"] = false, false
	at := time.Date(2026, 10, 16, 10, 2, 0, 0, time.UTC)
	entry := func(id, actor, action, target string, detail map[string]any) store.AuditEntry {
		return store.AuditEntry{ID: id, TenantID: "acme", Actor: actor, At: at, Action: action, Target: target, Detail: detail}
	}
	return map[string][]ocsf.Record{
		"elevation-granted-unverified":          ocsf.Map(unverified, "acme"),
		"elevation-revoked-out-of-band-command": ocsf.Map(consoleRevokeOfOutOfBand(t), "acme"),
		"account-created": ocsf.Map(withAccount(t,
			map[string]any{"kind": "local_account", "change": "added", "name": "support", "uid": 502.0, "admin": true}, false), "acme"),
		"console-activity": {
			ocsf.MapAudit(entry("6f1d2c3b-4a59-4e8f-9d0c-1b2a3c4d5e6f", "jane.doe@example.com", store.AuditSignIn, "jane.doe@example.com",
				map[string]any{"role": "admin"})),
			ocsf.MapAudit(entry("7a2e3d4c-5b6a-4f90-8e1d-2c3b4d5e6f70", "jane.doe@example.com", store.AuditRevokeDevice, "C02XK0AAJGH5",
				map[string]any{"serial": "C02XK0AAJGH5", "user": "jdoe", "command_id": "3b4c5d6e-7f80-4a91-b2c3-d4e5f6a7b8c9"})),
			ocsf.MapAudit(entry("8b3f4e5d-6c7b-4a01-9f2e-3d4c5e6f7081", "break-glass:3f2a9c1b", store.AuditApproveEnrollment, "C02XK0AAJGH5",
				map[string]any{"serial": "C02XK0AAJGH5"})),
		},
	}
}

// TestGoldenExamples keeps one file per example event that exports anything: the JSON array
// of records Map gives it (one event can give more than one record). extraExamples add a
// few more.
func TestGoldenExamples(t *testing.T) {
	examples := extraExamples(t)
	for _, name := range testfixture.Names {
		if records := ocsf.Map(stored(t, name), "acme"); len(records) > 0 {
			examples[name] = records
		}
	}
	want := map[string]bool{}
	for name, records := range examples {
		want[name+".json"] = true
		b, err := json.MarshalIndent(records, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, '\n')
		path := filepath.Join(goldenDir, name+".json")
		if *update {
			if err := os.MkdirAll(goldenDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%v: run go test ./backend/internal/ocsf -run Golden -update", err)
			continue
		}
		if !bytes.Equal(got, b) {
			t.Errorf("%s is out of date: run go test ./backend/internal/ocsf -run Golden -update", path)
		}
	}

	files, err := filepath.Glob(filepath.Join(goldenDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if want[filepath.Base(f)] {
			continue
		}
		if *update {
			if err := os.Remove(f); err != nil {
				t.Fatal(err)
			}
			continue
		}
		t.Errorf("%s has no example event: run go test ./backend/internal/ocsf -run Golden -update", f)
	}
	if !want["elevation-granted.json"] || !want["elevation-revoked.json"] {
		t.Fatal("the grant and revoke examples must export: the forwarder's contract test reads them")
	}
}
