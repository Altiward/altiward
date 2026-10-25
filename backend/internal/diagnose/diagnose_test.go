package diagnose_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/diagnose"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

const (
	agentToken   = "agent-secret-0000000001"
	consoleToken = "console-secret-000000001"
	dbPassword   = "db-password-9f8e7d"
	hecToken     = "hec-secret-token"
	dsn          = "postgres://altiward:" + dbPassword + "@db.internal:5432/altiward?sslmode=require"
)

var now = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

type fakeDB struct {
	stats store.Stats
	err   error
}

func (f fakeDB) Stats(context.Context, time.Time) (store.Stats, error) { return f.stats, f.err }

func options(env []string, db diagnose.Stats, connectErr error, dialErr error) diagnose.Options {
	return diagnose.Options{
		Version: "0.3.0", Environ: env, Now: func() time.Time { return now },
		Connect: func(ctx context.Context, url string) (diagnose.Stats, func(), error) {
			if connectErr != nil {
				return nil, nil, connectErr
			}
			return db, func() {}, nil
		},
		Dial: func(ctx context.Context, addr, serverName string, roots *x509.CertPool) error { return dialErr },
	}
}

func baseEnv() []string {
	return []string{
		"ALTIWARD_DATABASE_URL=" + dsn,
		"ALTIWARD_AGENT_TOKENS=acme=" + agentToken,
		"ALTIWARD_CONSOLE_TOKENS=acme=" + consoleToken,
		"ALTIWARD_SPLUNK_HEC_URL=https://splunk.example.com:8088",
		"ALTIWARD_SPLUNK_HEC_TOKEN=" + hecToken,
		"HOME=/root", // not Altiward's: left out
	}
}

func asJSON(t *testing.T, r diagnose.Report) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestReportNeverContainsSecrets(t *testing.T) {
	r := diagnose.Run(context.Background(), options(baseEnv(),
		fakeDB{stats: store.Stats{Exports: []store.ExportBacklog{{Sink: "splunk", Pending: 3}}}}, nil, nil))
	out := asJSON(t, r)
	for _, secret := range []string{agentToken, consoleToken, dbPassword, hecToken, "sslmode"} {
		if strings.Contains(out, secret) {
			t.Errorf("report contains %q", secret)
		}
	}
	s := r.Config.Settings
	if s["ALTIWARD_DATABASE_URL"] != "postgres://altiward@db.internal:5432/altiward" ||
		s["ALTIWARD_SPLUNK_HEC_TOKEN"] != "set (hidden)" || s["ALTIWARD_AGENT_TOKENS"] != "set (hidden)" ||
		s["ALTIWARD_SPLUNK_HEC_URL"] != "https://splunk.example.com:8088" {
		t.Fatalf("settings = %v", s)
	}
	if _, ok := s["HOME"]; ok {
		t.Fatal("a non-Altiward variable is in the report")
	}
	if len(r.Tokens) != 2 || r.Tokens[0].Tenant != "acme" || !strings.HasPrefix(r.Tokens[0].Actor, "token:") {
		t.Fatalf("tokens = %+v", r.Tokens)
	}
}

// The enrolment limits are numbers a support engineer needs to read, so they aren't hidden.
func TestReportShowsEnrolmentLimits(t *testing.T) {
	env := append(baseEnv(), "ALTIWARD_ENROLL_NEW_MACS_PER_HOUR=50", "ALTIWARD_ENROLL_KEYS_PER_MAC_PER_DAY=0")
	r := diagnose.Run(context.Background(), options(env, fakeDB{}, nil, nil))
	s := r.Config.Settings
	if !r.Config.Valid || s["ALTIWARD_ENROLL_NEW_MACS_PER_HOUR"] != "50" || s["ALTIWARD_ENROLL_KEYS_PER_MAC_PER_DAY"] != "0" {
		t.Fatalf("valid = %v, settings = %v", r.Config.Valid, s)
	}
}

func TestHealthyReportHasNoProblems(t *testing.T) {
	r := diagnose.Run(context.Background(), options(baseEnv(), fakeDB{stats: store.Stats{Devices: 12}}, nil, nil))
	if !r.Config.Valid || !r.Database.Reachable || r.Database.Stats.Devices != 12 || len(r.Problems) != 0 {
		t.Fatalf("report = %+v", r)
	}
	if len(r.Sinks) != 1 || !r.Sinks[0].Reachable || r.Sinks[0].Endpoint != "https://splunk.example.com:8088" {
		t.Fatalf("sinks = %+v", r.Sinks)
	}
	if r.Version != "0.3.0" || !r.GeneratedAt.Equal(now) {
		t.Fatalf("header = %+v", r)
	}
}

func TestReportExplainsProblems(t *testing.T) {
	stats := store.Stats{
		MigrationsUnknown: []string{"0099_future"}, DevicesSilent: 2,
		Exports: []store.ExportBacklog{{Sink: "splunk", Pending: 40, Failing: 40, LastError: "splunk: HTTP 403: invalid token"}},
	}
	r := diagnose.Run(context.Background(), options(baseEnv(), fakeDB{stats: stats}, nil, errors.New("connection refused")))
	got := strings.Join(r.Problems, "\n")
	for _, want := range []string{"newer Altiward", "Exports to splunk are failing: splunk: HTTP 403", "stopped checking in",
		"Can't connect to splunk"} {
		if !strings.Contains(got, want) {
			t.Errorf("problems lack %q:\n%s", want, got)
		}
	}
}

func TestQueueForARemovedSink(t *testing.T) {
	stats := store.Stats{Exports: []store.ExportBacklog{{Sink: "sentinel", Pending: 7, Failing: 7, LastError: "x"}}}
	r := diagnose.Run(context.Background(), options(baseEnv(), fakeDB{stats: stats}, nil, nil))
	if len(r.Problems) != 1 || r.Problems[0] != "7 items are still queued for sentinel, which is no longer configured. "+
		"If it was removed on purpose, run: altiward-api drop-exports sentinel" {
		t.Fatalf("problems = %q", r.Problems)
	}
}

func TestUnreachableDatabaseIsScrubbed(t *testing.T) {
	err := errors.New("ping: failed to connect to `" + dsn + "`: password authentication failed for " + dbPassword)
	r := diagnose.Run(context.Background(), options(baseEnv(), nil, err, nil))
	if r.Database.Reachable || strings.Contains(asJSON(t, r), dbPassword) {
		t.Fatalf("database = %+v", r.Database)
	}
	if !strings.Contains(r.Database.Error, "db.internal") {
		t.Fatalf("the error should still name the host: %q", r.Database.Error)
	}
}

func TestInvalidConfigAndNoDatabase(t *testing.T) {
	r := diagnose.Run(context.Background(), options([]string{"ALTIWARD_AGENT_TOKENS=acme=short"}, nil, nil, nil))
	if r.Config.Valid || r.Database.Configured || len(r.Problems) != 2 {
		t.Fatalf("report = %+v", r)
	}
	if !strings.Contains(r.Problems[0], "won't start") || !strings.Contains(r.Problems[1], "in memory") {
		t.Fatalf("problems = %q", r.Problems)
	}
}

func TestSentinelAuthMode(t *testing.T) {
	sentinel := []string{"ALTIWARD_SENTINEL_ENDPOINT=https://dce.ingest.monitor.azure.com", "ALTIWARD_SENTINEL_DCR_ID=dcr-1"}
	run := func(extra ...string) (diagnose.Report, []string) {
		var dialled []string
		o := options(append(append(baseEnv(), sentinel...), extra...), fakeDB{}, nil, nil)
		o.Dial = func(ctx context.Context, addr, serverName string, roots *x509.CertPool) error {
			dialled = append(dialled, addr+" tls="+serverName)
			return nil
		}
		return diagnose.Run(context.Background(), o), dialled
	}

	r, dialled := run("ALTIWARD_SENTINEL_TENANT_ID=t", "ALTIWARD_SENTINEL_CLIENT_ID=c", "ALTIWARD_SENTINEL_CLIENT_SECRET=s")
	if len(r.Sinks) != 2 || r.Sinks[1].Sink != "sentinel" || r.Sinks[1].Auth != "secret" || len(dialled) != 2 {
		t.Fatalf("secret: sinks = %+v, dialled %q", r.Sinks, dialled)
	}

	r, dialled = run("ALTIWARD_SENTINEL_AUTH=managed-identity")
	if !r.Config.Valid || r.Config.Settings["ALTIWARD_SENTINEL_AUTH"] != "managed-identity" {
		t.Fatalf("config = %+v", r.Config)
	}
	if len(r.Sinks) != 3 || r.Sinks[1].Auth != "managed-identity" || r.Sinks[2].Sink != "sentinel-identity" ||
		r.Sinks[2].Endpoint != "http://169.254.169.254" || !r.Sinks[2].Reachable {
		t.Fatalf("managed identity: sinks = %+v", r.Sinks)
	}
	if len(dialled) != 3 || dialled[2] != "169.254.169.254:80 tls=" { // IMDS is plain HTTP on a link-local address
		t.Fatalf("dialled %q", dialled)
	}

	// On Azure Container Apps the token comes from the platform's identity endpoint, and the
	// header that guards it is never reported.
	r, dialled = run("ALTIWARD_SENTINEL_AUTH=managed-identity", "IDENTITY_ENDPOINT=http://localhost:42356/msi/token",
		"IDENTITY_HEADER=header-1")
	if len(r.Sinks) != 3 || r.Sinks[2].Sink != "sentinel-identity" || r.Sinks[2].Endpoint != "http://localhost:42356" ||
		!r.Sinks[2].Reachable {
		t.Fatalf("container app: sinks = %+v", r.Sinks)
	}
	if len(dialled) != 3 || dialled[2] != "localhost:42356 tls=" {
		t.Fatalf("dialled %q", dialled)
	}
	if out, _ := json.Marshal(r); strings.Contains(string(out), "header-1") || strings.Contains(string(out), "IDENTITY_") {
		t.Fatalf("report shows the platform's identity settings: %s", out)
	}
	if !strings.Contains(r.Logs, "docker compose logs") {
		t.Fatalf("logs = %q", r.Logs)
	}
	if r, _ = run("CONTAINER_APP_NAME=altiward"); !strings.HasSuffix(r.Logs, ": az containerapp logs show --name altiward "+
		"--resource-group <its resource group> --container altiward --tail 300") { // az allows 300 lines at most
		t.Fatalf("container app logs = %q", r.Logs)
	}

	r, _ = run("ALTIWARD_SENTINEL_AUTH=certificate", "ALTIWARD_SENTINEL_TENANT_ID=t", "ALTIWARD_SENTINEL_CLIENT_ID=c",
		"ALTIWARD_SENTINEL_CERTIFICATE_FILE=/etc/altiward/certs/sentinel.pem")
	if !r.Config.Valid || r.Config.Settings["ALTIWARD_SENTINEL_CERTIFICATE_FILE"] != "/etc/altiward/certs/sentinel.pem" {
		t.Fatalf("config = %+v", r.Config)
	}
	if len(r.Sinks) != 2 || r.Sinks[1].Auth != "certificate" {
		t.Fatalf("certificate: sinks = %+v", r.Sinks)
	}
}

// A regression guard: the setup date reaches the report through the existing stats field.
func TestReportShowsSetUpDate(t *testing.T) {
	installed := now.AddDate(0, 0, -40)
	r := diagnose.Run(context.Background(), options(baseEnv(), fakeDB{stats: store.Stats{InstalledAt: &installed}}, nil, nil))
	var got struct {
		Database struct {
			Stats struct {
				InstalledAt time.Time `json:"installed_at"`
			} `json:"stats"`
		} `json:"database"`
	}
	if err := json.Unmarshal([]byte(asJSON(t, r)), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Database.Stats.InstalledAt.Equal(installed) {
		t.Fatalf("database.stats.installed_at = %v, want %v", got.Database.Stats.InstalledAt, installed)
	}
	if !strings.Contains(asJSON(t, r), `"installed_at":"2026-09-07T12:00:00Z"`) {
		t.Fatalf("report lacks the setup date: %s", asJSON(t, r))
	}
}

// TestTrustedCAsInChecks: the connection checks trust what the server trusts, so a SIEM with
// an internal CA's certificate shows as reachable once ALTIWARD_TRUSTED_CAS_FILE names it.
func TestTrustedCAsInChecks(t *testing.T) {
	caFile, cert := testfixture.PrivateCA(t, "Private CA")
	addr := testfixture.TLSListener(t, cert)
	run := func(extra ...string) diagnose.Report {
		env := append(baseEnv(), "ALTIWARD_SPLUNK_HEC_URL=https://"+addr, "ALTIWARD_SYSLOG_ADDR="+addr)
		o := options(append(env, extra...), fakeDB{}, nil, nil)
		o.Dial = diagnose.Live("0.3.0").Dial
		return diagnose.Run(context.Background(), o)
	}
	reachable := func(r diagnose.Report) map[string]bool {
		out := map[string]bool{}
		for _, s := range r.Sinks {
			out[s.Sink] = s.Reachable
		}
		return out
	}

	if got := reachable(run()); got["splunk"] || got["syslog"] {
		t.Fatalf("a private CA was trusted without the setting: %v", got)
	}
	r := run("ALTIWARD_TRUSTED_CAS_FILE=" + caFile)
	if got := reachable(r); !got["splunk"] || !got["syslog"] {
		t.Fatalf("with ALTIWARD_TRUSTED_CAS_FILE: %v, problems %q", got, r.Problems)
	}
	if r.Config.Settings["ALTIWARD_TRUSTED_CAS_FILE"] != caFile {
		t.Errorf("settings show %q", r.Config.Settings["ALTIWARD_TRUSTED_CAS_FILE"])
	}
	other, _ := testfixture.PrivateCA(t, "Another CA")
	if got := reachable(run("ALTIWARD_TRUSTED_CAS_FILE="+caFile, "ALTIWARD_SYSLOG_CA_FILE="+other)); !got["splunk"] || got["syslog"] {
		t.Fatalf("ALTIWARD_SYSLOG_CA_FILE didn't replace the roots for syslog: %v", got)
	}
	r = run("ALTIWARD_TRUSTED_CAS_FILE=" + t.TempDir() + "/missing.pem")
	if got := reachable(r); got["splunk"] || !strings.Contains(strings.Join(r.Problems, "\n"), "ALTIWARD_TRUSTED_CAS_FILE") {
		t.Fatalf("a missing file: %v, problems %q", got, r.Problems)
	}
}
