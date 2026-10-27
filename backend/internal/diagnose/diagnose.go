// Package diagnose builds the support report `altiward-api diagnose` prints: the version,
// the configuration with every secret removed, the database's migrations and counts, the
// Intune sync's status, and whether each SIEM endpoint answers. It reads; it never migrates
// the database or sends anything to a SIEM, and it reports problems rather than failing on
// them.
package diagnose

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/config"
	"github.com/Altiward/altiward/backend/internal/store"
)

// Report is the whole diagnosis, written as JSON for the admin to read before sending.
type Report struct {
	GeneratedAt time.Time   `json:"generated_at"`
	Version     string      `json:"version"`
	GoVersion   string      `json:"go_version"`
	Platform    string      `json:"platform"`
	Config      Config      `json:"config"`
	Tokens      []Token     `json:"tokens"`
	Database    Database    `json:"database"`
	Sinks       []SinkCheck `json:"sinks"`
	Problems    []string    `json:"problems"` // the findings worth a look, in plain words
	Logs        string      `json:"logs"`
}

type Config struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
	// Settings holds every ALTIWARD_* variable that is set. Secrets show only that they
	// are set; the database URL keeps its host and database but not its password.
	Settings map[string]string `json:"settings"`
}

// Token describes one configured token by its fingerprint, never its value.
type Token struct {
	Tenant string `json:"tenant"`
	Role   string `json:"role"`
	Actor  string `json:"actor"` // as it appears in the audit log
}

type Database struct {
	Configured bool         `json:"configured"`
	Reachable  bool         `json:"reachable"`
	Error      string       `json:"error,omitempty"`
	Stats      *store.Stats `json:"stats,omitempty"`
}

// SinkCheck is a connection test: TCP, then TLS where the sink uses it. Nothing is sent.
// The identity provider for console sign-in, if set up, is checked as the sink "sso", and
// where Sentinel's managed identity gets its tokens (the Azure Instance Metadata Service,
// or a container app's identity endpoint) as "sentinel-identity". The Intune connection is
// checked as "intune", with "intune-identity" for its managed identity.
type SinkCheck struct {
	Sink      string `json:"sink"`
	Endpoint  string `json:"endpoint"`
	Auth      string `json:"auth,omitempty"` // Sentinel's or Intune's: secret, certificate or managed-identity
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

// notSecret are the settings shown as they are. Everything else is shown only as set.
var notSecret = map[string]bool{
	"ALTIWARD_LISTEN_ADDR": true, "ALTIWARD_EXPORT_INTERVAL": true, "ALTIWARD_CONSOLE_DIR": true, "ALTIWARD_UPDATE_CHECK": true,
	"ALTIWARD_SPLUNK_HEC_URL": true, "ALTIWARD_SPLUNK_INDEX": true,
	"ALTIWARD_SENTINEL_ENDPOINT": true, "ALTIWARD_SENTINEL_DCR_ID": true, "ALTIWARD_SENTINEL_STREAM": true,
	"ALTIWARD_SENTINEL_AUTH": true, "ALTIWARD_SENTINEL_TENANT_ID": true, "ALTIWARD_SENTINEL_CLIENT_ID": true,
	"ALTIWARD_SENTINEL_CERTIFICATE_FILE": true,
	"ALTIWARD_INTUNE_AUTH":               true, "ALTIWARD_INTUNE_TENANT_ID": true, "ALTIWARD_INTUNE_CLIENT_ID": true,
	"ALTIWARD_INTUNE_CERTIFICATE_FILE": true,
	"ALTIWARD_SYSLOG_ADDR":             true, "ALTIWARD_SYSLOG_TLS": true, "ALTIWARD_SYSLOG_CA_FILE": true, "ALTIWARD_TRUSTED_CAS_FILE": true,
	"ALTIWARD_SYSLOG_FORMAT": true, "ALTIWARD_SYSLOG_FRAMING": true, "ALTIWARD_AUDIT_RETENTION_DAYS": true,
	"ALTIWARD_ENROLL_NEW_MACS_PER_HOUR": true, "ALTIWARD_ENROLL_KEYS_PER_MAC_PER_DAY": true,
	"ALTIWARD_OIDC_ISSUER": true, "ALTIWARD_OIDC_CLIENT_ID": true, "ALTIWARD_CONSOLE_URL": true,
	"ALTIWARD_OIDC_TENANT": true, "ALTIWARD_OIDC_GROUPS_CLAIM": true, "ALTIWARD_OIDC_SCOPES": true,
	"ALTIWARD_OIDC_ADMIN_GROUPS": true, "ALTIWARD_OIDC_OPERATOR_GROUPS": true, "ALTIWARD_OIDC_VIEWER_GROUPS": true,
	"ALTIWARD_OIDC_PROVIDER_SIGN_OUT": true,
}

// Options are the parts of the outside world a diagnosis touches, so tests can stand in.
type Options struct {
	Version string
	Environ []string // KEY=value pairs, as os.Environ returns
	Now     func() time.Time
	// Connect opens the database without migrating it.
	Connect func(ctx context.Context, url string) (Stats, func(), error)
	// Dial tests an endpoint. tlsServerName is empty for plain TCP; roots nil means the
	// system's.
	Dial func(ctx context.Context, addr, tlsServerName string, roots *x509.CertPool) error
}

// Stats reads the database counts; store.Postgres satisfies it.
type Stats interface {
	Stats(ctx context.Context, now time.Time) (store.Stats, error)
}

// Live is the real environment.
func Live(version string) Options {
	return Options{
		Version: version,
		Environ: os.Environ(),
		Now:     time.Now,
		Connect: func(ctx context.Context, url string) (Stats, func(), error) {
			p, err := store.ConnectPostgres(ctx, url, nil)
			if err != nil {
				return nil, nil, err
			}
			return p, p.Close, nil
		},
		Dial: dial,
	}
}

// Run builds the report.
func Run(ctx context.Context, o Options) Report {
	env := map[string]string{}
	platform := map[string]string{} // set by Azure Container Apps: read, never reported
	for _, kv := range o.Environ {
		if k, v, ok := strings.Cut(kv, "="); ok && v != "" {
			switch {
			case strings.HasPrefix(k, "ALTIWARD_"):
				env[k] = v
			case k == "IDENTITY_ENDPOINT" || k == "IDENTITY_HEADER" || k == "CONTAINER_APP_NAME":
				platform[k] = v
			}
		}
	}
	logs := "docker compose logs --since 24h altiward"
	if app := platform["CONTAINER_APP_NAME"]; app != "" {
		logs = "az containerapp logs show --name " + app + " --resource-group <its resource group> " +
			"--container altiward --tail 300"
	}
	now := o.Now()
	r := Report{
		GeneratedAt: now.UTC(), Version: o.Version, GoVersion: runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Config:   Config{Settings: redact(env)}, Tokens: []Token{}, Sinks: []SinkCheck{}, Problems: []string{},
		Logs: "The server's logs aren't in this report. Attach them separately if asked: " + logs,
	}
	problem := func(s string) { r.Problems = append(r.Problems, s) }

	cfg, err := config.Load(func(k string) string {
		if v, ok := env[k]; ok {
			return v
		}
		return platform[k]
	})
	r.Config.Valid = err == nil
	if err != nil {
		r.Config.Error = err.Error()
		problem("The configuration is invalid, so the server won't start: " + err.Error())
	} else if tokens, err := auth.Parse(cfg.AgentTokens, cfg.ConsoleTokens); err != nil {
		r.Config.Valid, r.Config.Error = false, err.Error()
		problem("A token setting is invalid, so the server won't start: " + err.Error())
	} else {
		if cfg.OIDC != nil {
			tokens.BreakGlass()
		}
		for _, p := range tokens.Principals() {
			r.Tokens = append(r.Tokens, Token{Tenant: p.TenantID, Role: string(p.Role), Actor: p.Actor})
		}
	}

	r.Database = database(ctx, o, env["ALTIWARD_DATABASE_URL"], cfg.SinkNames(), cfg.Intune, now, problem)
	if err == nil {
		r.Sinks = sinks(ctx, o, cfg, problem)
	}
	return r
}

func database(ctx context.Context, o Options, dsn string, sinks []string, intune *config.Intune, now time.Time,
	problem func(string)) Database {
	db := Database{Configured: dsn != ""}
	if dsn == "" {
		problem("No ALTIWARD_DATABASE_URL: the server keeps everything in memory and loses it on restart")
		return db
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, closeDB, err := o.Connect(ctx, dsn)
	if err != nil {
		db.Error = scrub(err.Error(), dsn)
		problem("Can't reach the database: " + db.Error)
		return db
	}
	defer closeDB()
	db.Reachable = true
	stats, err := conn.Stats(ctx, now)
	if err != nil {
		db.Error = scrub(err.Error(), dsn)
		problem("Couldn't read the database: " + db.Error)
		return db
	}
	db.Stats = &stats
	if len(stats.MigrationsPending) > 0 {
		problem("Database migrations are pending; they run when the server starts. Has it started since the upgrade?")
	}
	if len(stats.MigrationsUnknown) > 0 {
		problem("The database was migrated by a newer Altiward than this one. Downgrades aren't supported: restore a backup or upgrade.")
	}
	for _, e := range stats.Exports {
		switch {
		case !slices.Contains(sinks, e.Sink):
			problem(fmt.Sprintf("%d items are still queued for %s, which is no longer configured. "+
				"If it was removed on purpose, run: altiward-api drop-exports %s", e.Pending, e.Sink, e.Sink))
		case e.Failing > 0:
			problem("Exports to " + e.Sink + " are failing: " + e.LastError)
		}
	}
	if stats.DevicesSilent > 0 {
		problem("Some Macs have stopped checking in; see Fleet in the console")
	}
	// A copy left from before Intune was turned off is deleted at the next start; only a
	// connection that is on can be failing.
	for _, m := range stats.MDM {
		if intune != nil && m.TenantID == intune.Tenant && m.Source == store.MDMIntune {
			intuneSync(m, now, problem)
		}
	}
	return db
}

// intuneSync reports an Intune sync that is failing, or that has stopped: it runs every 15
// minutes.
func intuneSync(m store.MDMSync, now time.Time, problem func(string)) {
	switch {
	case m.LastErrorAt != nil && (m.LastSuccessAt == nil || m.LastErrorAt.After(*m.LastSuccessAt)):
		problem("The Intune sync is failing: " + m.LastError)
	case m.LastSuccessAt != nil && now.Sub(*m.LastSuccessAt) > time.Hour:
		problem("The Intune sync last succeeded at " + m.LastSuccessAt.UTC().Format(time.RFC3339) +
			", more than an hour ago, though it runs every 15 minutes. Is the server running?")
	}
}

func sinks(ctx context.Context, o Options, cfg config.Config, problem func(string)) []SinkCheck {
	var checks []SinkCheck
	// The roots the server would use; a file it can't read fails every TLS check, as the
	// server would fail to start.
	trusted, rootsErr := cfg.TrustedRoots()
	check := func(sink, endpoint, addr, serverName string, roots *x509.CertPool, rootsErr error) {
		c := SinkCheck{Sink: sink, Endpoint: endpoint}
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		err := rootsErr
		if err == nil || serverName == "" { // plain TCP needs no roots
			err = o.Dial(dctx, addr, serverName, roots)
		}
		if err != nil {
			c.Error = err.Error()
			problem("Can't connect to " + sink + " at " + endpoint + ": " + c.Error)
		} else {
			c.Reachable = true
		}
		checks = append(checks, c)
	}
	httpsCheck := func(sink, raw string) {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			checks = append(checks, SinkCheck{Sink: sink, Endpoint: raw, Error: "not a URL"})
			problem(sink + " URL isn't a URL: " + raw)
			return
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80"}[u.Scheme]
			if port == "" {
				port = "443"
			}
		}
		serverName := u.Hostname()
		if u.Scheme == "http" {
			serverName = ""
		}
		check(sink, u.Scheme+"://"+u.Host, net.JoinHostPort(u.Hostname(), port), serverName, trusted, rootsErr)
	}
	if s := cfg.Splunk; s != nil {
		httpsCheck("splunk", s.URL)
	}
	if s := cfg.Sentinel; s != nil {
		httpsCheck("sentinel", s.Endpoint)
		checks[len(checks)-1].Auth = s.Auth
		switch {
		case s.Auth != config.SentinelManagedIdentity:
		case s.IdentityEndpoint != "":
			// Where a container app's token comes from: a local address the platform gives it.
			httpsCheck("sentinel-identity", s.IdentityEndpoint)
		default:
			// Where a VM's token comes from. Nothing answers off Azure, or if the container
			// can't reach the link-local address.
			check("sentinel-identity", "http://169.254.169.254", "169.254.169.254:80", "", nil, nil)
		}
	}
	if i := cfg.Intune; i != nil {
		// The connection to Microsoft Graph; not an export sink, so only the diagnosis lists it.
		httpsCheck("intune", "https://graph.microsoft.com")
		checks[len(checks)-1].Auth = i.Auth
		switch {
		case i.Auth != config.AuthManagedIdentity:
		case i.IdentityEndpoint != "":
			httpsCheck("intune-identity", i.IdentityEndpoint)
		default:
			check("intune-identity", "http://169.254.169.254", "169.254.169.254:80", "", nil, nil)
		}
	}
	if s := cfg.Syslog; s != nil {
		serverName := ""
		if s.TLS {
			serverName, _, _ = net.SplitHostPort(s.Addr)
		}
		roots, err := s.Roots(trusted)
		if rootsErr != nil {
			err = rootsErr
		}
		check("syslog", s.Addr, s.Addr, serverName, roots, err)
	}
	if o := cfg.OIDC; o != nil {
		httpsCheck("sso", o.Issuer) // the identity provider, for console sign-in
	}
	if checks == nil {
		checks = []SinkCheck{}
	}
	return checks
}

func redact(env map[string]string) map[string]string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]string{}
	for _, k := range keys {
		v := env[k]
		switch {
		case notSecret[k]:
			out[k] = v
		case k == "ALTIWARD_DATABASE_URL":
			out[k] = redactURL(v)
		default:
			out[k] = "set (hidden)"
		}
	}
	return out
}

// redactURL keeps a database URL's host, port and database, dropping the password and
// any query parameters (which can hold one too).
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "set (hidden: not a URL)"
	}
	user := ""
	if u.User != nil {
		user = u.User.Username() + "@"
	}
	return u.Scheme + "://" + user + u.Host + u.Path
}

// scrub removes the database URL, and its password, from an error message.
func scrub(msg, dsn string) string {
	msg = strings.ReplaceAll(msg, dsn, redactURL(dsn))
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			msg = strings.ReplaceAll(msg, pw, "…")
		}
	}
	return msg
}

func dial(ctx context.Context, addr, serverName string, roots *x509.CertPool) error {
	cfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12, RootCAs: roots}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if serverName == "" {
		return nil
	}
	return tls.Client(conn, cfg).HandshakeContext(ctx)
}
