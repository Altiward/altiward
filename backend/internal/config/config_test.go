package config_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/config"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := config.Load(env(map[string]string{"ALTIWARD_AGENT_TOKENS": "acme=x", "ALTIWARD_CONSOLE_TOKENS": "acme=y"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8080" || c.ExportInterval != 10*time.Second || c.SinkNames() != nil || c.ConsoleDir != "" {
		t.Fatalf("%+v", c)
	}
}

// Tenants are the distinct tenants the tokens name, so the server can clear what each
// tenant kept from a connection that has been turned off.
func TestTenants(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"ALTIWARD_AGENT_TOKENS": "acme=x, globex=y", "ALTIWARD_CONSOLE_TOKENS": "acme=z,initech=w,globex=v",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Tenants(), ","); got != "acme,globex,initech" {
		t.Fatalf("tenants = %q", got)
	}
}

func TestAuditRetention(t *testing.T) {
	for v, want := range map[string]int{"": 0, "0": 0, "365": 365, "2555": 2555} {
		c, err := config.Load(env(map[string]string{"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_AUDIT_RETENTION_DAYS": v}))
		if err != nil || c.AuditRetentionDays != want {
			t.Errorf("%q: %d, %v", v, c.AuditRetentionDays, err)
		}
	}
}

// The console's update check is on unless ALTIWARD_UPDATE_CHECK is false.
func TestUpdateCheck(t *testing.T) {
	for v, want := range map[string]bool{"": true, "true": true, "false": false} {
		c, err := config.Load(env(map[string]string{"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_UPDATE_CHECK": v}))
		if err != nil || c.UpdateCheck != want {
			t.Errorf("%q: %v, %v", v, c.UpdateCheck, err)
		}
	}
}

// How fast a tenant may add Macs and keys is bounded by default: 1000 new Macs an hour and
// 5 keys for one Mac a day. 0 turns a limit off.
func TestEnrollLimits(t *testing.T) {
	load := func(m map[string]string) (config.Config, error) {
		m["ALTIWARD_AGENT_TOKENS"], m["ALTIWARD_CONSOLE_TOKENS"] = "a=x", "a=y"
		return config.Load(env(m))
	}
	for name, c := range map[string]struct {
		macs, keys string
		want       store.EnrollLimits
	}{
		"defaults":     {"", "", store.EnrollLimits{NewMacsPerHour: 1000, KeysPerMacPerDay: 5}},
		"set":          {"50", "3", store.EnrollLimits{NewMacsPerHour: 50, KeysPerMacPerDay: 3}},
		"no Mac limit": {"0", "", store.EnrollLimits{NewMacsPerHour: 0, KeysPerMacPerDay: 5}},
		"no key limit": {"", "0", store.EnrollLimits{NewMacsPerHour: 1000, KeysPerMacPerDay: 0}},
		"both off":     {"0", "0", store.EnrollLimits{}},
		"one set":      {"7", "", store.EnrollLimits{NewMacsPerHour: 7, KeysPerMacPerDay: 5}},
	} {
		cfg, err := load(map[string]string{"ALTIWARD_ENROLL_NEW_MACS_PER_HOUR": c.macs, "ALTIWARD_ENROLL_KEYS_PER_MAC_PER_DAY": c.keys})
		if err != nil || cfg.EnrollLimits != c.want {
			t.Errorf("%s: %+v, %v, want %+v", name, cfg.EnrollLimits, err, c.want)
		}
	}
	for _, name := range []string{"ALTIWARD_ENROLL_NEW_MACS_PER_HOUR", "ALTIWARD_ENROLL_KEYS_PER_MAC_PER_DAY"} {
		for _, v := range []string{"-1", "abc", "1.5", "1e3", "ten"} {
			_, err := load(map[string]string{name: v})
			want := name + `: want 0 (no limit) or a positive whole number, got "` + v + `"`
			if err == nil || err.Error() != want {
				t.Errorf("%s=%q: err = %v, want %s", name, v, err, want)
			}
		}
	}
}

func TestOIDC(t *testing.T) {
	base := map[string]string{
		"ALTIWARD_AGENT_TOKENS": "acme=x", "ALTIWARD_CONSOLE_TOKENS": "acme=y",
		"ALTIWARD_OIDC_ISSUER": "https://login.example.com/t/v2.0", "ALTIWARD_OIDC_CLIENT_ID": "app",
		"ALTIWARD_CONSOLE_URL": "https://altiward.example.com/", "ALTIWARD_OIDC_ADMIN_GROUPS": "g1, g2",
		"ALTIWARD_OIDC_SCOPES": "email groups",
	}
	c, err := config.Load(env(base))
	if err != nil {
		t.Fatal(err)
	}
	o := c.OIDC
	if o == nil || o.Tenant != "acme" || o.ConsoleURL != "https://altiward.example.com" || o.GroupsClaim != "groups" ||
		strings.Join(o.AdminGroups, "|") != "g1|g2" || strings.Join(o.Scopes, " ") != "openid email groups" {
		t.Fatalf("%+v", o)
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for kk, vv := range base {
			m[kk] = vv
		}
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, m := range map[string]map[string]string{
		"http issuer":        with("ALTIWARD_OIDC_ISSUER", "http://login.example.com"),
		"no client ID":       with("ALTIWARD_OIDC_CLIENT_ID", ""),
		"no console URL":     with("ALTIWARD_CONSOLE_URL", ""),
		"relative URL":       with("ALTIWARD_CONSOLE_URL", "altiward.example.com"),
		"no groups":          with("ALTIWARD_OIDC_ADMIN_GROUPS", ""),
		"two tenants, unset": with("ALTIWARD_CONSOLE_TOKENS", "other=y"),
	} {
		if _, err := config.Load(env(m)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	m := with("ALTIWARD_CONSOLE_TOKENS", "other=y,acme=z")
	m["ALTIWARD_OIDC_TENANT"] = "other"
	if c, err := config.Load(env(m)); err != nil || c.OIDC.Tenant != "other" {
		t.Errorf("explicit tenant: %v", err)
	}
	// Plain http only on this machine, for development.
	m = with("ALTIWARD_CONSOLE_URL", "http://localhost:5173")
	m["ALTIWARD_OIDC_ISSUER"] = "http://127.0.0.1:9000"
	if _, err := config.Load(env(m)); err != nil {
		t.Errorf("localhost: %v", err)
	}
}

func TestOIDCProviderSignOut(t *testing.T) {
	base := map[string]string{
		"ALTIWARD_AGENT_TOKENS": "acme=x", "ALTIWARD_CONSOLE_TOKENS": "acme=y",
		"ALTIWARD_OIDC_ISSUER": "https://login.microsoftonline.com/tenant-id/v2.0", "ALTIWARD_OIDC_CLIENT_ID": "app",
		"ALTIWARD_CONSOLE_URL": "https://altiward.example.com", "ALTIWARD_OIDC_ADMIN_GROUPS": "g1",
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for kk, vv := range base {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	// Off unless asked for.
	if c, err := config.Load(env(base)); err != nil || c.OIDC.ProviderSignOut {
		t.Fatalf("default: %v", err)
	}
	for v, want := range map[string]bool{"true": true, "false": false, "": false} {
		c, err := config.Load(env(with("ALTIWARD_OIDC_PROVIDER_SIGN_OUT", v)))
		if err != nil || c.OIDC.ProviderSignOut != want {
			t.Errorf("%q: %v, %v", v, c.OIDC, err)
		}
	}
	_, err := config.Load(env(with("ALTIWARD_OIDC_PROVIDER_SIGN_OUT", "maybe")))
	if want := `ALTIWARD_OIDC_PROVIDER_SIGN_OUT: want true or false, got "maybe"`; err == nil || err.Error() != want {
		t.Errorf("garbage: %v", err)
	}
	// Only Entra ID, for now.
	m := with("ALTIWARD_OIDC_PROVIDER_SIGN_OUT", "true")
	m["ALTIWARD_OIDC_ISSUER"] = "https://login.example.com/t/v2.0"
	_, err = config.Load(env(m))
	if want := "ALTIWARD_OIDC_PROVIDER_SIGN_OUT works with Entra ID only until 1.2.0"; err == nil || err.Error() != want {
		t.Errorf("other issuer: %v", err)
	}
	// An issuer that merely contains the host is not Entra.
	m["ALTIWARD_OIDC_ISSUER"] = "https://login.microsoftonline.com.evil.example/t/v2.0"
	if _, err = config.Load(env(m)); err == nil {
		t.Error("lookalike issuer accepted")
	}
	// Off with another issuer is fine.
	m["ALTIWARD_OIDC_PROVIDER_SIGN_OUT"] = "false"
	if _, err = config.Load(env(m)); err != nil {
		t.Errorf("off, other issuer: %v", err)
	}
}

func TestSinks(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"ALTIWARD_AGENT_TOKENS":           "acme=x",
		"ALTIWARD_CONSOLE_TOKENS":         "acme=y",
		"ALTIWARD_SPLUNK_HEC_URL":         "https://splunk:8088",
		"ALTIWARD_SPLUNK_HEC_TOKEN":       "hec",
		"ALTIWARD_SENTINEL_ENDPOINT":      "https://dce",
		"ALTIWARD_SENTINEL_DCR_ID":        "dcr-1",
		"ALTIWARD_SENTINEL_TENANT_ID":     "t",
		"ALTIWARD_SENTINEL_CLIENT_ID":     "c",
		"ALTIWARD_SENTINEL_CLIENT_SECRET": "s",
		"ALTIWARD_SYSLOG_ADDR":            "siem.example.com:6514",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.SinkNames(), ","); got != "splunk,sentinel,syslog" || c.Sentinel.Stream != "Custom-AltiwardOCSF" {
		t.Fatalf("sinks = %s stream = %s", got, c.Sentinel.Stream)
	}
	if s := c.Syslog; !s.TLS || s.Format != "cef" || s.Framing != "octet" {
		t.Fatalf("syslog defaults = %+v", s)
	}
	if c.Sentinel.Auth != config.SentinelSecret {
		t.Fatalf("sentinel auth = %q", c.Sentinel.Auth)
	}
}

func TestSentinelManagedIdentity(t *testing.T) {
	m := map[string]string{
		"ALTIWARD_AGENT_TOKENS":      "acme=x",
		"ALTIWARD_CONSOLE_TOKENS":    "acme=y",
		"ALTIWARD_SENTINEL_ENDPOINT": "https://dce",
		"ALTIWARD_SENTINEL_DCR_ID":   "dcr-1",
		"ALTIWARD_SENTINEL_AUTH":     "managed-identity",
	}
	c, err := config.Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if s := c.Sentinel; s.Auth != config.SentinelManagedIdentity || s.ClientID != "" || s.TenantID != "" {
		t.Fatalf("system-assigned = %+v", s)
	}
	m["ALTIWARD_SENTINEL_CLIENT_ID"] = "user-assigned-id"
	if c, err = config.Load(env(m)); err != nil || c.Sentinel.ClientID != "user-assigned-id" {
		t.Fatalf("user-assigned = %+v, %v", c.Sentinel, err)
	}
	// Azure Container Apps sets these for an app with a managed identity.
	m["IDENTITY_ENDPOINT"], m["IDENTITY_HEADER"] = "http://localhost:42356/msi/token", "header-1"
	if c, err = config.Load(env(m)); err != nil || c.Sentinel.IdentityEndpoint != "http://localhost:42356/msi/token" ||
		c.Sentinel.IdentityHeader != "header-1" {
		t.Fatalf("container app = %+v, %v", c.Sentinel, err)
	}

	for name, tc := range map[string]struct{ key, value, want string }{
		"a secret too": {"ALTIWARD_SENTINEL_CLIENT_SECRET", "s", "ALTIWARD_SENTINEL_CLIENT_SECRET isn't used with ALTIWARD_SENTINEL_AUTH=managed-identity"},
		"no rule":      {"ALTIWARD_SENTINEL_DCR_ID", "", "ALTIWARD_SENTINEL_DCR_ID"},
		"unknown auth": {"ALTIWARD_SENTINEL_AUTH", "msi", `ALTIWARD_SENTINEL_AUTH: want secret, certificate or managed-identity, got "msi"`},
	} {
		bad := map[string]string{}
		for k, v := range m {
			bad[k] = v
		}
		bad[tc.key] = tc.value
		if _, err := config.Load(env(bad)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestSentinelCertificate(t *testing.T) {
	m := map[string]string{
		"ALTIWARD_AGENT_TOKENS":              "acme=x",
		"ALTIWARD_CONSOLE_TOKENS":            "acme=y",
		"ALTIWARD_SENTINEL_ENDPOINT":         "https://dce",
		"ALTIWARD_SENTINEL_DCR_ID":           "dcr-1",
		"ALTIWARD_SENTINEL_AUTH":             "certificate",
		"ALTIWARD_SENTINEL_TENANT_ID":        "t",
		"ALTIWARD_SENTINEL_CLIENT_ID":        "c",
		"ALTIWARD_SENTINEL_CERTIFICATE_FILE": "/etc/altiward/certs/sentinel.pem",
	}
	c, err := config.Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if s := c.Sentinel; s.Auth != config.SentinelCertificate || s.CertificateFile != "/etc/altiward/certs/sentinel.pem" {
		t.Fatalf("certificate = %+v", s)
	}

	for name, tc := range map[string]struct{ key, value, want string }{
		"a secret too": {"ALTIWARD_SENTINEL_CLIENT_SECRET", "s", "ALTIWARD_SENTINEL_CLIENT_SECRET isn't used with ALTIWARD_SENTINEL_AUTH=certificate"},
		"no file":      {"ALTIWARD_SENTINEL_CERTIFICATE_FILE", "", "needs ALTIWARD_SENTINEL_DCR_ID, TENANT_ID, CLIENT_ID and CERTIFICATE_FILE"},
		"no tenant":    {"ALTIWARD_SENTINEL_TENANT_ID", "", "needs ALTIWARD_SENTINEL_DCR_ID, TENANT_ID, CLIENT_ID and CERTIFICATE_FILE"},
		"another auth": {"ALTIWARD_SENTINEL_AUTH", "secret", "ALTIWARD_SENTINEL_CERTIFICATE_FILE is only used with ALTIWARD_SENTINEL_AUTH=certificate"},
	} {
		bad := map[string]string{}
		for k, v := range m {
			bad[k] = v
		}
		bad[tc.key] = tc.value
		if _, err := config.Load(env(bad)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestIntune(t *testing.T) {
	m := map[string]string{
		"ALTIWARD_AGENT_TOKENS":            "acme=x",
		"ALTIWARD_CONSOLE_TOKENS":          "acme=y",
		"ALTIWARD_INTUNE_AUTH":             "certificate",
		"ALTIWARD_INTUNE_TENANT_ID":        "t",
		"ALTIWARD_INTUNE_CLIENT_ID":        "c",
		"ALTIWARD_INTUNE_CERTIFICATE_FILE": "/etc/altiward/certs/intune.pem",
	}
	c, err := config.Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if i := c.Intune; i == nil || i.Auth != config.AuthCertificate || i.TenantID != "t" || i.ClientID != "c" ||
		i.CertificateFile != "/etc/altiward/certs/intune.pem" || i.Tenant != "acme" {
		t.Fatalf("certificate = %+v", c.Intune)
	}
	if got := strings.Join(c.SinkNames(), ","); got != "" {
		t.Fatalf("Intune is not a sink, sinks = %q", got)
	}

	secret := map[string]string{
		"ALTIWARD_AGENT_TOKENS":         "acme=x",
		"ALTIWARD_CONSOLE_TOKENS":       "acme=y",
		"ALTIWARD_INTUNE_AUTH":          "secret",
		"ALTIWARD_INTUNE_TENANT_ID":     "t",
		"ALTIWARD_INTUNE_CLIENT_ID":     "c",
		"ALTIWARD_INTUNE_CLIENT_SECRET": "s",
	}
	if c, err = config.Load(env(secret)); err != nil || c.Intune.Auth != config.AuthSecret || c.Intune.ClientSecret != "s" {
		t.Fatalf("secret = %+v, %v", c.Intune, err)
	}

	// A managed identity needs no tenant, and the platform's settings come with it.
	mi := map[string]string{
		"ALTIWARD_AGENT_TOKENS":   "acme=x",
		"ALTIWARD_CONSOLE_TOKENS": "acme=y",
		"ALTIWARD_INTUNE_AUTH":    "managed-identity",
	}
	if c, err = config.Load(env(mi)); err != nil || c.Intune.Auth != config.AuthManagedIdentity || c.Intune.Tenant != "acme" ||
		c.Intune.TenantID != "" || c.Intune.IdentityEndpoint != "" {
		t.Fatalf("managed identity = %+v, %v", c.Intune, err)
	}
	mi["ALTIWARD_INTUNE_CLIENT_ID"] = "user-assigned-id"
	mi["IDENTITY_ENDPOINT"], mi["IDENTITY_HEADER"] = "http://localhost:42356/msi/token", "header-1"
	if c, err = config.Load(env(mi)); err != nil || c.Intune.ClientID != "user-assigned-id" ||
		c.Intune.IdentityEndpoint != "http://localhost:42356/msi/token" || c.Intune.IdentityHeader != "header-1" {
		t.Fatalf("container app = %+v, %v", c.Intune, err)
	}

	// Off unless AUTH is set.
	if c, err = config.Load(env(map[string]string{"ALTIWARD_AGENT_TOKENS": "acme=x", "ALTIWARD_CONSOLE_TOKENS": "acme=y"})); err != nil || c.Intune != nil {
		t.Fatalf("off = %+v, %v", c.Intune, err)
	}

	for name, tc := range map[string]struct{ key, value, want string }{
		"no auth":        {"ALTIWARD_INTUNE_AUTH", "", "set ALTIWARD_INTUNE_AUTH to turn Intune on (secret, certificate or managed-identity)"},
		"unknown auth":   {"ALTIWARD_INTUNE_AUTH", "bogus", `ALTIWARD_INTUNE_AUTH: want secret, certificate or managed-identity, got "bogus"`},
		"no file":        {"ALTIWARD_INTUNE_CERTIFICATE_FILE", "", "ALTIWARD_INTUNE_AUTH=certificate needs ALTIWARD_INTUNE_TENANT_ID, CLIENT_ID and CERTIFICATE_FILE"},
		"no tenant":      {"ALTIWARD_INTUNE_TENANT_ID", "", "ALTIWARD_INTUNE_AUTH=certificate needs ALTIWARD_INTUNE_TENANT_ID, CLIENT_ID and CERTIFICATE_FILE"},
		"no client":      {"ALTIWARD_INTUNE_CLIENT_ID", "", "ALTIWARD_INTUNE_AUTH=certificate needs ALTIWARD_INTUNE_TENANT_ID, CLIENT_ID and CERTIFICATE_FILE"},
		"a secret too":   {"ALTIWARD_INTUNE_CLIENT_SECRET", "s", "ALTIWARD_INTUNE_CLIENT_SECRET isn't used with ALTIWARD_INTUNE_AUTH=certificate: remove it"},
		"two tenants":    {"ALTIWARD_CONSOLE_TOKENS", "acme=y,beta=z", "ALTIWARD_INTUNE_* needs a server with one tenant: the tokens name more than one"},
		"another auth":   {"ALTIWARD_INTUNE_AUTH", "secret", "ALTIWARD_INTUNE_CERTIFICATE_FILE is only used with ALTIWARD_INTUNE_AUTH=certificate"},
		"managed + file": {"ALTIWARD_INTUNE_AUTH", "managed-identity", "ALTIWARD_INTUNE_CERTIFICATE_FILE is only used with ALTIWARD_INTUNE_AUTH=certificate"},
	} {
		bad := map[string]string{}
		for k, v := range m {
			bad[k] = v
		}
		bad[tc.key] = tc.value
		if _, err := config.Load(env(bad)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	for name, tc := range map[string]struct {
		set  map[string]string
		want string
	}{
		"secret missing": {map[string]string{"ALTIWARD_INTUNE_AUTH": "secret", "ALTIWARD_INTUNE_TENANT_ID": "t", "ALTIWARD_INTUNE_CLIENT_ID": "c"},
			"ALTIWARD_INTUNE_AUTH=secret needs ALTIWARD_INTUNE_TENANT_ID, CLIENT_ID and CLIENT_SECRET"},
		"a secret with a managed identity": {map[string]string{"ALTIWARD_INTUNE_AUTH": "managed-identity", "ALTIWARD_INTUNE_CLIENT_SECRET": "s"},
			"ALTIWARD_INTUNE_CLIENT_SECRET isn't used with ALTIWARD_INTUNE_AUTH=managed-identity: remove it"},
		"a secret without auth": {map[string]string{"ALTIWARD_INTUNE_CLIENT_SECRET": "s"},
			"set ALTIWARD_INTUNE_AUTH to turn Intune on (secret, certificate or managed-identity)"},
		"a tenant without auth": {map[string]string{"ALTIWARD_INTUNE_TENANT_ID": "t"},
			"set ALTIWARD_INTUNE_AUTH to turn Intune on (secret, certificate or managed-identity)"},
	} {
		bad := map[string]string{"ALTIWARD_AGENT_TOKENS": "acme=x", "ALTIWARD_CONSOLE_TOKENS": "acme=y"}
		for k, v := range tc.set {
			bad[k] = v
		}
		if _, err := config.Load(env(bad)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"no tokens":        {},
		"bad interval":     {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_EXPORT_INTERVAL": "soon"},
		"splunk no token":  {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_SPLUNK_HEC_URL": "https://s"},
		"sentinel partial": {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_SENTINEL_ENDPOINT": "https://dce"},
		"syslog no port":   {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_SYSLOG_ADDR": "siem"},
		"syslog format":    {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_SYSLOG_ADDR": "s:1", "ALTIWARD_SYSLOG_FORMAT": "leef"},
		"syslog framing":   {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_SYSLOG_ADDR": "s:1", "ALTIWARD_SYSLOG_FRAMING": "nul"},
		"syslog tls":       {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_SYSLOG_ADDR": "s:1", "ALTIWARD_SYSLOG_TLS": "maybe"},
		"update check":     {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_UPDATE_CHECK": "no"},
		"retention short":  {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_AUDIT_RETENTION_DAYS": "90"},
		"retention words":  {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_AUDIT_RETENTION_DAYS": "a year"},
		"syslog ca no tls": {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_SYSLOG_ADDR": "s:1", "ALTIWARD_SYSLOG_TLS": "false",
			"ALTIWARD_SYSLOG_CA_FILE": "/ca.pem"},
	}
	for name, m := range cases {
		if _, err := config.Load(env(m)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// handshake reports whether a TLS connection to addr verifies against roots (nil: the
// system's).
func handshake(addr string, roots *x509.CertPool) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"})
	if err == nil {
		conn.Close()
	}
	return err
}

// TestTrustedRoots: ALTIWARD_TRUSTED_CAS_FILE adds a private CA to the system's roots, for
// the SIEM and the identity provider. ALTIWARD_SYSLOG_CA_FILE still replaces them for syslog.
func TestTrustedRoots(t *testing.T) {
	caFile, cert := testfixture.PrivateCA(t, "Private CA")
	addr := testfixture.TLSListener(t, cert)
	base := map[string]string{"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_CONSOLE_TOKENS": "a=y", "ALTIWARD_SYSLOG_ADDR": addr}

	c, err := config.Load(env(base))
	if err != nil {
		t.Fatal(err)
	}
	roots, err := c.TrustedRoots()
	if err != nil || roots != nil {
		t.Fatalf("unset: roots %v, err %v; want the system's (nil)", roots, err)
	}
	if handshake(addr, roots) == nil {
		t.Fatal("a private CA was trusted without the setting")
	}

	with := map[string]string{"ALTIWARD_TRUSTED_CAS_FILE": caFile}
	for k, v := range base {
		with[k] = v
	}
	c, err = config.Load(env(with))
	if err != nil {
		t.Fatal(err)
	}
	if roots, err = c.TrustedRoots(); err != nil {
		t.Fatal(err)
	}
	if err := handshake(addr, roots); err != nil {
		t.Fatalf("with ALTIWARD_TRUSTED_CAS_FILE: %v", err)
	}
	syslogRoots, err := c.Syslog.Roots(roots)
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(addr, syslogRoots); err != nil {
		t.Fatalf("syslog with trusted CAs only: %v", err)
	}
	other, _ := testfixture.PrivateCA(t, "Another CA")
	c.Syslog.CAFile = other
	if syslogRoots, err = c.Syslog.Roots(roots); err != nil {
		t.Fatal(err)
	}
	if handshake(addr, syslogRoots) == nil {
		t.Fatal("ALTIWARD_SYSLOG_CA_FILE didn't replace the roots for syslog")
	}

	bad := t.TempDir() + "/bad.pem"
	os.WriteFile(bad, []byte("not a certificate"), 0o600)
	for _, file := range []string{bad, t.TempDir() + "/missing.pem"} {
		with["ALTIWARD_TRUSTED_CAS_FILE"] = file
		c, err := config.Load(env(with))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.TrustedRoots(); err == nil || !strings.Contains(err.Error(), "ALTIWARD_TRUSTED_CAS_FILE") {
			t.Errorf("%s: err %v", file, err)
		}
	}
}

func TestConsoleNeedsAnAdminWayIn(t *testing.T) {
	const noToken = "set ALTIWARD_CONSOLE_TOKENS, or single sign-on with ALTIWARD_OIDC_ISSUER: without either, nobody can sign in to the console"
	const noAdmins = "set ALTIWARD_OIDC_ADMIN_GROUPS, or keep a console token in ALTIWARD_CONSOLE_TOKENS: without either, nobody can approve Macs or change settings"
	sso := map[string]string{
		"ALTIWARD_OIDC_ISSUER": "https://login.example.com/t/v2.0", "ALTIWARD_OIDC_CLIENT_ID": "app",
		"ALTIWARD_CONSOLE_URL": "https://altiward.example.com",
	}
	twoOrgs := map[string]string{"ALTIWARD_AGENT_TOKENS": "a=agent-token-0000000001,b=agent-token-0000000002"}
	with := func(extra ...map[string]string) map[string]string {
		m := map[string]string{"ALTIWARD_AGENT_TOKENS": "acme=agent-token-0000000001"}
		for _, e := range extra {
			for k, v := range e {
				m[k] = v
			}
		}
		return m
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"no console tokens, no single sign-on", with(), noToken},
		{"only commas", with(map[string]string{"ALTIWARD_CONSOLE_TOKENS": ","}), noToken},
		{"only blanks and a comma", with(map[string]string{"ALTIWARD_CONSOLE_TOKENS": " , "}), noToken},
		{"single sign-on with viewer groups only", with(sso, map[string]string{"ALTIWARD_OIDC_VIEWER_GROUPS": "g1"}), noAdmins},
		{"single sign-on with admin groups", with(sso, map[string]string{"ALTIWARD_OIDC_ADMIN_GROUPS": "g1"}), ""},
		{"console token, no single sign-on", with(map[string]string{"ALTIWARD_CONSOLE_TOKENS": "acme=console-token-0000000001"}), ""},
		{"console token, single sign-on with viewer groups only", with(sso, map[string]string{
			"ALTIWARD_CONSOLE_TOKENS": "acme=console-token-0000000001", "ALTIWARD_OIDC_VIEWER_GROUPS": "g1"}), ""},
		// A token that isn't tenant=token is auth.Parse's to explain.
		{"a console token without an organisation", with(map[string]string{"ALTIWARD_CONSOLE_TOKENS": "console-token-0000000001"}), ""},

		// Each organisation needs a way in of its own: single sign-on serves only one.
		{"two organisations, single sign-on and a console token for one", with(sso, twoOrgs, map[string]string{
			"ALTIWARD_OIDC_TENANT": "a", "ALTIWARD_OIDC_ADMIN_GROUPS": "g1", "ALTIWARD_CONSOLE_TOKENS": "a=console-token-0000000001"}),
			"organisation b: set ALTIWARD_CONSOLE_TOKENS for it, or single sign-on with ALTIWARD_OIDC_ISSUER and ALTIWARD_OIDC_TENANT=b: " +
				"without either, nobody can sign in to its console"},
		{"two organisations, single sign-on for one and a console token for the other", with(sso, twoOrgs, map[string]string{
			"ALTIWARD_OIDC_TENANT": "a", "ALTIWARD_OIDC_ADMIN_GROUPS": "g1", "ALTIWARD_CONSOLE_TOKENS": "a=console-token-0000000001,b=console-token-0000000002"}), ""},
		{"two organisations, a console token for each", with(twoOrgs, map[string]string{
			"ALTIWARD_CONSOLE_TOKENS": "a=console-token-0000000001,b=console-token-0000000002"}), ""},
		{"two organisations, single sign-on without admin groups for one", with(sso, twoOrgs, map[string]string{
			"ALTIWARD_OIDC_TENANT": "b", "ALTIWARD_OIDC_VIEWER_GROUPS": "g1", "ALTIWARD_CONSOLE_TOKENS": "a=console-token-0000000001"}),
			"organisation b: set ALTIWARD_OIDC_ADMIN_GROUPS, or keep a console token for it in ALTIWARD_CONSOLE_TOKENS: " +
				"without either, nobody can approve its Macs or change its settings"},
		{"two organisations, no console tokens", with(twoOrgs),
			"organisation a: set ALTIWARD_CONSOLE_TOKENS for it, or single sign-on with ALTIWARD_OIDC_ISSUER and ALTIWARD_OIDC_TENANT=a: " +
				"without either, nobody can sign in to its console"},
	} {
		_, err := config.Load(env(tc.env))
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || err.Error() != tc.want):
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}
