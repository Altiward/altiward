package config_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/config"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := config.Load(env(map[string]string{"ALTIWARD_AGENT_TOKENS": "acme=x"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8080" || c.ExportInterval != 10*time.Second || c.SinkNames() != nil || c.ConsoleDir != "" {
		t.Fatalf("%+v", c)
	}
}

func TestAuditRetention(t *testing.T) {
	for v, want := range map[string]int{"": 0, "0": 0, "365": 365, "2555": 2555} {
		c, err := config.Load(env(map[string]string{"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_AUDIT_RETENTION_DAYS": v}))
		if err != nil || c.AuditRetentionDays != want {
			t.Errorf("%q: %d, %v", v, c.AuditRetentionDays, err)
		}
	}
}

// The console's update check is on unless ALTIWARD_UPDATE_CHECK is false.
func TestUpdateCheck(t *testing.T) {
	for v, want := range map[string]bool{"": true, "true": true, "false": false} {
		c, err := config.Load(env(map[string]string{"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_UPDATE_CHECK": v}))
		if err != nil || c.UpdateCheck != want {
			t.Errorf("%q: %v, %v", v, c.UpdateCheck, err)
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
	m := with("ALTIWARD_CONSOLE_TOKENS", "other=y")
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

func TestSinks(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"ALTIWARD_AGENT_TOKENS":           "acme=x",
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

func TestErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"no tokens":        {},
		"bad interval":     {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_EXPORT_INTERVAL": "soon"},
		"splunk no token":  {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_SPLUNK_HEC_URL": "https://s"},
		"sentinel partial": {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_SENTINEL_ENDPOINT": "https://dce"},
		"syslog no port":   {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_SYSLOG_ADDR": "siem"},
		"syslog format":    {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_SYSLOG_ADDR": "s:1", "ALTIWARD_SYSLOG_FORMAT": "leef"},
		"syslog framing":   {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_SYSLOG_ADDR": "s:1", "ALTIWARD_SYSLOG_FRAMING": "nul"},
		"syslog tls":       {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_SYSLOG_ADDR": "s:1", "ALTIWARD_SYSLOG_TLS": "maybe"},
		"update check":     {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_UPDATE_CHECK": "no"},
		"retention short":  {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_AUDIT_RETENTION_DAYS": "90"},
		"retention words":  {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_AUDIT_RETENTION_DAYS": "a year"},
		"syslog ca no tls": {"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_SYSLOG_ADDR": "s:1", "ALTIWARD_SYSLOG_TLS": "false",
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
	base := map[string]string{"ALTIWARD_AGENT_TOKENS": "a=x", "ALTIWARD_SYSLOG_ADDR": addr}

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
