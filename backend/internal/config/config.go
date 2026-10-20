// Package config reads the API server's settings from ALTIWARD_* environment variables.
package config

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr     string        // ALTIWARD_LISTEN_ADDR, default :8080
	DatabaseURL    string        // ALTIWARD_DATABASE_URL; empty = in-memory store (development only)
	AgentTokens    string        // ALTIWARD_AGENT_TOKENS, "tenant=token,..."
	ConsoleTokens  string        // ALTIWARD_CONSOLE_TOKENS, "tenant=token,..."
	ExportInterval time.Duration // ALTIWARD_EXPORT_INTERVAL, default 10s
	ConsoleDir     string        // ALTIWARD_CONSOLE_DIR: the built console (console/dist) to serve; empty = API only
	// ALTIWARD_AUDIT_RETENTION_DAYS: remove audit entries older than this many days, at
	// least MinAuditRetentionDays; 0 (the default) keeps them forever.
	AuditRetentionDays int
	// ALTIWARD_UPDATE_CHECK: whether the console's browser asks GitHub for newer releases
	// to tell admins about. Default true; "false" turns it off. The server itself never asks.
	UpdateCheck bool
	// ALTIWARD_TRUSTED_CAS_FILE (optional): PEM certificates trusted on top of the system's
	// roots for the SIEMs and the identity provider, when one has an internal CA's certificate
	TrustedCAsFile string

	Splunk   *Splunk
	Sentinel *Sentinel
	Syslog   *Syslog
	OIDC     *OIDC // console single sign-on; nil = console tokens only
}

// OIDC is the console's identity provider. Set ALTIWARD_OIDC_ISSUER to turn it on.
type OIDC struct {
	Issuer       string // ALTIWARD_OIDC_ISSUER, https
	ClientID     string // ALTIWARD_OIDC_CLIENT_ID
	ClientSecret string // ALTIWARD_OIDC_CLIENT_SECRET; empty for a public client (PKCE only)
	// ALTIWARD_CONSOLE_URL: where people open the console, such as
	// https://altiward.example.com. The redirect URL is this plus /v1/auth/callback.
	ConsoleURL string
	// ALTIWARD_OIDC_TENANT: the Altiward tenant people who sign in belong to. Defaults to
	// the one tenant the tokens name.
	Tenant      string
	GroupsClaim string   // ALTIWARD_OIDC_GROUPS_CLAIM, default groups
	Scopes      []string // ALTIWARD_OIDC_SCOPES, space separated, default "openid email profile"
	// ALTIWARD_OIDC_ADMIN_GROUPS, _OPERATOR_GROUPS, _VIEWER_GROUPS: comma-separated group
	// IDs or names, as the groups claim carries them.
	AdminGroups, OperatorGroups, ViewerGroups []string
}

// MinAuditRetentionDays is the shortest audit retention; the database refuses to delete a
// younger entry.
const MinAuditRetentionDays = 365

type Syslog struct {
	Addr    string // ALTIWARD_SYSLOG_ADDR, host:port
	TLS     bool   // ALTIWARD_SYSLOG_TLS, default true; "false" for plain TCP on a trusted network
	CAFile  string // ALTIWARD_SYSLOG_CA_FILE (optional): PEM roots for the receiver, instead of the system's
	Format  string // ALTIWARD_SYSLOG_FORMAT: cef (default) or json
	Framing string // ALTIWARD_SYSLOG_FRAMING: octet (default, RFC 6587) or newline
}

type Splunk struct {
	URL   string // ALTIWARD_SPLUNK_HEC_URL
	Token string // ALTIWARD_SPLUNK_HEC_TOKEN
	Index string // ALTIWARD_SPLUNK_INDEX (optional)
}

type Sentinel struct {
	Endpoint string // ALTIWARD_SENTINEL_ENDPOINT (the rule's logs ingestion URL, or a DCE's)
	RuleID   string // ALTIWARD_SENTINEL_DCR_ID (immutable ID)
	Stream   string // ALTIWARD_SENTINEL_STREAM, default Custom-AltiwardOCSF
	Auth     string // ALTIWARD_SENTINEL_AUTH: SentinelSecret (default) or SentinelManagedIdentity
	TenantID string // ALTIWARD_SENTINEL_TENANT_ID; secret only
	// ALTIWARD_SENTINEL_CLIENT_ID: the app registration's, or with a managed identity, a
	// user-assigned identity's (empty = the VM's system-assigned identity)
	ClientID     string
	ClientSecret string // ALTIWARD_SENTINEL_CLIENT_SECRET; secret only
}

// How the Sentinel export signs in to Entra ID.
const (
	SentinelSecret          = "secret"           // an app registration's client secret
	SentinelManagedIdentity = "managed-identity" // the Azure VM's managed identity, through IMDS
)

// Load reads and validates the environment.
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		ListenAddr:     or(getenv("ALTIWARD_LISTEN_ADDR"), ":8080"),
		DatabaseURL:    getenv("ALTIWARD_DATABASE_URL"),
		AgentTokens:    getenv("ALTIWARD_AGENT_TOKENS"),
		ConsoleTokens:  getenv("ALTIWARD_CONSOLE_TOKENS"),
		ExportInterval: 10 * time.Second,
		ConsoleDir:     getenv("ALTIWARD_CONSOLE_DIR"),
		UpdateCheck:    true,
		TrustedCAsFile: getenv("ALTIWARD_TRUSTED_CAS_FILE"),
	}
	if v := getenv("ALTIWARD_EXPORT_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Second {
			return c, fmt.Errorf("ALTIWARD_EXPORT_INTERVAL: want a duration of at least 1s, got %q", v)
		}
		c.ExportInterval = d
	}
	if v := getenv("ALTIWARD_AUDIT_RETENTION_DAYS"); v != "" {
		days, err := strconv.Atoi(v)
		if err != nil || days != 0 && days < MinAuditRetentionDays {
			return c, fmt.Errorf("ALTIWARD_AUDIT_RETENTION_DAYS: want 0 (keep forever) or at least %d, got %q", MinAuditRetentionDays, v)
		}
		c.AuditRetentionDays = days
	}
	switch v := getenv("ALTIWARD_UPDATE_CHECK"); v {
	case "", "true":
	case "false":
		c.UpdateCheck = false
	default:
		return c, fmt.Errorf("ALTIWARD_UPDATE_CHECK: want true or false, got %q", v)
	}
	if c.AgentTokens == "" && c.ConsoleTokens == "" {
		return c, errors.New("set ALTIWARD_AGENT_TOKENS and/or ALTIWARD_CONSOLE_TOKENS")
	}

	if url := getenv("ALTIWARD_SPLUNK_HEC_URL"); url != "" {
		c.Splunk = &Splunk{URL: url, Token: getenv("ALTIWARD_SPLUNK_HEC_TOKEN"), Index: getenv("ALTIWARD_SPLUNK_INDEX")}
		if c.Splunk.Token == "" {
			return c, errors.New("ALTIWARD_SPLUNK_HEC_TOKEN is required with ALTIWARD_SPLUNK_HEC_URL")
		}
	}
	if ep := getenv("ALTIWARD_SENTINEL_ENDPOINT"); ep != "" {
		c.Sentinel = &Sentinel{
			Endpoint:     ep,
			RuleID:       getenv("ALTIWARD_SENTINEL_DCR_ID"),
			Stream:       or(getenv("ALTIWARD_SENTINEL_STREAM"), "Custom-AltiwardOCSF"),
			Auth:         or(getenv("ALTIWARD_SENTINEL_AUTH"), SentinelSecret),
			TenantID:     getenv("ALTIWARD_SENTINEL_TENANT_ID"),
			ClientID:     getenv("ALTIWARD_SENTINEL_CLIENT_ID"),
			ClientSecret: getenv("ALTIWARD_SENTINEL_CLIENT_SECRET"),
		}
		s := c.Sentinel
		switch s.Auth {
		case SentinelSecret:
			if s.RuleID == "" || s.TenantID == "" || s.ClientID == "" || s.ClientSecret == "" {
				return c, errors.New("ALTIWARD_SENTINEL_* needs DCR_ID, TENANT_ID, CLIENT_ID and CLIENT_SECRET " +
					"(or ALTIWARD_SENTINEL_AUTH=managed-identity on an Azure VM)")
			}
		case SentinelManagedIdentity:
			if s.RuleID == "" {
				return c, errors.New("ALTIWARD_SENTINEL_DCR_ID is required with ALTIWARD_SENTINEL_ENDPOINT")
			}
			if s.ClientSecret != "" {
				return c, errors.New("ALTIWARD_SENTINEL_CLIENT_SECRET isn't used with ALTIWARD_SENTINEL_AUTH=managed-identity: " +
					"remove it from .env")
			}
		default:
			return c, fmt.Errorf("ALTIWARD_SENTINEL_AUTH: want secret or managed-identity, got %q", s.Auth)
		}
	}
	if addr := getenv("ALTIWARD_SYSLOG_ADDR"); addr != "" {
		c.Syslog = &Syslog{
			Addr: addr, TLS: true, CAFile: getenv("ALTIWARD_SYSLOG_CA_FILE"),
			Format: or(getenv("ALTIWARD_SYSLOG_FORMAT"), "cef"), Framing: or(getenv("ALTIWARD_SYSLOG_FRAMING"), "octet"),
		}
		s := c.Syslog
		switch v := getenv("ALTIWARD_SYSLOG_TLS"); v {
		case "", "true":
		case "false":
			s.TLS = false
		default:
			return c, fmt.Errorf("ALTIWARD_SYSLOG_TLS: want true or false, got %q", v)
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return c, fmt.Errorf("ALTIWARD_SYSLOG_ADDR: want host:port, got %q", addr)
		}
		if s.Format != "cef" && s.Format != "json" {
			return c, fmt.Errorf("ALTIWARD_SYSLOG_FORMAT: want cef or json, got %q", s.Format)
		}
		if s.Framing != "octet" && s.Framing != "newline" {
			return c, fmt.Errorf("ALTIWARD_SYSLOG_FRAMING: want octet or newline, got %q", s.Framing)
		}
		if s.CAFile != "" && !s.TLS {
			return c, errors.New("ALTIWARD_SYSLOG_CA_FILE needs TLS")
		}
	}
	if issuer := getenv("ALTIWARD_OIDC_ISSUER"); issuer != "" {
		o, err := loadOIDC(getenv, issuer, c.AgentTokens, c.ConsoleTokens)
		if err != nil {
			return c, err
		}
		c.OIDC = o
	}
	return c, nil
}

func loadOIDC(getenv func(string) string, issuer, agentTokens, consoleTokens string) (*OIDC, error) {
	o := &OIDC{
		Issuer: issuer, ClientID: getenv("ALTIWARD_OIDC_CLIENT_ID"), ClientSecret: getenv("ALTIWARD_OIDC_CLIENT_SECRET"),
		ConsoleURL:  strings.TrimSuffix(getenv("ALTIWARD_CONSOLE_URL"), "/"),
		Tenant:      getenv("ALTIWARD_OIDC_TENANT"),
		GroupsClaim: or(getenv("ALTIWARD_OIDC_GROUPS_CLAIM"), "groups"),
		Scopes:      strings.Fields(or(getenv("ALTIWARD_OIDC_SCOPES"), "openid email profile")),
		AdminGroups: list(getenv("ALTIWARD_OIDC_ADMIN_GROUPS")), OperatorGroups: list(getenv("ALTIWARD_OIDC_OPERATOR_GROUPS")),
		ViewerGroups: list(getenv("ALTIWARD_OIDC_VIEWER_GROUPS")),
	}
	if err := secureURL("ALTIWARD_OIDC_ISSUER", o.Issuer); err != nil {
		return nil, err
	}
	if err := secureURL("ALTIWARD_CONSOLE_URL", o.ConsoleURL); err != nil {
		return nil, fmt.Errorf("%w (single sign-on needs it for the redirect URL)", err)
	}
	if o.ClientID == "" {
		return nil, errors.New("ALTIWARD_OIDC_CLIENT_ID is required with ALTIWARD_OIDC_ISSUER")
	}
	if !slices.Contains(o.Scopes, "openid") {
		o.Scopes = append([]string{"openid"}, o.Scopes...)
	}
	if len(o.AdminGroups)+len(o.OperatorGroups)+len(o.ViewerGroups) == 0 {
		return nil, errors.New("set at least one of ALTIWARD_OIDC_ADMIN_GROUPS, _OPERATOR_GROUPS and _VIEWER_GROUPS: " +
			"nobody could sign in")
	}
	if o.Tenant == "" {
		tenants := tokenTenants(agentTokens + "," + consoleTokens)
		if len(tenants) != 1 {
			return nil, errors.New("set ALTIWARD_OIDC_TENANT: the tokens name more than one tenant")
		}
		o.Tenant = tenants[0]
	}
	return o, nil
}

// secureURL accepts an absolute https URL, or http for localhost (development).
func secureURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLocal(u.Hostname()))) {
		return fmt.Errorf("%s: want an https URL, got %q", name, raw)
	}
	return nil
}

func isLocal(host string) bool {
	return host == "localhost" || net.ParseIP(host).IsLoopback()
}

// tokenTenants lists the distinct tenants in "tenant=token,..." lists.
func tokenTenants(lists string) []string {
	var out []string
	for _, entry := range strings.Split(lists, ",") {
		if tenant, _, ok := strings.Cut(strings.TrimSpace(entry), "="); ok && tenant != "" && !slices.Contains(out, tenant) {
			out = append(out, tenant)
		}
	}
	return out
}

func list(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// SinkNames are the export sinks events are queued for.
func (c Config) SinkNames() []string {
	var names []string
	if c.Splunk != nil {
		names = append(names, "splunk")
	}
	if c.Sentinel != nil {
		names = append(names, "sentinel")
	}
	if c.Syslog != nil {
		names = append(names, "syslog")
	}
	return names
}

// FromEnv loads from the process environment.
func FromEnv() (Config, error) { return Load(os.Getenv) }

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// TrustedRoots is the roots for the server's outbound TLS (SIEMs and the identity provider):
// nil, meaning the system's, or the system's plus ALTIWARD_TRUSTED_CAS_FILE.
func (c Config) TrustedRoots() (*x509.CertPool, error) {
	if c.TrustedCAsFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(c.TrustedCAsFile)
	if err != nil {
		return nil, fmt.Errorf("ALTIWARD_TRUSTED_CAS_FILE: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ALTIWARD_TRUSTED_CAS_FILE %s: no PEM certificates", c.TrustedCAsFile)
	}
	return roots, nil
}

// Roots is the roots the syslog receiver's certificate must chain to: ALTIWARD_SYSLOG_CA_FILE
// alone when it's set, otherwise trusted (TrustedRoots).
func (s Syslog) Roots(trusted *x509.CertPool) (*x509.CertPool, error) {
	if s.CAFile == "" {
		return trusted, nil
	}
	pem, err := os.ReadFile(s.CAFile)
	if err != nil {
		return nil, fmt.Errorf("ALTIWARD_SYSLOG_CA_FILE: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ALTIWARD_SYSLOG_CA_FILE %s: no PEM certificates", s.CAFile)
	}
	return roots, nil
}
