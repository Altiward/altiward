// altiward-api serves agent ingestion and the console read API, and, with
// ALTIWARD_CONSOLE_DIR set, the console itself. It runs the SIEM export workers and the
// monitor that notices Macs that stop checking in, and, with a retention period set, removes
// old audit entries. Configuration: ALTIWARD_* environment
// variables (see backend/internal/config and backend/README.md).
//
//	altiward-api            run the server
//	altiward-api health     exit 0 if the server on ALTIWARD_LISTEN_ADDR answers /healthz
//	altiward-api diagnose   print a support report with every secret removed
//	altiward-api drop-exports SINK
//	                        drop what is still queued for a sink that is no longer configured
//	altiward-api version    print the version
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/config"
	"github.com/Altiward/altiward/backend/internal/diagnose"
	"github.com/Altiward/altiward/backend/internal/export"
	"github.com/Altiward/altiward/backend/internal/monitor"
	"github.com/Altiward/altiward/backend/internal/retention"
	"github.com/Altiward/altiward/backend/internal/sso"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/integrations/sentinel"
	"github.com/Altiward/altiward/integrations/splunk"
	"github.com/Altiward/altiward/integrations/syslog"
)

// version is set at build time: -ldflags "-X main.version=0.1.0".
var version = "dev"

func main() {
	command := ""
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	switch command {
	case "", "serve":
		log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		if err := run(log); err != nil {
			log.Error("fatal", "err", err)
			os.Exit(1)
		}
	case "health":
		if err := health(); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
	case "diagnose":
		r := diagnose.Run(context.Background(), diagnose.Live(version))
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "drop-exports":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: altiward-api drop-exports SINK")
			os.Exit(2)
		}
		if err := dropExports(context.Background(), os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "replay-exports":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: altiward-api replay-exports SINK SINCE (a date, 2026-10-01, or a time, 2026-10-01T09:00:00Z)")
			os.Exit(2)
		}
		if err := replayExports(context.Background(), os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q: use health, diagnose, drop-exports, replay-exports or version, or nothing to run the server\n", command)
		os.Exit(2)
	}
}

// health asks the local server for /healthz, for container health checks: the image has
// no shell or curl.
func health() error {
	addr := os.Getenv("ALTIWARD_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/healthz answered %d", resp.StatusCode)
	}
	return nil
}

// dropExports removes the export queue of a sink taken out of the configuration, which
// diagnose reports as a problem. It refuses a sink that is still configured: that queue is
// owed to a SIEM that is still there. It connects without migrating.
func dropExports(ctx context.Context, sink string) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if slices.Contains(cfg.SinkNames(), sink) {
		return fmt.Errorf("%s is still configured; remove its settings first", sink)
	}
	if cfg.DatabaseURL == "" {
		return errors.New("ALTIWARD_DATABASE_URL is not set: nothing is queued in memory between runs")
	}
	p, err := store.ConnectPostgres(ctx, cfg.DatabaseURL, nil)
	if err != nil {
		return err
	}
	defer p.Close()
	n, err := p.DropExports(ctx, sink)
	if err != nil {
		return err
	}
	fmt.Printf("Dropped %d queued exports for %s. The events stay in the database.\n", n, sink)
	return nil
}

// replayExports queues for a sink what was received since a date: the events and console
// actions from before the sink was configured were never queued for it. It refuses a sink
// that isn't configured, since nothing would drain its queue. It connects without migrating.
func replayExports(ctx context.Context, sink, since string) error {
	from, err := parseSince(since)
	if err != nil {
		return err
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if !slices.Contains(cfg.SinkNames(), sink) {
		return fmt.Errorf("%s is not configured; set it up and restart the server first", sink)
	}
	if cfg.DatabaseURL == "" {
		return errors.New("ALTIWARD_DATABASE_URL is not set: there is nothing stored to replay")
	}
	p, err := store.ConnectPostgres(ctx, cfg.DatabaseURL, nil)
	if err != nil {
		return err
	}
	defer p.Close()
	n, err := p.ReplayExports(ctx, sink, from, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("Queued %d events and console actions since %s for %s. The server sends them next.\n",
		n, from.Format(time.RFC3339), sink)
	return nil
}

// parseSince reads a date (midnight UTC) or an RFC 3339 time.
func parseSince(s string) (time.Time, error) {
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("SINCE: want a date like 2026-10-01 or a time like 2026-10-01T09:00:00Z, got %q", s)
	}
	return t.UTC(), nil
}

func run(log *slog.Logger) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	tokens, err := auth.Parse(cfg.AgentTokens, cfg.ConsoleTokens)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var st store.Store
	if cfg.DatabaseURL == "" {
		log.Warn("ALTIWARD_DATABASE_URL not set: using the in-memory store; data is lost on exit")
		st = store.NewMemory(cfg.SinkNames())
	} else {
		pg, err := store.OpenPostgres(ctx, cfg.DatabaseURL, cfg.SinkNames())
		if err != nil {
			return err
		}
		st = pg
	}
	defer st.Close()

	// Shared by the SIEMs and the identity provider.
	httpClient := &http.Client{Timeout: 30 * time.Second}
	trusted, err := cfg.TrustedRoots()
	if err != nil {
		return err
	}
	if trusted != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: trusted, MinVersion: tls.VersionTLS12}
		httpClient.Transport = transport
	}
	var sinks []export.Sink
	if s := cfg.Splunk; s != nil {
		sinks = append(sinks, &export.SplunkSink{Client: &splunk.Client{URL: s.URL, Token: s.Token, HTTP: httpClient}, Index: s.Index})
	}
	if s := cfg.Sentinel; s != nil {
		var tokens sentinel.TokenSource = &sentinel.ClientCredentials{TenantID: s.TenantID, ClientID: s.ClientID, ClientSecret: s.ClientSecret, HTTP: httpClient}
		if s.Auth == config.SentinelManagedIdentity {
			tokens = &sentinel.ManagedIdentity{ClientID: s.ClientID} // its own client: IMDS mustn't go through a proxy
		}
		sinks = append(sinks, &export.SentinelSink{Client: &sentinel.Client{
			Endpoint: s.Endpoint, RuleID: s.RuleID, Stream: s.Stream, Tokens: tokens, HTTP: httpClient,
		}})
	}
	if s := cfg.Syslog; s != nil {
		client := &syslog.Client{Addr: s.Addr}
		if s.Framing == "newline" {
			client.Framing = syslog.Newline
		}
		if s.TLS {
			roots, err := s.Roots(trusted)
			if err != nil {
				return err
			}
			client.TLS = &tls.Config{RootCAs: roots}
		}
		sinks = append(sinks, &export.SyslogSink{Client: client, Format: export.SyslogFormat(s.Format)})
	}
	if len(sinks) > 0 {
		w := &export.Worker{Store: st, Sinks: sinks, BatchSize: 200, Lease: 2 * time.Minute, Log: log, Now: time.Now}
		go w.Run(ctx, cfg.ExportInterval)
	}

	silence := &monitor.Silence{Store: st, Log: log, Now: time.Now}
	go silence.Run(ctx, time.Minute)

	if days := cfg.AuditRetentionDays; days > 0 {
		purge := &retention.Audit{Store: st, After: time.Duration(days) * 24 * time.Hour, Log: log, Now: time.Now}
		go purge.Run(ctx, 24*time.Hour)
	}

	// Closed when shutdown starts, releasing requests held for agents' next commands.
	stopping := make(chan struct{})
	opts := []api.Option{
		api.WithVersion(version), api.WithSinks(cfg.SinkNames()), api.WithShutdown(stopping),
		api.WithUpdateCheck(cfg.UpdateCheck),
	}
	if o := cfg.OIDC; o != nil {
		tokens.BreakGlass()
		provider := sso.New(*o, httpClient, time.Now)
		opts = append(opts, api.WithSSO(provider, strings.HasPrefix(o.ConsoleURL, "https://")))
		log.Info("single sign-on", "issuer", o.Issuer, "redirect_url", provider.RedirectURL(), "tenant", o.Tenant,
			"break_glass_tokens", cfg.ConsoleTokens != "")
	}
	handler := api.New(st, tokens, log, time.Now, opts...)
	if cfg.ConsoleDir != "" {
		dist := os.DirFS(cfg.ConsoleDir)
		if err := api.CheckConsole(dist); err != nil {
			return fmt.Errorf("ALTIWARD_CONSOLE_DIR %s: %w", cfg.ConsoleDir, err)
		}
		handler = api.WithConsole(handler, dist, cfg.UpdateCheck)
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	srv.RegisterOnShutdown(func() { close(stopping) })
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("altiward-api listening", "version", version, "addr", cfg.ListenAddr, "sinks", cfg.SinkNames(), "postgres", cfg.DatabaseURL != "",
		"console", cfg.ConsoleDir, "update_check", cfg.UpdateCheck)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("stopped")
	return nil
}
