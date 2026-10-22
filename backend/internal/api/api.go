// Package api serves the agent ingestion endpoint and the read API behind the console.
// Console endpoints need a console role: a console token is an admin; a person
// signed in through single sign-on has the role their groups give them.
//
//	POST /v1/agent/enroll               enrollment token  register a device key
//	POST /v1/agent/events               device signature  ingest a batch; per-event verdicts
//	GET  /v1/sessions                   viewer            list elevation sessions
//	GET  /v1/sessions/{id}              viewer            one session and its event timeline
//	GET  /v1/devices                    viewer            fleet inventory and current admins
//	GET  /v1/overview?days=7|30|90      viewer            the overview: admins now, the period's elevations, health
//	GET  /v1/enrollments                viewer            device credentials
//	POST /v1/enrollments/{id}/approve   admin             activate a pending re-enrollment
//	POST /v1/enrollments/{id}/revoke    admin             revoke a device credential
//	GET  /v1/settings                   viewer            tenant settings
//	PUT  /v1/settings                   admin             change them
//	GET  /v1/console-sessions           admin             who is signed in to the console
//	DELETE /v1/console-sessions/{id}    admin             end one of those sign-ins
//	POST /v1/sessions/{id}/revoke       operator          revoke one session
//	POST /v1/devices/{serial}/revoke    operator          revoke a Mac's admins
//	GET  /v1/commands, /v1/commands/{id} viewer           commands and their results
//	GET  /v1/audit                      viewer            console actions, newest first
//	GET  /v1/about                      viewer            the server's version, the oldest agent it accepts, tamper severities,
//	                                                      whether the console may check GitHub for newer releases and
//	                                                      the platform it runs on
//	/v1/auth/*                          see auth.go   console sign-in
//	GET  /v1/agent/commands             device signature  this Mac's pending commands
//	POST /v1/agent/commands/{id}/result device signature  report a command's result
//	GET  /healthz                       none              liveness
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/ocsf"
	"github.com/Altiward/altiward/backend/internal/release"
	"github.com/Altiward/altiward/backend/internal/sso"
	"github.com/Altiward/altiward/backend/internal/store"
)

const (
	MaxBatchEvents = 500
	MaxBodyBytes   = 8 << 20
)

type Server struct {
	store   store.Store
	tokens  *auth.Tokens
	log     *slog.Logger
	now     func() time.Time
	version string
	// Whether the console's browser may ask GitHub for newer releases (ALTIWARD_UPDATE_CHECK).
	updateCheck bool
	// Where it runs, when that changes how to upgrade: "azure-container-apps", and the app's name.
	platform, app string
	sinks         []string // the configured SIEM export sinks

	sso           *sso.Provider // nil: console tokens only
	secureCookies bool
	stopping      <-chan struct{} // closed when the server starts shutting down
}

// Option configures New.
type Option func(*Server)

// WithShutdown releases requests held for an agent's next command when stopping closes,
// so they don't delay a graceful shutdown. Close it from http.Server.RegisterOnShutdown.
func WithShutdown(stopping <-chan struct{}) Option { return func(s *Server) { s.stopping = stopping } }

// WithVersion sets the version GET /v1/about reports; "dev" without it.
func WithVersion(v string) Option { return func(s *Server) { s.version = v } }

// WithUpdateCheck sets whether GET /v1/about lets the console check GitHub for newer
// releases; on without it. Pass the same value to WithConsole, whose CSP allows the check.
func WithUpdateCheck(on bool) Option { return func(s *Server) { s.updateCheck = on } }

// WithAzureContainerApp says the server runs as the named Azure container app, so GET
// /v1/about tells the console to show how to upgrade one.
func WithAzureContainerApp(name string) Option {
	return func(s *Server) { s.platform, s.app = "azure-container-apps", name }
}

func New(s store.Store, tokens *auth.Tokens, log *slog.Logger, now func() time.Time, opts ...Option) http.Handler {
	srv := &Server{store: s, tokens: tokens, log: log, now: now, version: "dev", updateCheck: true}
	for _, o := range opts {
		o(srv)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("POST /v1/agent/enroll", srv.require(auth.RoleAgent, srv.enroll))
	mux.Handle("POST /v1/agent/events", srv.requireDevice(srv.ingest))
	mux.Handle("GET /v1/sessions", srv.console(auth.Viewer, srv.listSessions))
	mux.Handle("GET /v1/sessions/{id}", srv.console(auth.Viewer, srv.getSession))
	mux.Handle("GET /v1/devices", srv.console(auth.Viewer, srv.listDevices))
	mux.Handle("GET /v1/overview", srv.console(auth.Viewer, srv.overview))
	mux.Handle("GET /v1/enrollments", srv.console(auth.Viewer, srv.listEnrollments))
	mux.Handle("POST /v1/enrollments/{id}/approve", srv.console(auth.Admin, srv.approveEnrollment))
	mux.Handle("POST /v1/enrollments/{id}/revoke", srv.console(auth.Admin, srv.revokeEnrollment))
	mux.Handle("GET /v1/settings", srv.console(auth.Viewer, srv.getSettings))
	mux.Handle("PUT /v1/settings", srv.console(auth.Admin, srv.putSettings))
	mux.Handle("POST /v1/sessions/{id}/revoke", srv.console(auth.Operator, srv.revokeSession))
	mux.Handle("POST /v1/devices/{serial}/revoke", srv.console(auth.Operator, srv.revokeDevice))
	mux.Handle("GET /v1/commands", srv.console(auth.Viewer, srv.listCommands))
	mux.Handle("GET /v1/commands/{id}", srv.console(auth.Viewer, srv.getCommand))
	mux.Handle("GET /v1/audit", srv.console(auth.Viewer, srv.listAudit))
	mux.Handle("GET /v1/exports", srv.console(auth.Viewer, srv.listExports))
	mux.Handle("POST /v1/exports/test", srv.console(auth.Admin, srv.testExport))
	mux.Handle("POST /v1/exports/{sink}/retry", srv.console(auth.Admin, srv.retryExports))
	mux.Handle("GET /v1/console-sessions", srv.console(auth.Admin, srv.listConsoleSessions))
	mux.Handle("DELETE /v1/console-sessions/{id}", srv.console(auth.Admin, srv.endConsoleSession))
	mux.Handle("GET /v1/about", srv.console(auth.Viewer, srv.about))
	mux.HandleFunc("GET /v1/auth/config", srv.authConfig)
	mux.HandleFunc("GET /v1/auth/login", srv.login)
	mux.HandleFunc("GET /v1/auth/callback", srv.callback)
	mux.HandleFunc("GET /v1/auth/me", srv.me)
	mux.HandleFunc("POST /v1/auth/logout", srv.logout)
	mux.Handle("GET /v1/agent/commands", srv.requireDevice(srv.agentCommands))
	mux.Handle("POST /v1/agent/commands/{id}/result", srv.requireDevice(srv.agentCommandResult))
	return mux
}

type handler func(w http.ResponseWriter, r *http.Request, p auth.Principal)

func (s *Server) require(role auth.Role, h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.tokens.Authenticate(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		if p.Role != role {
			writeError(w, http.StatusForbidden, "token not valid for this endpoint")
			return
		}
		h(w, r, p)
	})
}

func (s *Server) about(w http.ResponseWriter, _ *http.Request, _ auth.Principal) {
	about := map[string]any{
		"version": s.version, "oldest_supported_agent": release.OldestSupportedAgent,
		"tamper_severities": ocsf.TamperSeverities(), "update_check": s.updateCheck,
	}
	if s.platform != "" {
		about["platform"], about["app"] = s.platform, s.app
	}
	writeJSON(w, http.StatusOK, about)
}

func parseTime(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil, errors.New("must be RFC 3339")
	}
	return &t, nil
}

func (s *Server) serverError(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeCodedError adds a machine-readable code the agent acts on.
func writeCodedError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": msg, "code": code})
}
