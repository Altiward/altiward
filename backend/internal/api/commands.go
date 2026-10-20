package api

// Remote commands: the console queues them, the agent polls and reports.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/command"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
)

// CommandView is a command plus its computed status.
type CommandView struct {
	command.Command
	Status command.Status `json:"status"`
}

func commandView(c command.Command, now time.Time) CommandView {
	return CommandView{Command: c, Status: c.Status(now)}
}

func (s *Server) newCommand(p auth.Principal, serial string, user, sessionID *string) (command.Command, error) {
	id, err := store.NewDeviceID()
	if err != nil {
		return command.Command{}, err
	}
	now := s.now()
	return command.Command{
		CommandID: id, TenantID: p.TenantID, Serial: serial, Type: command.TypeRevokeAdmin, User: user, SessionID: sessionID,
		IssuedBy: p.Actor, CreatedAt: now, ExpiresAt: now.Add(command.Lifetime),
	}, nil
}

// queue stores c with the audit entry for the console action that asked for it.
func (s *Server) queue(w http.ResponseWriter, r *http.Request, p auth.Principal, c command.Command, action, target string) {
	a, err := s.auditEntry(p, action, target, map[string]any{
		"command_id": c.CommandID, "serial": c.Serial, "user": c.User, "session_id": c.SessionID,
	})
	if err != nil {
		s.serverError(w, "audit entry", err)
		return
	}
	if err := s.store.CreateCommand(r.Context(), c, a); err != nil {
		s.serverError(w, "create command", err)
		return
	}
	s.log.Info("command queued", "tenant", c.TenantID, "serial", c.Serial, "command_id", c.CommandID, "type", c.Type)
	writeJSON(w, http.StatusCreated, commandView(c, s.now()))
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	ss, _, err := s.store.GetSession(r.Context(), p.TenantID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if err != nil {
		s.serverError(w, "get session", err)
		return
	}
	if !ss.Open() {
		writeError(w, http.StatusConflict, "session has already ended")
		return
	}
	permanent, err := s.permanentAdmins(r.Context(), p.TenantID, ss)
	if err != nil {
		s.serverError(w, "list devices", err)
		return
	}
	if isPermanentAdmin(permanent, ss) {
		writeError(w, http.StatusConflict, ss.LocalUser+" is a permanent admin on "+ss.DeviceSerial+", so Altiward doesn’t remove their rights")
		return
	}
	user, sessionID := ss.LocalUser, ss.SessionID
	c, err := s.newCommand(p, ss.DeviceSerial, &user, &sessionID)
	if err != nil {
		s.serverError(w, "new command", err)
		return
	}
	s.queue(w, r, p, c, store.AuditRevokeSession, sessionID)
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	var body struct {
		User *string `json:"user"`
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err == nil && len(raw) > 0 {
		err = json.Unmarshal(raw, &body)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, `body must be empty or {"user": "shortname"}`)
		return
	}
	if body.User != nil && (*body.User == "" || len(*body.User) > event.MaxNameLength) {
		writeError(w, http.StatusBadRequest, "user must be a local short name")
		return
	}
	serial := r.PathValue("serial")
	devices, err := s.store.ListDevices(r.Context(), p.TenantID)
	if err != nil {
		s.serverError(w, "list devices", err)
		return
	}
	known := false
	for _, d := range devices {
		known = known || d.Serial == serial
	}
	if !known {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	c, err := s.newCommand(p, serial, body.User, nil)
	if err != nil {
		s.serverError(w, "new command", err)
		return
	}
	s.queue(w, r, p, c, store.AuditRevokeDevice, serial)
}

func (s *Server) listCommands(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	f := store.CommandFilter{Serial: r.URL.Query().Get("serial"), Status: command.Status(r.URL.Query().Get("status"))}
	switch f.Status {
	case "", command.StatusPending, command.StatusCompleted, command.StatusFailed, command.StatusSkipped, command.StatusExpired:
	default:
		writeError(w, http.StatusBadRequest, "status must be pending, completed, failed, skipped or expired")
		return
	}
	now := s.now()
	cs, err := s.store.ListCommands(r.Context(), p.TenantID, f, now)
	if err != nil {
		s.serverError(w, "list commands", err)
		return
	}
	views := make([]CommandView, 0, len(cs))
	for _, c := range cs {
		views = append(views, commandView(c, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"commands": views})
}

func (s *Server) getCommand(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	c, err := s.store.GetCommand(r.Context(), p.TenantID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "command not found")
		return
	}
	if err != nil {
		s.serverError(w, "get command", err)
		return
	}
	writeJSON(w, http.StatusOK, commandView(c, s.now()))
}

// MaxCommandWait caps how long GET /v1/agent/commands?wait= holds a request: under the
// 60-second idle timeout common to load balancers and the server's WriteTimeout.
const MaxCommandWait = 50

// agentCommands returns the Mac's pending commands. With ?wait=N it holds the request for
// up to N seconds until one is queued, so a revoke lands within about a second;
// without it, it answers at once.
func (s *Server) agentCommands(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	wait := 0
	if v := r.URL.Query().Get("wait"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > MaxCommandWait {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("wait must be whole seconds from 0 to %d", MaxCommandWait))
			return
		}
		wait = n
	}
	var deadline <-chan time.Time
	if wait > 0 {
		t := time.NewTimer(time.Duration(wait) * time.Second)
		defer t.Stop()
		deadline = t.C
	}
	for {
		// Watch before reading, so a command queued in between still wakes us.
		woken, stop := s.store.WatchCommands(p.TenantID, p.Serial)
		cs, err := s.store.PendingCommands(r.Context(), p.TenantID, p.Serial, s.now())
		if err != nil {
			stop()
			s.log.Error("pending commands", "tenant", p.TenantID, "serial", p.Serial, "err", err)
			writeError(w, http.StatusServiceUnavailable, "could not load commands; retry later")
			return
		}
		if len(cs) > 0 || deadline == nil {
			stop()
			writeJSON(w, http.StatusOK, command.AgentList(cs))
			return
		}
		select {
		case <-woken:
			continue
		case <-deadline:
		case <-s.stopping:
		case <-r.Context().Done():
		}
		stop()
		writeJSON(w, http.StatusOK, command.AgentList(nil))
		return
	}
}

func (s *Server) agentCommandResult(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	result, err := command.DecodeResult(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c, err := s.store.RecordCommandResult(r.Context(), p.TenantID, p.Serial, r.PathValue("id"), result, s.now())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such command for this device")
		return
	}
	if err != nil {
		s.log.Error("record command result", "tenant", p.TenantID, "serial", p.Serial, "err", err)
		writeError(w, http.StatusServiceUnavailable, "could not store result; retry later")
		return
	}
	s.log.Info("command result", "tenant", p.TenantID, "serial", p.Serial, "command_id", c.CommandID, "status", c.Result.Status)
	writeJSON(w, http.StatusOK, map[string]any{"status": c.Status(s.now())})
}
