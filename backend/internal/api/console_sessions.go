package api

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
)

// Who is signed in to the console, for an admin to end a sign-in without waiting for it
// to expire, for example after removing someone from a group at the identity provider,
// which otherwise applies only at their next sign-in. A session is named by the hex of its
// stored hash, never by its cookie token: the hash can end it but can't sign in.

type consoleSessionView struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	EndsAt    time.Time `json:"ends_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Current   bool      `json:"current"` // the session making this request
}

func (s *Server) listConsoleSessions(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	sessions, err := s.store.ListConsoleSessions(r.Context(), p.TenantID, s.now())
	if err != nil {
		s.serverError(w, "list console sessions", err)
		return
	}
	var own []byte
	if !auth.HasBearer(r) && s.sso != nil {
		if sess, ok := s.session(r); ok {
			own = sess.TokenHash
		}
	}
	out := []consoleSessionView{}
	for _, c := range sessions {
		out = append(out, consoleSessionView{
			ID: hex.EncodeToString(c.TokenHash), Actor: c.Actor, Name: c.Name, Role: c.Role,
			CreatedAt: c.CreatedAt, EndsAt: c.EndsAt, ExpiresAt: c.ExpiresAt, Current: own != nil && bytes.Equal(own, c.TokenHash),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) endConsoleSession(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	hash, err := hex.DecodeString(r.PathValue("id"))
	if err != nil || len(hash) == 0 {
		writeError(w, http.StatusNotFound, "no such console session")
		return
	}
	sessions, err := s.store.ListConsoleSessions(r.Context(), p.TenantID, s.now())
	if err != nil {
		s.serverError(w, "list console sessions", err)
		return
	}
	var target *store.ConsoleSession
	for i := range sessions {
		if bytes.Equal(sessions[i].TokenHash, hash) {
			target = &sessions[i]
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "no such console session")
		return
	}
	a, err := s.auditEntry(p, store.AuditEndConsoleSession, target.Actor, map[string]any{"name": target.Name, "role": target.Role})
	if err != nil {
		s.serverError(w, "audit entry", err)
		return
	}
	switch err := s.store.EndConsoleSession(r.Context(), p.TenantID, hash, a); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such console session")
		return
	case err != nil:
		s.serverError(w, "end console session", err)
		return
	}
	s.log.Info("console session ended by an admin", "tenant", p.TenantID, "actor", p.Actor, "ended", target.Actor)
	w.WriteHeader(http.StatusNoContent)
}
