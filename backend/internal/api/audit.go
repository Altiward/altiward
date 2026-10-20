package api

// The audit log of console actions.

import (
	"net/http"
	"strconv"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
)

// auditEntry starts the entry for a console action by p, at the server's clock.
func (s *Server) auditEntry(p auth.Principal, action, target string, detail map[string]any) (store.AuditEntry, error) {
	id, err := store.NewDeviceID() // a random UUID, as for device IDs
	if err != nil {
		return store.AuditEntry{}, err
	}
	return store.AuditEntry{
		ID: id, TenantID: p.TenantID, At: s.now(), Actor: p.Actor, Action: action, Target: target, Detail: detail,
	}, nil
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	q := r.URL.Query()
	var f store.AuditFilter
	var err error
	if f.Before, err = parseTime(q.Get("before")); err != nil {
		writeError(w, http.StatusBadRequest, "before: "+err.Error())
		return
	}
	if bs := q.Get("before_seq"); bs != "" {
		seq, err := strconv.ParseInt(bs, 10, 64)
		if err != nil || f.Before == nil {
			writeError(w, http.StatusBadRequest, "before_seq must be an integer, given with before")
			return
		}
		f.BeforeSeq = &seq
	}
	if l := q.Get("limit"); l != "" {
		if f.Limit, err = strconv.Atoi(l); err != nil || f.Limit < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
	}
	entries, err := s.store.ListAudit(r.Context(), p.TenantID, f)
	if err != nil {
		s.serverError(w, "list audit", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}
