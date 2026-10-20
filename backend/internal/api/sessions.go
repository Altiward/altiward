package api

// Elevation sessions and their event timelines.

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/session"
	"github.com/Altiward/altiward/backend/internal/store"
)

// SessionView is a session plus derived fields the console shows.
type SessionView struct {
	session.Session
	Open           bool     `json:"open"`
	AllowedSeconds *float64 `json:"allowed_seconds"`
	ActualSeconds  *float64 `json:"actual_seconds"`
	Overran        bool     `json:"overran"`
	// PermanentAdmin: the Mac's agent never demotes or revokes this user, as of its last
	// heartbeat, so the console offers no revoke.
	PermanentAdmin bool `json:"permanent_admin"`
}

func view(s session.Session, now time.Time) SessionView {
	v := SessionView{Session: s, Open: s.Open()}
	if d := s.AllowedDuration(); d != nil {
		v.AllowedSeconds = seconds(*d)
	}
	if d := s.ActualDuration(now); d != nil {
		v.ActualSeconds = seconds(*d)
	}
	if v.AllowedSeconds != nil && v.ActualSeconds != nil {
		v.Overran = *v.ActualSeconds > *v.AllowedSeconds
	}
	return v
}

// permanentAdmins lists, by serial, the users each Mac's agent never demotes or revokes,
// as its last heartbeat reported them. Devices are read only when one of sessions is
// open, since only an open session can be revoked.
func (s *Server) permanentAdmins(ctx context.Context, tenantID string, sessions ...session.Session) (map[string][]string, error) {
	if !slices.ContainsFunc(sessions, session.Session.Open) {
		return nil, nil
	}
	devices, err := s.store.ListDevices(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(devices))
	for _, d := range devices {
		out[d.Serial] = d.PermanentAdmins
	}
	return out, nil
}

func isPermanentAdmin(permanent map[string][]string, ss session.Session) bool {
	return slices.Contains(permanent[ss.DeviceSerial], ss.LocalUser)
}

func seconds(d time.Duration) *float64 {
	s := d.Seconds()
	return &s
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	q := r.URL.Query()
	f := store.SessionFilter{
		DeviceSerial: q.Get("device"),
		LocalUser:    q.Get("user"),
		OpenOnly:     q.Get("open") == "true",
	}
	var err error
	if f.Since, err = parseTime(q.Get("since")); err != nil {
		writeError(w, http.StatusBadRequest, "since: "+err.Error())
		return
	}
	if f.Until, err = parseTime(q.Get("until")); err != nil {
		writeError(w, http.StatusBadRequest, "until: "+err.Error())
		return
	}
	if l := q.Get("limit"); l != "" {
		if f.Limit, err = strconv.Atoi(l); err != nil || f.Limit < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
	}
	sessions, err := s.store.ListSessions(r.Context(), p.TenantID, f)
	if err != nil {
		s.serverError(w, "list sessions", err)
		return
	}
	permanent, err := s.permanentAdmins(r.Context(), p.TenantID, sessions...)
	if err != nil {
		s.serverError(w, "list devices", err)
		return
	}
	now := s.now()
	views := make([]SessionView, 0, len(sessions))
	for _, ss := range sessions {
		v := view(ss, now)
		v.PermanentAdmin = isPermanentAdmin(permanent, ss)
		views = append(views, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": views})
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	ss, events, err := s.store.GetSession(r.Context(), p.TenantID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if err != nil {
		s.serverError(w, "get session", err)
		return
	}
	permanent, err := s.permanentAdmins(r.Context(), p.TenantID, ss)
	if err != nil {
		s.serverError(w, "list devices", err)
		return
	}
	v := view(ss, s.now())
	v.PermanentAdmin = isPermanentAdmin(permanent, ss)
	writeJSON(w, http.StatusOK, map[string]any{"session": v, "events": events})
}
