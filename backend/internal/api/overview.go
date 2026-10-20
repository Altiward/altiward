package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/report"
)

// overview answers "how are we doing" from the tenant's own sessions, devices and SIEM
// queues, for the period ?days names (30 by default).
func (s *Server) overview(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || !report.ValidDays(n) {
			writeError(w, http.StatusBadRequest, "days must be 7, 30 or 90")
			return
		}
		days = n
	}
	now := s.now()
	sessions, err := s.store.ReportSessions(r.Context(), p.TenantID, now.Add(-time.Duration(days)*24*time.Hour))
	if err != nil {
		s.serverError(w, "report sessions", err)
		return
	}
	devices, err := s.store.ListDevices(r.Context(), p.TenantID)
	if err != nil {
		s.serverError(w, "list devices", err)
		return
	}
	sinks, err := s.sinkStatus(r.Context(), p.TenantID)
	if err != nil {
		s.serverError(w, "export status", err)
		return
	}
	writeJSON(w, http.StatusOK, report.Build(report.Input{
		Now: now, Days: days, Sessions: sessions, Devices: devices, Sinks: sinks,
	}))
}
