package api

// Tenant settings, independent of any one device.

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
)

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	settings, err := s.store.TenantSettings(r.Context(), p.TenantID)
	if err != nil {
		s.serverError(w, "get settings", err)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	var settings store.TenantSettings
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&settings); err != nil {
		writeError(w, http.StatusBadRequest, "invalid settings: "+err.Error())
		return
	}
	if h := settings.SilentAfterHours; h != 0 && (h < store.MinSilentAfterHours || h > store.MaxSilentAfterHours) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("silent_after_hours must be between %d and %d, or 0 for the default",
			store.MinSilentAfterHours, store.MaxSilentAfterHours))
		return
	}
	previous, err := s.store.TenantSettings(r.Context(), p.TenantID)
	if err != nil {
		s.serverError(w, "get settings", err)
		return
	}
	a, err := s.auditEntry(p, store.AuditChangeSettings, "settings", map[string]any{"previous": previous, "settings": settings})
	if err != nil {
		s.serverError(w, "audit entry", err)
		return
	}
	if err := s.store.PutTenantSettings(r.Context(), p.TenantID, settings, a); err != nil {
		s.serverError(w, "put settings", err)
		return
	}
	s.log.Info("tenant settings changed", "tenant", p.TenantID, "reenrollment_requires_approval", settings.ReenrollmentRequiresApproval,
		"silent_after_hours", settings.SilentAfterHours)
	writeJSON(w, http.StatusOK, settings)
}
