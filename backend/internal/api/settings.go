package api

// Tenant settings, independent of any one device.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid settings: "+err.Error())
		return
	}
	settings := store.DefaultTenantSettings()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&settings); err != nil {
		writeError(w, http.StatusBadRequest, "invalid settings: "+err.Error())
		return
	}
	// Whether the body names history_days and require_intune_match at all: one that leaves
	// either out (a console tab loaded before the setting existed, a script that only toggles
	// approval) keeps the stored value instead of resetting it, which could otherwise start
	// removing history, or stop holding keys that don't match Intune.
	var named struct {
		HistoryDays        *int  `json:"history_days"`
		RequireIntuneMatch *bool `json:"require_intune_match"`
	}
	if err := json.Unmarshal(body, &named); err != nil {
		writeError(w, http.StatusBadRequest, "invalid settings: "+err.Error())
		return
	}
	if d := settings.HistoryDays; named.HistoryDays != nil && d != 0 && d != store.HistoryKeptForGood &&
		(d < store.MinHistoryDays || d > store.MaxHistoryDays) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"history_days must be 0 for the default, %d to keep history for good, or between %d and %d",
			store.HistoryKeptForGood, store.MinHistoryDays, store.MaxHistoryDays))
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
	if named.HistoryDays == nil {
		settings.HistoryDays = previous.HistoryDays
	}
	if named.RequireIntuneMatch == nil {
		settings.RequireIntuneMatch = previous.RequireIntuneMatch
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
		"new_mac_requires_approval", settings.NewMacRequiresApproval, "silent_after_hours", settings.SilentAfterHours,
		"history_days", settings.HistoryDays, "require_intune_match", settings.RequireIntuneMatch)
	writeJSON(w, http.StatusOK, settings)
}
