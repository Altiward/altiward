package api

// How long the server keeps history, and why. It is its own endpoint rather than a field
// of GET /v1/settings: the console's Settings page PUTs back what GET returned, so a
// field there that PUT does not accept would be refused.

import (
	"net/http"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
)

type retentionHistory struct {
	// Days is the period in force; 0 means nothing is removed.
	Days        int  `json:"days"`
	KeptForGood bool `json:"kept_for_good"`
	// Reason is default_siem, default_no_siem, set or kept_for_good.
	Reason string `json:"reason"`
	// HeldBefore is the SIEM coverage start while the default period holds back history
	// received before it; nil otherwise.
	HeldBefore *time.Time `json:"held_before"`
	// WaitingForBackfill is true until the admin group has been sent to the SIEM from
	// readings stored before the upgrade: expiry does not start before then.
	WaitingForBackfill bool `json:"waiting_for_backfill"`
}

func (s *Server) getRetention(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	settings, err := s.store.TenantSettings(r.Context(), p.TenantID)
	if err != nil {
		s.serverError(w, "get settings", err)
		return
	}
	days, reason := settings.History(len(s.sinks) > 0)
	h := retentionHistory{Days: days, KeptForGood: days == 0, Reason: reason}
	if reason == store.HistoryReasonDefaultSIEM {
		if h.HeldBefore, err = s.store.SinkCoverage(r.Context(), s.sinks); err != nil {
			s.serverError(w, "get sink coverage", err)
			return
		}
	}
	in, err := s.store.Installation(r.Context())
	if err != nil {
		s.serverError(w, "get installation", err)
		return
	}
	h.WaitingForBackfill = in.AdminGroupBackfilledAt == nil
	writeJSON(w, http.StatusOK, map[string]any{"history": h})
}
