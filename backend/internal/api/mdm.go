package api

import (
	"net/http"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/mdm"
	"github.com/Altiward/altiward/backend/internal/store"
)

// The Intune connection as the console shows it: the sync, and the copy of the Macs Intune
// manages. Viewers see each Mac's serial, name, primary user and last check-in, never the
// IDs that identify it to Intune and Entra ID.

// WithMDM connects the server to Intune through c. Without it, Intune is off.
func WithMDM(c *mdm.Checker) Option { return func(s *Server) { s.mdm = c } }

type mdmStatus struct {
	Configured    bool       `json:"configured"`
	Source        string     `json:"source"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastErrorAt   *time.Time `json:"last_error_at,omitempty"`
	LastError     string     `json:"last_error"`
	Devices       int        `json:"devices"`
	SilenceHeldAt *time.Time `json:"silence_held_at,omitempty"`
	SilenceHeld   int        `json:"silence_held"`
	// Checks counts the keys in use by the outcome of their Intune check; a key never
	// checked isn't counted.
	Checks map[store.MDMCheck]int `json:"checks"`
}

type mdmDevice struct {
	Serial      string     `json:"serial"`
	PrimaryUPN  string     `json:"primary_upn"`
	Name        string     `json:"name"`
	LastCheckIn *time.Time `json:"last_check_in,omitempty"`
}

// mdmFor is the connection the caller's tenant has, or nil. Intune serves one tenant.
func (s *Server) mdmFor(p auth.Principal) *mdm.Checker {
	if s.mdm == nil || s.mdm.TenantID != p.TenantID {
		return nil
	}
	return s.mdm
}

func (s *Server) getMDMStatus(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	c := s.mdmFor(p)
	if c == nil {
		writeJSON(w, http.StatusOK, map[string]bool{"configured": false})
		return
	}
	st, err := c.Store.MDMSyncStatus(r.Context(), c.TenantID, store.MDMIntune)
	if err != nil {
		s.serverError(w, "Intune sync status", err)
		return
	}
	checks, err := s.store.MDMCheckCounts(r.Context(), c.TenantID)
	if err != nil {
		s.serverError(w, "Intune check counts", err)
		return
	}
	delete(checks, store.MDMNotChecked)
	writeJSON(w, http.StatusOK, mdmStatus{
		Configured: true, Source: store.MDMIntune, LastSuccessAt: st.LastSuccessAt, LastErrorAt: st.LastErrorAt,
		LastError: st.LastError, Devices: st.Devices, SilenceHeldAt: st.SilenceHeldAt, SilenceHeld: st.SilenceHeld,
		Checks: checks,
	})
}

func (s *Server) listMDMDevices(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	out := []mdmDevice{}
	if c := s.mdmFor(p); c != nil {
		devices, err := c.Store.MDMDevices(r.Context(), c.TenantID, store.MDMIntune)
		if err != nil {
			s.serverError(w, "Intune devices", err)
			return
		}
		for _, d := range devices {
			m := mdmDevice{Serial: d.Serial, PrimaryUPN: d.PrimaryUPN, Name: d.Name}
			if !d.LastCheckIn.IsZero() {
				m.LastCheckIn = &d.LastCheckIn
			}
			out = append(out, m)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}
