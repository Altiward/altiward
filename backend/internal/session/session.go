// Package session folds events into elevation sessions and device records.
//
// Both reducers are pure and tolerate out-of-order delivery, so every store
// implementation shares them and stays consistent.
package session

import (
	"slices"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
)

// Flags raised on a session; the console and detection rules key off them.
const (
	FlagUnverifiedClaim     = "unverified_claim"     // hook claim contradicted the admin group
	FlagOrphanRevoke        = "orphan_revoke"        // revoke with no grant seen on the device
	FlagOutOfBand           = "out_of_band"          // admin rights nothing granted
	FlagInferredEnd         = "inferred_end"         // closed by the heartbeat, not the hook
	FlagPersistenceDetected = "persistence_detected" // new persistence seen during the window
	FlagOverdue             = "overdue"              // rights outlived their expiry plus grace
)

// End reasons.
const (
	EndRevoked         = "revoked"
	EndInferred        = "inferred"
	EndExpiredEnforced = "expired_enforced"
	EndRemoteRevoke    = "remote_revoke"   // console revoke executed by the agent
	EndPermanentAdmin  = "permanent_admin" // found without a grant, then made a permanent admin; rights kept
)

// Session is one elevation window, from grant (or first observation) to revoke.
type Session struct {
	TenantID     string       `json:"tenant_id"`
	SessionID    string       `json:"session_id"`
	DeviceSerial string       `json:"device_serial"`
	HardwareUUID string       `json:"hardware_uuid"`
	LocalUser    string       `json:"local_user"`
	UPN          *string      `json:"upn"`
	Source       event.Source `json:"source"`
	Reason       *string      `json:"reason"`
	StartedAt    *time.Time   `json:"started_at"`
	ExpiresAt    *time.Time   `json:"expires_at"`
	EndedAt      *time.Time   `json:"ended_at"`
	EndReason    *string      `json:"end_reason"`
	Renewals     int          `json:"renewals"`
	Verified     bool         `json:"verified"`
	Flags        []string     `json:"flags"`
	EventCount   int          `json:"event_count"`
	LastEventAt  time.Time    `json:"last_event_at"`
	// ExpirySetAt and ExpirySetBy name the grant ExpiresAt came from: the newest, by
	// timestamp then event ID. Each grant carries the expiry the agent enforces from then
	// on, which a renewal can shorten as well as extend.
	ExpirySetAt *time.Time `json:"expiry_set_at,omitempty"`
	ExpirySetBy string     `json:"expiry_set_by,omitempty"`
}

// New starts an empty session; Apply fills it in.
func New(tenantID, sessionID string) Session {
	return Session{TenantID: tenantID, SessionID: sessionID, Verified: true, Flags: []string{}}
}

// Open reports whether no end has been seen yet.
func (s Session) Open() bool { return s.EndedAt == nil }

// AllowedDuration is the window Privileges granted, when an expiry is known.
func (s Session) AllowedDuration() *time.Duration {
	if s.StartedAt == nil || s.ExpiresAt == nil {
		return nil
	}
	d := s.ExpiresAt.Sub(*s.StartedAt)
	return &d
}

// ActualDuration is how long rights were held, up to now for open sessions.
func (s Session) ActualDuration(now time.Time) *time.Duration {
	if s.StartedAt == nil {
		return nil
	}
	end := now
	if s.EndedAt != nil {
		end = *s.EndedAt
	}
	d := end.Sub(*s.StartedAt)
	return &d
}

// Apply folds one event into the session.
func (s *Session) Apply(e event.Event) {
	s.EventCount++
	if e.Timestamp.After(s.LastEventAt) {
		s.LastEventAt = e.Timestamp
	}
	if s.DeviceSerial == "" {
		s.DeviceSerial = e.Device.Serial
		s.HardwareUUID = e.Device.HardwareUUID
	}
	if e.User != nil {
		if s.LocalUser == "" {
			s.LocalUser = e.User.LocalName
		}
		if e.User.UPN != nil {
			s.UPN = e.User.UPN
		}
	}
	if e.Elevation != nil && s.Source == "" {
		s.Source = e.Elevation.Source
	}
	if verified, ok := e.DetailBool("verified"); ok && !verified {
		s.Verified = false
		s.flag(FlagUnverifiedClaim)
	}

	switch e.Type {
	case event.ElevationGranted:
		s.start(e.Timestamp)
		if renewed, _ := e.DetailBool("renewed"); renewed {
			s.Renewals++
		}
		if e.Elevation != nil {
			if s.Reason == nil && e.Elevation.Reason != nil {
				s.Reason = e.Elevation.Reason
			}
			if s.ExpirySetAt == nil || e.Timestamp.After(*s.ExpirySetAt) ||
				e.Timestamp.Equal(*s.ExpirySetAt) && e.EventID > s.ExpirySetBy {
				t := e.Timestamp
				s.ExpiresAt, s.ExpirySetAt, s.ExpirySetBy = e.Elevation.Expires, &t, e.EventID
			}
		}
	case event.AdminOutOfBand:
		s.Source = event.SourceOutOfBand
		s.start(e.Timestamp)
		s.flag(FlagOutOfBand)
	case event.ElevationRevoked:
		reason := EndRevoked
		switch trigger, _ := e.Detail["trigger"].(string); trigger {
		case "command":
			reason = EndRemoteRevoke
		case "permanent_admin":
			reason = EndPermanentAdmin
		}
		if inferred, _ := e.DetailBool("inferred"); inferred {
			reason = EndInferred
			s.flag(FlagInferredEnd)
		}
		if orphan, _ := e.DetailBool("orphan"); orphan {
			s.flag(FlagOrphanRevoke)
		}
		s.end(e.Timestamp, reason)
	case event.ElevationExpiredEnforced:
		s.end(e.Timestamp, EndExpiredEnforced)
	case event.ElevationOverdue:
		s.flag(FlagOverdue)
	case event.PersistenceDetected:
		s.flag(FlagPersistenceDetected)
	}
}

func (s *Session) start(t time.Time) {
	if s.StartedAt == nil || t.Before(*s.StartedAt) {
		s.StartedAt = &t
	}
}

// end keeps the earliest end; an enforced expiry outranks a plain revoke at the same instant.
func (s *Session) end(t time.Time, reason string) {
	if s.EndedAt == nil || t.Before(*s.EndedAt) || (t.Equal(*s.EndedAt) && reason == EndExpiredEnforced) {
		s.EndedAt = &t
		s.EndReason = &reason
	}
}

func (s *Session) flag(f string) {
	if !slices.Contains(s.Flags, f) {
		s.Flags = append(s.Flags, f)
		slices.Sort(s.Flags)
	}
}
