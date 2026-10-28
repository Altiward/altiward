package store

import (
	"time"

	"github.com/Altiward/altiward/backend/internal/session"
)

// Device is a Mac as the store holds it: what its reports built (session.Device) and
// whether an admin has retired it. Retirement isn't something the Mac reported, so it sits
// beside the reduced state, never in it. Embedding keeps the API's JSON flat.
type Device struct {
	session.Device
	// RetiredAt is when an admin revoked the Mac's last key, or nil while it is in Fleet.
	// Any new key for the Mac clears it.
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}
