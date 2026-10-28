package store

import (
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/session"
)

// snapshotWindow is how recently a Mac must have checked in to get a daily snapshot of its
// admin group.
const snapshotWindow = 24 * time.Hour

// deviceIdentity is the identity and versions an event raised for d carries.
func deviceIdentity(d session.Device) event.Device {
	return event.Device{
		Serial: d.Serial, HardwareUUID: d.HardwareUUID, OSVersion: d.OSVersion,
		AgentVersion: d.AgentVersion, PrivilegesVersion: d.PrivilegesVersion,
	}
}
