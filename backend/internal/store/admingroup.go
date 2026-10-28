package store

import (
	"iter"
	"time"

	"github.com/Altiward/altiward/backend/internal/admingroup"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/session"
)

// snapshotWindow is how recently a Mac must have checked in to get a daily snapshot of its
// admin group.
const snapshotWindow = 24 * time.Hour

// BackfillHold is how long what the backfill stores waits before it is due for the SIEM:
// longer than an update, so an older revision that doesn't know agent.admin_group can't
// claim it and mark it sent unsent.
const BackfillHold = time.Hour

// deviceIdentity is the identity and versions an event raised for d carries.
func deviceIdentity(d session.Device) event.Device {
	return event.Device{
		Serial: d.Serial, HardwareUUID: d.HardwareUUID, OSVersion: d.OSVersion,
		AgentVersion: d.AgentVersion, PrivilegesVersion: d.PrivilegesVersion,
	}
}

// backfillMac walks one Mac's health readings, oldest first, as ingest would have: the group
// last reported starts as nothing and follows each reading (raiseAdminGroup in either
// store). It holds only the reading in hand and the group before it, so readings can come
// from the database a page at a time; an error from readings stops the walk. keep stores
// what a reading raises, at the time the reading was received, and reports whether the
// event is now recorded (false: its ID belongs to another event, so the group last
// reported stays as it was) and whether it stored it just now. An event that doesn't
// validate is left out, as ingest leaves it. It returns how many were stored.
func backfillMac(readings iter.Seq2[StoredEvent, error], tenantID string, secret []byte,
	keep func(raised event.Event, at time.Time) (recorded, stored bool, err error)) (int, error) {
	var prev *admingroup.Report
	stored := 0
	for r, err := range readings {
		if err != nil {
			return stored, err
		}
		raised, next, ok := admingroup.OnHealth(prev, r.Event, tenantID, secret, r.ReceivedAt)
		if !ok {
			refreshed := admingroup.Refreshed(*prev, r.Event)
			prev = &refreshed
			continue
		}
		if raised.Validate(r.ReceivedAt) != nil {
			continue
		}
		recorded, isNew, err := keep(raised, r.ReceivedAt)
		if err != nil {
			return stored, err
		}
		if !recorded {
			continue
		}
		if isNew {
			stored++
		}
		prev = &next
	}
	return stored, nil
}
