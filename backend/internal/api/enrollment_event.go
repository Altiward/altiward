package api

// The agent.enrollment events the server raises when a key enrols, when a Mac rotates its
// key, and when a key that rotation replaced is used again.

import (
	"strings"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
)

// agentUserAgent is what the agent sends as its User-Agent, followed by its version.
const agentUserAgent = "altiward-agent/"

// enrollmentEvent reports a key that has just enrolled, as res says: its first key
// (enrolled), a new key waiting for approval (pending) or one that took the place of the
// active key without it (replaced).
//
// The ID names the credential, so the same enrolment is the same event. The Mac's own
// claims (hardware UUID, key storage, agent version) are the ones it made when it enrolled.
// What isn't known is left out, not sent empty.
func enrollmentEvent(tenantID string, res store.EnrollResult, userAgent string, now time.Time) event.Event {
	c := res.Credential
	state := event.EnrollmentStateEnrolled
	switch {
	case res.Replaced != "":
		state = event.EnrollmentStateReplaced
	case c.Status == store.CredentialPending:
		state = event.EnrollmentStatePending
	}
	detail := map[string]any{
		"state":           state,
		"device_id":       c.DeviceID,
		"key_fingerprint": c.KeyFingerprint(),
	}
	if c.KeyStorage != store.KeyStorageUnknown {
		detail["key_storage"] = string(c.KeyStorage)
	}
	if c.Token != "" {
		detail["token"] = c.Token
	}
	if prev := res.Previous; prev != nil {
		detail["previous_device_id"] = prev.DeviceID
		if prev.KeyStorage != store.KeyStorageUnknown {
			detail["previous_key_storage"] = string(prev.KeyStorage)
		}
		detail["hardware_uuid_matches"] = prev.HardwareUUID == c.HardwareUUID
	}
	return event.Event{
		SchemaVersion: event.SchemaVersion,
		EventID:       event.RaisedID(tenantID + "/enrollment/" + c.DeviceID),
		Type:          event.AgentEnrollment,
		Timestamp:     now.UTC(),
		Device:        event.Device{Serial: c.Serial, HardwareUUID: c.HardwareUUID, AgentVersion: agentVersion(userAgent)},
		Detail:        detail,
	}
}

// rotationEvent reports the rotation res made or found: the successor, made from the key
// in res.Previous. Its ID names the successor as an enrolment's names its key, so a retry
// raises the same event and it is stored once.
//
// It never carries a token: a rotation doesn't use one, and without one the Mac itself is
// the actor in OCSF. Both keys belong to one Mac, so the hardware UUIDs always match.
func rotationEvent(tenantID string, res store.RotateResult, userAgent string, now time.Time) event.Event {
	c, prev := res.Credential, res.Previous
	detail := map[string]any{
		"state":                 event.EnrollmentStateRotated,
		"device_id":             c.DeviceID,
		"key_fingerprint":       c.KeyFingerprint(),
		"previous_device_id":    prev.DeviceID,
		"hardware_uuid_matches": prev.HardwareUUID == c.HardwareUUID,
	}
	if c.KeyStorage != store.KeyStorageUnknown {
		detail["key_storage"] = string(c.KeyStorage)
	}
	if prev.KeyStorage != store.KeyStorageUnknown {
		detail["previous_key_storage"] = string(prev.KeyStorage)
	}
	return event.Event{
		SchemaVersion: event.SchemaVersion,
		EventID:       event.RaisedID(tenantID + "/enrollment/" + c.DeviceID),
		Type:          event.AgentEnrollment,
		Timestamp:     now.UTC(),
		Device:        event.Device{Serial: c.Serial, HardwareUUID: c.HardwareUUID, AgentVersion: agentVersion(userAgent)},
		Detail:        detail,
	}
}

// rotatedKeyUsedEvent reports the use of c.Stale, a key that rotation replaced, and the key
// the contest revoked, if any. The agent version is the stale request's.
//
// Its ID is random. One made from what the event reports could be worked out by the Mac,
// which could then send an event of its own with that ID first, and this one would be
// dropped as a duplicate. The store reports a stale key at most once a day instead.
func rotatedKeyUsedEvent(c store.ContestResult, userAgent string, now time.Time) event.Event {
	stale := c.Stale
	detail := map[string]any{
		"state":           event.EnrollmentStateRotatedKeyUsed,
		"device_id":       stale.DeviceID,
		"key_fingerprint": stale.KeyFingerprint(),
		"rotated_to":      stale.RotatedTo,
	}
	if c.Revoked != nil {
		detail["revoked_device_id"] = c.Revoked.DeviceID
	}
	// NewDeviceID reads crypto/rand, which doesn't fail: it would stop the program instead.
	id, _ := store.NewDeviceID()
	return event.Event{
		SchemaVersion: event.SchemaVersion,
		EventID:       id,
		Type:          event.AgentEnrollment,
		Timestamp:     now.UTC(),
		Device:        event.Device{Serial: stale.Serial, HardwareUUID: stale.HardwareUUID, AgentVersion: agentVersion(userAgent)},
		Detail:        detail,
	}
}

// agentVersion is the version in the agent's User-Agent, or "" for any other header. The
// caller writes the header, so only a plain version is taken.
func agentVersion(userAgent string) string {
	v, ok := strings.CutPrefix(userAgent, agentUserAgent)
	if !ok || v == "" || len(v) > event.MaxNameLength {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] >= 0x7f {
			return ""
		}
	}
	return v
}
