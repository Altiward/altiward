// Package event defines the core event the Mac agent sends (docs/schema/event.schema.json)
// and validates it at the API boundary.
package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// SchemaVersion is the only version this backend accepts.
const SchemaVersion = 1

type Type string

const (
	ElevationGranted         Type = "elevation.granted"
	ElevationRevoked         Type = "elevation.revoked"
	ElevationExpiredEnforced Type = "elevation.expired_enforced"
	ElevationOverdue         Type = "elevation.overdue"
	AdminOutOfBand           Type = "admin.out_of_band"
	AdminOutOfBandRemoved    Type = "admin.out_of_band_removed"
	Activity                 Type = "activity"
	PersistenceDetected      Type = "persistence.detected"
	AgentHealth              Type = "agent.health"
	AgentTamper              Type = "agent.tamper"
	AgentSilent              Type = "agent.silent"
)

var knownTypes = map[Type]bool{
	ElevationGranted: true, ElevationRevoked: true, ElevationExpiredEnforced: true, ElevationOverdue: true,
	AdminOutOfBand: true, AdminOutOfBandRemoved: true, Activity: true, PersistenceDetected: true, AgentHealth: true,
	AgentTamper: true, AgentSilent: true,
}

// Silence states for agent.silent.
const (
	SilentStateSilent  = "silent"
	SilentStateResumed = "resumed"
)

// Event is one record from the agent. Field names and nullability follow the JSON schema.
type Event struct {
	SchemaVersion int            `json:"schema_version"`
	EventID       string         `json:"event_id"`
	Type          Type           `json:"type"`
	SessionID     *string        `json:"session_id"`
	Timestamp     time.Time      `json:"timestamp"`
	Device        Device         `json:"device"`
	User          *User          `json:"user"`
	Elevation     *Elevation     `json:"elevation"`
	Delayed       bool           `json:"delayed"`
	Detail        map[string]any `json:"detail"`
}

type Device struct {
	Serial            string  `json:"serial"`
	HardwareUUID      string  `json:"hardware_uuid"`
	OSVersion         string  `json:"os_version,omitempty"`
	AgentVersion      string  `json:"agent_version,omitempty"`
	PrivilegesVersion *string `json:"privileges_version"`
}

type User struct {
	LocalName string  `json:"local_name"`
	UPN       *string `json:"upn"`
}

type Source string

const (
	SourcePrivileges Source = "privileges"
	SourceOutOfBand  Source = "out_of_band"
)

type Elevation struct {
	Reason  *string    `json:"reason"`
	Expires *time.Time `json:"expires"`
	Source  Source     `json:"source"`
}

// IsSessionEvent reports whether events of this type belong to an elevation session.
func (t Type) IsSessionEvent() bool {
	switch t {
	case ElevationGranted, ElevationRevoked, ElevationExpiredEnforced, ElevationOverdue, AdminOutOfBand,
		AdminOutOfBandRemoved, Activity, PersistenceDetected:
		return true
	}
	return false
}

// IsServerRaised reports whether the backend raises events of this type itself. Agents may
// not send them, and they say nothing about when the Mac was last seen.
func (t Type) IsServerRaised() bool { return t == AgentSilent }

// DetailBool returns detail[key] when it is a JSON boolean.
func (e Event) DetailBool(key string) (value, ok bool) {
	v, ok := e.Detail[key].(bool)
	return v, ok
}

// Limits keep one misbehaving agent from bloating storage.
const (
	MaxReasonLength = 2048
	MaxNameLength   = 255
	MaxDetailBytes  = 64 << 10
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Decode parses one event strictly: unknown fields are an error, so schema drift
// between agent and backend is caught rather than silently dropped.
func Decode(raw []byte) (Event, error) {
	var e Event
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Event{}, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return Event{}, errors.New("decode: trailing data after event")
	}
	return e, nil
}

// PeekID extracts event_id from a payload that may not decode as a full event,
// so a rejection can still name the event it refers to.
func PeekID(raw []byte) string {
	var probe struct {
		EventID string `json:"event_id"`
	}
	_ = json.Unmarshal(raw, &probe)
	return probe.EventID
}

// Validate checks the rules the JSON schema expresses plus cross-field rules.
// now bounds how far in the future a device clock may claim to be.
func (e *Event) Validate(now time.Time) error {
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", e.SchemaVersion)
	}
	if !uuidPattern.MatchString(e.EventID) {
		return errors.New("event_id must be a lower-case UUID")
	}
	if !knownTypes[e.Type] {
		return fmt.Errorf("unknown type %q", e.Type)
	}
	if e.Timestamp.IsZero() {
		return errors.New("timestamp is required")
	}
	if e.Timestamp.After(now.Add(24 * time.Hour)) {
		return errors.New("timestamp is more than 24h in the future")
	}
	if e.Device.Serial == "" || e.Device.HardwareUUID == "" {
		return errors.New("device.serial and device.hardware_uuid are required")
	}
	if len(e.Device.Serial) > MaxNameLength || len(e.Device.HardwareUUID) > MaxNameLength {
		return errors.New("device identifiers too long")
	}
	if e.SessionID != nil && !uuidPattern.MatchString(*e.SessionID) {
		return errors.New("session_id must be a lower-case UUID")
	}
	if e.User != nil && (e.User.LocalName == "" || len(e.User.LocalName) > MaxNameLength) {
		return errors.New("user.local_name must be 1-255 bytes")
	}
	if e.Elevation != nil {
		if s := e.Elevation.Source; s != SourcePrivileges && s != SourceOutOfBand {
			return fmt.Errorf("unknown elevation.source %q", e.Elevation.Source)
		}
		if r := e.Elevation.Reason; r != nil && len(*r) > MaxReasonLength {
			return errors.New("elevation.reason too long")
		}
	}
	switch e.Type {
	case ElevationGranted, ElevationRevoked, ElevationExpiredEnforced, ElevationOverdue, AdminOutOfBand,
		AdminOutOfBandRemoved:
		if e.SessionID == nil || e.User == nil || e.Elevation == nil {
			return fmt.Errorf("%s requires session_id, user and elevation", e.Type)
		}
	case Activity:
		if e.SessionID == nil {
			return fmt.Errorf("%s requires session_id", e.Type)
		}
	case PersistenceDetected:
		if e.SessionID == nil || e.User == nil || e.Elevation == nil {
			return fmt.Errorf("%s requires session_id, user and elevation", e.Type)
		}
		if f, _ := e.Detail["findings"].([]any); len(f) == 0 {
			return fmt.Errorf("%s requires detail.findings", e.Type)
		}
	case AgentTamper:
		if c, _ := e.Detail["check"].(string); c == "" {
			return fmt.Errorf("%s requires detail.check", e.Type)
		}
	case AgentSilent:
		if st, _ := e.Detail["state"].(string); st != SilentStateSilent && st != SilentStateResumed {
			return fmt.Errorf("%s requires detail.state silent or resumed", e.Type)
		}
		if e.SessionID != nil || e.User != nil {
			return fmt.Errorf("%s has no session_id or user", e.Type)
		}
	}
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	if b, err := json.Marshal(e.Detail); err != nil || len(b) > MaxDetailBytes {
		return errors.New("detail is not serialisable or exceeds 64 KiB")
	}
	return nil
}
