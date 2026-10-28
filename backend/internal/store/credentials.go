package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
)

// Device credentials and tenant settings.

var (
	ErrConflict     = errors.New("conflict")
	ErrInvalidState = errors.New("invalid state for this operation")
	// ErrRateLimited is an enrolment refused for a limit in EnrollLimits. The two errors
	// below say which, and both match it with errors.Is.
	ErrRateLimited       = errors.New("enrolment rate limited")
	ErrNewMacsLimited    = fmt.Errorf("%w: too many new Macs in the last hour", ErrRateLimited)
	ErrKeysPerMacLimited = fmt.Errorf("%w: too many keys for this Mac in the last 24 hours", ErrRateLimited)

	// Rotate's refusals. A rotation from a pending key is ErrInvalidState, and from an
	// unknown one ErrNotFound.
	ErrRotationNotAllowed = errors.New("a Secure Enclave key is not rotated")
	ErrRotationTooSoon    = errors.New("key rotated too recently")
	ErrKeyInUse           = errors.New("key already enrolled")
	ErrRotatedElsewhere   = errors.New("key already rotated to another key")
	ErrRevoked            = errors.New("key revoked")
	// ErrRotated refuses to revoke a key that was rotated while its lineage still has an
	// active key: revoke that one (LineageActive names it).
	ErrRotated = errors.New("key rotated; its lineage has an active key")
)

type CredentialStatus string

const (
	CredentialActive  CredentialStatus = "active"
	CredentialPending CredentialStatus = "pending"
	CredentialRevoked CredentialStatus = "revoked"
)

// KeyStorage is where a Mac said its key is kept when it enrolled. It's the agent's own
// claim: nothing on the server can check it.
type KeyStorage string

const (
	// KeyStorageUnknown: the agent didn't say (before 0.2.0, all file keys), or said
	// something this server doesn't know.
	KeyStorageUnknown       KeyStorage = ""
	KeyStorageSecureEnclave KeyStorage = "secure_enclave"
	KeyStorageSoftware      KeyStorage = "software"
)

// ParseKeyStorage keeps the values this server knows and makes anything else unknown,
// so a value from a newer agent never stops a Mac enrolling.
func ParseKeyStorage(s string) KeyStorage {
	switch k := KeyStorage(s); k {
	case KeyStorageSecureEnclave, KeyStorageSoftware:
		return k
	default:
		return KeyStorageUnknown
	}
}

// DeviceCredential binds a Mac's public key to its tenant and serial.
type DeviceCredential struct {
	DeviceID     string           `json:"device_id"`
	TenantID     string           `json:"tenant_id"`
	Serial       string           `json:"serial"`
	HardwareUUID string           `json:"hardware_uuid"`
	PublicKey    []byte           `json:"public_key"` // SubjectPublicKeyInfo DER
	KeyStorage   KeyStorage       `json:"key_storage"`
	Token        string           `json:"token"` // the enrolling token's audit name, as Principal.Actor; "" before server 0.9.0
	Status       CredentialStatus `json:"status"`
	CreatedAt    time.Time        `json:"created_at"`
	ActivatedAt  *time.Time       `json:"activated_at"`
	RevokedAt    *time.Time       `json:"revoked_at"`
	// RotatedFrom is the key this one replaced by rotation, and "" for an enrolled key.
	RotatedFrom string `json:"rotated_from,omitempty"`
	// RotatedTo is the key that replaced this one by rotation (its direct successor). It is
	// filled only by Credential and ListCredentials, and for the stale key in RotateResult
	// and ContestResult.
	RotatedTo string `json:"rotated_to,omitempty"`
	// RotationSignedAt is when the Mac signed the rotation that made this key, by its own
	// clock.
	RotationSignedAt *time.Time `json:"-"`
}

// KeyFingerprint is the lower-case hex SHA-256 of the public key's DER, which is how a key
// is told apart in the console (it shows the first 16 digits) and in the SIEM.
func (c DeviceCredential) KeyFingerprint() string { return hex.EncodeToString(keyDigest(c.PublicKey)) }

// EnrollResult is the credential an enrollment produced or found, and the device ID of
// the active credential it replaced, if any.
type EnrollResult struct {
	Credential DeviceCredential
	Replaced   string
	// Previous is the serial's active credential as it was just before a new key enrolled,
	// whether the key replaced it or is waiting for approval. It is nil for a serial's first
	// key, when nothing was active (the earlier credentials were revoked), and when the same
	// key enrolled again.
	Previous *DeviceCredential
}

// EnrollLimits bound how fast one tenant's enrolment token can add Macs and keys, which
// otherwise it can do without end. 0 turns a limit off.
type EnrollLimits struct {
	// NewMacsPerHour is how many serials new to the tenant may enrol in an hour. A serial is
	// new when the tenant has no credential of any status for it, and counts for the hour
	// after its first key.
	NewMacsPerHour int
	// KeysPerMacPerDay is how many keys one serial may enrol in 24 hours, in any status.
	KeysPerMacPerDay int
}

// The limits a server applies unless its administrator changes them: well above what a
// real fleet enrols in an hour, and a handful of reinstalls for one Mac in a day.
const (
	DefaultNewMacsPerHour   = 1000
	DefaultKeysPerMacPerDay = 5
)

// DefaultEnrollLimits are the limits a server applies unless told otherwise.
func DefaultEnrollLimits() EnrollLimits {
	return EnrollLimits{NewMacsPerHour: DefaultNewMacsPerHour, KeysPerMacPerDay: DefaultKeysPerMacPerDay}
}

// The windows the limits count over, ending at the new key's CreatedAt.
const (
	NewMacsWindow    = time.Hour
	KeysPerMacWindow = 24 * time.Hour
)

// refusesNewMac reports whether n new Macs in the last hour leave no room for another.
func (l EnrollLimits) refusesNewMac(n int) bool { return l.NewMacsPerHour > 0 && n >= l.NewMacsPerHour }

// refusesKey reports whether n keys for one Mac in the last 24 hours leave no room for another.
func (l EnrollLimits) refusesKey(n int) bool {
	return l.KeysPerMacPerDay > 0 && n >= l.KeysPerMacPerDay
}

// holdsForApproval reports whether a new key waits for an admin instead of becoming active.
// It does when the tenant requires approval for a Mac that enrolled before, or for a new
// Mac, and whatever the tenant chose when the Mac has an active key and the new one claims
// other hardware: then it may be a different Mac under the same serial. active is nil when
// nothing is.
func holdsForApproval(settings TenantSettings, enrolledBefore bool, active *DeviceCredential, hardwareUUID string) bool {
	if enrolledBefore && settings.ReenrollmentRequiresApproval || !enrolledBefore && settings.NewMacRequiresApproval {
		return true
	}
	return active != nil && active.HardwareUUID != hardwareUUID
}

// Rotation replaces a Mac's active key with one it proves it holds. The old key is then
// stale: revoked, with a successor. A stale key used again shows two holders of one
// lineage, which is a contest (StaleKeyUsed).
const (
	// MinRotationInterval is how long a key must have been active before it rotates.
	MinRotationInterval = 24 * time.Hour
	// InFlightGrace is how long after a rotation a request signed before it may still
	// arrive without being a contest.
	InFlightGrace = 60 * time.Second
	// ContestWindow: a contest revokes only if the stale key's successor was activated this
	// recently. An older stale key only raises the alert.
	ContestWindow = 30 * 24 * time.Hour
)

// staleUseReportInterval is how often one stale key's use is reported again.
const staleUseReportInterval = 24 * time.Hour

// RotateRequest asks to replace FromDeviceID's key with PublicKey.
type RotateRequest struct {
	TenantID, FromDeviceID, DeviceID string // DeviceID: the successor's, from NewDeviceID
	PublicKey                        []byte
	KeyStorage                       KeyStorage
	SignedAt                         time.Time // the rotate request's signed timestamp
	Now                              time.Time
	Alert                            ContestAlert // for a stale key asking for another key
}

// ContestResult is what a contest over a stale key did.
type ContestResult struct {
	Stale   DeviceCredential
	Revoked *DeviceCredential // the active descendant it revoked, if any
	Report  bool              // raise rotated_key_used
}

// ContestAlert makes the rotated_key_used event for a contest that reports. The store
// writes it in the contest's own transaction, so a revoke or a report marker is never kept
// without the alert that explains it: if the event can't be stored, nothing changes, and
// the stale key's next use contests again. Nil stores no event.
type ContestAlert func(ContestResult) event.Event

// RotateResult is what Rotate did or found.
type RotateResult struct {
	Credential DeviceCredential // the successor: new, or the existing one on a retry; zero when refused
	Previous   DeviceCredential // FromDeviceID's key as re-read under the lock, whenever it exists
	Retry      bool
	Contest    *ContestResult // set when a stale key asked to rotate to another key
}

// inFlight reports whether a request signed with next's predecessor at signedAt, and
// received at now, was on its way when next replaced it: signed no later than the rotation
// (both by the Mac's clock), and received no later than InFlightGrace after it.
func inFlight(next DeviceCredential, signedAt, now time.Time) bool {
	return next.RotationSignedAt != nil && next.ActivatedAt != nil &&
		!signedAt.After(*next.RotationSignedAt) && !now.After(next.ActivatedAt.Add(InFlightGrace))
}

// withinContestWindow reports whether next, a stale key's successor, was activated recently
// enough at now that a contest over the stale key revokes.
func withinContestWindow(next DeviceCredential, now time.Time) bool {
	return next.ActivatedAt != nil && now.Sub(*next.ActivatedAt) < ContestWindow
}

// staleUseReported reports whether a stale use at now changes the stale key's marker, last
// set at last (nil if never), and so is reported.
func staleUseReported(last *time.Time, now time.Time) bool {
	return last == nil || last.Before(now.Add(-staleUseReportInterval))
}

type CredentialFilter struct {
	Status CredentialStatus // empty = any
	Serial string
}

// TenantSettings are per-tenant switches set from the console.
type TenantSettings struct {
	// A new key for a serial that enrolled before waits for console approval, even
	// when the previous credential was revoked. Enabled by default.
	ReenrollmentRequiresApproval bool `json:"reenrollment_requires_approval"`
	// A serial's first key waits for console approval too, so the shared enrolment token
	// can't add a Mac on its own. Off by default, and when missing, for rollouts.
	NewMacRequiresApproval bool `json:"new_mac_requires_approval"`
	// SilentAfterHours is how long a Mac may go without checking in before the backend
	// raises agent.silent; 0 means DefaultSilentAfterHours.
	SilentAfterHours int `json:"silent_after_hours"`
	// SilentAlertsOff stops new agent.silent alerts, for a tenant that would rather spot
	// quiet Macs in its SIEM. A Mac already reported silent still sends "resumed" when it
	// checks in, so its alert closes. False, the zero value, keeps them on.
	SilentAlertsOff bool `json:"silent_alerts_off"`
	// HistoryDays is how long the server keeps history of Macs: 0 is the default (a year
	// with a SIEM connected, for good without one), HistoryKeptForGood (-1) keeps it for
	// good, and MinHistoryDays to MaxHistoryDays is a period an admin chose. Settings
	// stored before this field existed decode to 0, so they read as the default.
	HistoryDays int `json:"history_days"`
}

// DefaultTenantSettings requires approval before a new key can replace an enrolled Mac.
// Initialise JSON decoding with these defaults so missing or null flags stay secure.
// An explicit false remains an administrator's supported opt-out.
func DefaultTenantSettings() TenantSettings {
	return TenantSettings{ReenrollmentRequiresApproval: true}
}

// Bounds for TenantSettings.SilentAfterHours. The default rides out a laptop closed over
// a weekend.
const (
	DefaultSilentAfterHours = 72
	MinSilentAfterHours     = 1
	MaxSilentAfterHours     = 30 * 24
)

// Bounds for TenantSettings.HistoryDays. The minimum is the Overview's longest period, so
// it always stays complete.
const (
	HistoryKeptForGood = -1
	MinHistoryDays     = 90
	MaxHistoryDays     = 3650
	DefaultHistoryDays = 365
)

// Why History gave the period it did.
const (
	HistoryReasonDefaultSIEM   = "default_siem"
	HistoryReasonDefaultNoSIEM = "default_no_siem"
	HistoryReasonSet           = "set"
	HistoryReasonKeptForGood   = "kept_for_good"
)

// History is the period the server keeps history for, in days, and why. siem says whether
// the server has at least one export sink configured. 0 days means nothing is removed.
// An explicit period applies with or without a SIEM: the admin chose it on purpose.
func (s TenantSettings) History(siem bool) (days int, reason string) {
	switch {
	case s.HistoryDays == HistoryKeptForGood:
		return 0, HistoryReasonKeptForGood
	case s.HistoryDays > 0:
		return s.HistoryDays, HistoryReasonSet
	case siem:
		return DefaultHistoryDays, HistoryReasonDefaultSIEM
	default:
		return 0, HistoryReasonDefaultNoSIEM
	}
}

// SilentAfter is how long a Mac may go without checking in before it is reported silent.
func (s TenantSettings) SilentAfter() time.Duration {
	h := s.SilentAfterHours
	if h == 0 {
		h = DefaultSilentAfterHours
	}
	return time.Duration(h) * time.Hour
}

type Credentials interface {
	// Enroll records c (DeviceID, TenantID, Serial, HardwareUUID, PublicKey, KeyStorage,
	// CreatedAt). The same key again returns its existing credential, KeyStorage
	// unchanged, and no Previous, whatever limits say; a key held by another tenant
	// is ErrConflict. A new key is then counted against limits, over the time before
	// c.CreatedAt, and refused with ErrNewMacsLimited or ErrKeysPerMacLimited (both
	// ErrRateLimited) when it would pass one; nothing is stored then.
	// A serial's first credential is active. A later one replaces the active credential
	// (revoking it) only when the tenant explicitly disables approval and the key comes
	// from the same hardware as the active one. Otherwise it is pending: when approval is
	// on, even if the earlier credential was revoked, and when the hardware UUID differs
	// from the active credential's, even if approval is off. There is no limit on the number
	// of active Macs.
	Enroll(ctx context.Context, c DeviceCredential, limits EnrollLimits) (EnrollResult, error)
	// Credential looks a credential up by device ID across tenants, for authentication.
	Credential(ctx context.Context, deviceID string) (DeviceCredential, error)
	// ApproveCredential activates a pending credential and revokes the serial's other active
	// one, recording a.
	ApproveCredential(ctx context.Context, tenantID, deviceID string, now time.Time, a AuditEntry) (DeviceCredential, error)
	// RevokeCredential revokes a credential, recording a; revoking twice keeps the first time.
	// A rotated key whose lineage has an active key is ErrRotated, and nothing changes.
	RevokeCredential(ctx context.Context, tenantID, deviceID string, now time.Time, a AuditEntry) (DeviceCredential, error)
	// Rotate replaces r.FromDeviceID's active key with r.PublicKey, under the Mac's lock. In
	// order: the same request again (the old key's successor holds r.PublicKey) returns the
	// successor as it is now, with Retry; a stale key asking for another key is a contest,
	// returned with ErrRotatedElsewhere (storing r.Alert's event when the contest reports);
	// a revoked key is ErrRevoked, and a pending one ErrInvalidState. An active key is
	// refused with ErrRotationNotAllowed when it is in the Secure Enclave,
	// ErrRotationTooSoon when it was activated less than MinRotationInterval before r.Now,
	// and ErrKeyInUse when any credential holds r.PublicKey. Otherwise the old key is revoked and its successor is active, with the
	// old key's serial, hardware UUID and token. Rotation is not an enrolment: no approval
	// or EnrollLimits apply.
	Rotate(ctx context.Context, r RotateRequest) (RotateResult, error)
	// StaleKeyUsed resolves a contest when a stale key (revoked, with a successor) signed a
	// request at signedAt, received at now. It returns nil when the request was in flight
	// (see InFlightGrace) and when the key is not stale. Otherwise, under the Mac's lock, it
	// revokes the Mac's active key if that descends from the stale key and the stale key's
	// successor was activated less than ContestWindow ago, and reports the use at most once
	// in 24 hours unless it revoked, storing alert's event with the contest when it does.
	StaleKeyUsed(ctx context.Context, deviceID string, signedAt, now time.Time, alert ContestAlert) (*ContestResult, error)
	// LineageActive returns the active key among deviceID's key and its successors, or
	// ErrNotFound if none is.
	LineageActive(ctx context.Context, deviceID string) (DeviceCredential, error)
	// ListCredentials returns the tenant's credentials, newest first.
	ListCredentials(ctx context.Context, tenantID string, f CredentialFilter) ([]DeviceCredential, error)

	TenantSettings(ctx context.Context, tenantID string) (TenantSettings, error)
	// PutTenantSettings replaces the tenant's settings, recording a.
	PutTenantSettings(ctx context.Context, tenantID string, s TenantSettings, a AuditEntry) error
}

// NewDeviceID returns a random lower-case UUID (version 4).
func NewDeviceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func keyDigest(publicKey []byte) []byte {
	d := sha256.Sum256(publicKey)
	return d[:]
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// isUUID guards uuid columns: a malformed ID is simply not found, not a database error.
func isUUID(s string) bool { return uuidPattern.MatchString(s) }
