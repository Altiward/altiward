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
)

// Device credentials and tenant settings.

var (
	ErrConflict     = errors.New("conflict")
	ErrInvalidState = errors.New("invalid state for this operation")
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
	Status       CredentialStatus `json:"status"`
	CreatedAt    time.Time        `json:"created_at"`
	ActivatedAt  *time.Time       `json:"activated_at"`
	RevokedAt    *time.Time       `json:"revoked_at"`
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

type CredentialFilter struct {
	Status CredentialStatus // empty = any
	Serial string
}

// TenantSettings are per-tenant switches set from the console.
type TenantSettings struct {
	// A new key for a serial that enrolled before waits for console approval, even
	// when the previous credential was revoked. Enabled by default.
	ReenrollmentRequiresApproval bool `json:"reenrollment_requires_approval"`
	// SilentAfterHours is how long a Mac may go without checking in before the backend
	// raises agent.silent; 0 means DefaultSilentAfterHours.
	SilentAfterHours int `json:"silent_after_hours"`
	// SilentAlertsOff stops new agent.silent alerts, for a tenant that would rather spot
	// quiet Macs in its SIEM. A Mac already reported silent still sends "resumed" when it
	// checks in, so its alert closes. False, the zero value, keeps them on.
	SilentAlertsOff bool `json:"silent_alerts_off"`
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
	// unchanged, and no Previous; a key held by another tenant
	// is ErrConflict. A serial's first credential is active. A later one replaces the
	// active credential (revoking it) only when the tenant explicitly disables approval.
	// Otherwise it is pending, even when the earlier credential was revoked. There is no limit on
	// the number of active Macs.
	Enroll(ctx context.Context, c DeviceCredential) (EnrollResult, error)
	// Credential looks a credential up by device ID across tenants, for authentication.
	Credential(ctx context.Context, deviceID string) (DeviceCredential, error)
	// ApproveCredential activates a pending credential and revokes the serial's other active
	// one, recording a.
	ApproveCredential(ctx context.Context, tenantID, deviceID string, now time.Time, a AuditEntry) (DeviceCredential, error)
	// RevokeCredential revokes a credential, recording a; revoking twice keeps the first time.
	RevokeCredential(ctx context.Context, tenantID, deviceID string, now time.Time, a AuditEntry) (DeviceCredential, error)
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
