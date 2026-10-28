package store

import (
	"context"
	"strings"
	"time"
)

// MDMIntune is the source name of Microsoft Intune's copy.
const MDMIntune = "intune"

// MDMDevice is one Mac in the copy the server keeps of what an MDM manages.
type MDMDevice struct {
	TenantID      string
	Source        string // MDMIntune
	DeviceID      string // the MDM's own ID, stored lower-cased
	Serial        string
	EntraDeviceID string
	PrimaryUPN    string // the MDM's primary user, never written into a person's events
	Name          string
	LastCheckIn   time.Time // zero when the Mac has never checked in with the MDM
}

// MDMSync is the record of one source's sync for a tenant. Nil times mean never.
type MDMSync struct {
	TenantID      string     `json:"tenant_id"`
	Source        string     `json:"source"`
	LastSuccessAt *time.Time `json:"last_success_at"`
	LastErrorAt   *time.Time `json:"last_error_at"`
	SilenceHeldAt *time.Time `json:"silence_held_at"` // when silence alerts were last held back in bulk
	LastError     string     `json:"last_error,omitempty"`
	Devices       int        `json:"devices"` // in the copy, at the last success
	SilenceHeld   int        `json:"silence_held"`
}

// MDM keeps a copy of the Macs an MDM manages, replaced whole at each sync, and the record
// of that sync. Each copy belongs to one tenant and one source.
type MDM interface {
	// ClaimMDMSync reports whether this caller may sync now: true for one caller per every/2,
	// so of several replicas running the sync every interval, one does.
	ClaimMDMSync(ctx context.Context, tenantID, source string, now time.Time, every time.Duration) (bool, error)
	// ReplaceMDMDevices replaces the whole copy with devices in one transaction, and records
	// a successful sync at at. Device IDs are stored lower-cased; one listed twice is kept
	// once, as last listed.
	ReplaceMDMDevices(ctx context.Context, tenantID, source string, devices []MDMDevice, at time.Time) error
	// RecordMDMSyncError records a failed sync. The copy and the last success stay.
	RecordMDMSyncError(ctx context.Context, tenantID, source, msg string, at time.Time) error
	// RecordSilenceHeld records that count silence alerts were held back at at, because too
	// many Macs would have tripped at once.
	RecordSilenceHeld(ctx context.Context, tenantID, source string, count int, at time.Time) error
	// MDMDevicesBySerial returns the copy's records for serial, ignoring case and surrounding
	// spaces, newest check-in first: an MDM can list one serial more than once.
	MDMDevicesBySerial(ctx context.Context, tenantID, source, serial string) ([]MDMDevice, error)
	// MDMDevices returns the whole copy, by serial.
	MDMDevices(ctx context.Context, tenantID, source string) ([]MDMDevice, error)
	// MDMSyncStatus returns the sync's record: the zero value when it has never run.
	MDMSyncStatus(ctx context.Context, tenantID, source string) (MDMSync, error)
	// ClearMDM deletes the copy and the record of its sync.
	ClearMDM(ctx context.Context, tenantID, source string) error
}

// MDMSerial is how a serial is matched: upper-cased, without surrounding spaces, as the
// index on mdm_devices has it.
func MDMSerial(s string) string { return strings.ToUpper(strings.Trim(s, " ")) }

// uniqueMDMDevices lower-cases each device ID and keeps the last record of each, in the
// order first listed.
func uniqueMDMDevices(devices []MDMDevice) []MDMDevice {
	at := map[string]int{}
	out := make([]MDMDevice, 0, len(devices))
	for _, d := range devices {
		d.DeviceID = strings.ToLower(d.DeviceID)
		if i, ok := at[d.DeviceID]; ok {
			out[i] = d
			continue
		}
		at[d.DeviceID] = len(out)
		out = append(out, d)
	}
	return out
}
