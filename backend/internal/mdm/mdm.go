// Package mdm connects Altiward to the MDM that manages the Macs, read-only: Microsoft
// Intune, through Microsoft Graph. A sync keeps a copy of every Mac it manages in the
// store, for the console and the silence monitor, and a checker asks it about an enrolling
// Mac.
package mdm

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Altiward/altiward/backend/internal/intune"
	"github.com/Altiward/altiward/backend/internal/store"
)

// Source is what the MDM answers. intune.Client is one.
type Source interface {
	// Macs lists every Mac the MDM manages.
	Macs(ctx context.Context) ([]intune.Device, error)
	// Device returns one managed device by the MDM's ID.
	Device(ctx context.Context, id string) (intune.Device, error)
	// DevicesBySerial lists the managed devices with a serial number.
	DevicesBySerial(ctx context.Context, serial string) ([]intune.Device, error)
}

// Checker checks an enrolling Mac against the MDM.
type Checker struct {
	Store    store.Store
	Source   Source
	TenantID string // the Altiward tenant the MDM's Macs belong to
	Log      *slog.Logger
	Now      func() time.Time
	// LookupTimeout bounds each live lookup, including any wait for a token.
	LookupTimeout time.Duration
	// SerialFilter says whether the MDM answers a lookup by serial number.
	SerialFilter bool

	mu       sync.Mutex
	started  []time.Time                          // when each live lookup in the last minute started
	inflight map[string]*lookup                   // live lookups in flight, by ID or serial
	notFound map[string]missing                   // IDs Intune didn't know, and what they turned out to be
	warned   map[string]time.Time                 // when each warning was last logged
	after    func(time.Duration) <-chan time.Time // nil: time.After; a test's clock otherwise
}
