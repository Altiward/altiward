package mdm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/Altiward/altiward/backend/internal/store"
)

const (
	// Interval is how often the copy is refreshed.
	Interval = 15 * time.Minute
	// passTimeout bounds one pass: Graph's paging has no page cap, so a list that never
	// ends must still stop.
	passTimeout = 5 * time.Minute
	// maxError bounds a recorded error; a token endpoint's answer can be long.
	maxError = 1000
)

// Sync keeps the store's copy of the Macs Intune manages, replacing it whole at each pass.
// Replicas share the work through a claim in the store, so one of them syncs each round.
type Sync struct {
	Store    store.Store
	Source   Source
	TenantID string
	Log      *slog.Logger
	Now      func() time.Time
}

// Once claims this round and refreshes the copy. It does nothing when another replica
// holds the claim. A failed pass keeps the last good copy and records the error.
func (s *Sync) Once(ctx context.Context) error { return s.once(ctx, Interval) }

// Run syncs, then waits interval, until ctx is cancelled.
func (s *Sync) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := s.once(ctx, interval); err != nil && ctx.Err() == nil {
			s.Log.Warn("Intune sync failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// once holds the claim for every/2, so of several replicas each syncing every interval,
// one syncs each round.
func (s *Sync) once(ctx context.Context, every time.Duration) error {
	won, err := s.Store.ClaimMDMSync(ctx, s.TenantID, store.MDMIntune, s.Now(), every)
	if err != nil {
		return fmt.Errorf("claim the Intune sync: %w", err)
	}
	if !won {
		return nil
	}
	pass, cancel := context.WithTimeout(ctx, passTimeout)
	defer cancel()
	// A list that failed part way is never stored: the copy is all of Intune's Macs or the
	// last one that was.
	macs, err := s.Source.Macs(pass)
	if err != nil {
		if ctx.Err() != nil {
			return err // shutting down, not a failed sync
		}
		if errors.Is(pass.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("listing the Macs took longer than %v: %w", passTimeout, err)
		}
		return s.failed(ctx, err)
	}
	devices := make([]store.MDMDevice, 0, len(macs))
	for _, d := range macs {
		devices = append(devices, store.MDMDevice{
			TenantID: s.TenantID, Source: store.MDMIntune, DeviceID: d.ID, Serial: d.Serial,
			EntraDeviceID: d.EntraDeviceID, PrimaryUPN: d.PrimaryUPN, Name: d.Name, LastCheckIn: d.LastCheckIn,
		})
	}
	if err := s.Store.ReplaceMDMDevices(ctx, s.TenantID, store.MDMIntune, devices, s.Now()); err != nil {
		return s.failed(ctx, fmt.Errorf("store the Intune copy: %w", err))
	}
	return nil
}

// failed records err as the sync's last error, and returns it.
func (s *Sync) failed(ctx context.Context, err error) error {
	msg := err.Error()
	if len(msg) > maxError {
		cut := maxError
		for cut > 0 && !utf8.RuneStart(msg[cut]) {
			cut--
		}
		msg = msg[:cut] + "…"
	}
	if rerr := s.Store.RecordMDMSyncError(ctx, s.TenantID, store.MDMIntune, msg, s.Now()); rerr != nil {
		return errors.Join(err, fmt.Errorf("record the Intune sync's error: %w", rerr))
	}
	return err
}
