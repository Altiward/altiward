package mdm

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Altiward/altiward/backend/internal/intune"
	"github.com/Altiward/altiward/backend/internal/store"
)

// An enrolment asks Intune about the Mac while the agent waits, with the shared enrolment
// token, so whoever holds that token must not be able to spend the Graph budget the sync
// needs, or hold enrolments up. Live lookups are bounded in three ways: each waits at most
// LookupTimeout, at most maxLookups start in any minute, and one at a time is in flight
// for any one ID or serial.
const (
	defaultLookupTimeout = 10 * time.Second
	maxLookups           = 30 // live lookups started in any minute
	lookupWindow         = time.Minute
	// notFoundFor is how long an ID Intune didn't know, and what it turned out to be, is
	// answered from memory.
	notFoundFor = 5 * time.Minute
	// warnEvery is how often each warning about a profile's MDMDeviceID is logged.
	warnEvery = time.Hour
)

const (
	warnInvalidID = "MDMDeviceID isn't an Intune device ID: use {{deviceid}}"
	warnEntraID   = "MDMDeviceID is the Mac's Entra device ID: use {{deviceid}}"
	warnCapped    = "more than 30 Intune lookups in a minute: enrolments are checked as unavailable until there is room"
	warnTimedOut  = "Intune didn't answer an enrolment's lookup in time"
)

// errUnavailable is a live lookup that wasn't made, or wasn't answered in time.
var errUnavailable = errors.New("mdm: Intune couldn't be asked in time")

// errEntraID is an ID Intune didn't know that is a Mac's Entra device ID.
var errEntraID = errors.New("mdm: the ID is a Mac's Entra device ID")

// missing is what an ID Intune didn't know turned out to be, and when Intune said so:
// MDMUnknownID, or MDMInvalidID for a Mac's Entra device ID.
type missing struct {
	at    time.Time
	check store.MDMCheck
}

// lookup is one live lookup in flight. val and err are set before done is closed.
type lookup struct {
	done chan struct{}
	val  any
	err  error
}

// Check asks Intune about the device ID a Mac sent as it enrolled, and gives the outcome
// that holdsForApproval in the store decides on. deviceID is never logged.
//
// It gives MDMNotChecked for a tenant Intune isn't connected for, MDMNotSent for an empty
// ID, and MDMInvalidID for one that isn't a GUID. Otherwise it looks the device up, live:
// MDMMismatch when the device isn't a Mac (a Mac can't honestly send another platform's
// ID), MDMUnknownID when Intune has no such device or one without a serial, MDMMismatch
// when its serial isn't exactly the Mac's, and MDMMatch when it is. An ID Intune doesn't have is
// MDMInvalidID instead when it is the Entra device ID of a Mac in the copy. Only then is the
// copy read, so that read sits under the same bounds as the lookup, and for notFoundFor
// both the outcome is answered from memory, without a lookup or a read.
// It gives MDMUnavailable when the lookup fails, isn't answered in time or ctx ends, or
// when the minute's lookups are spent.
//
// hardwareUUID is not compared: Graph v1.0 returns a device's udid empty when asked by ID,
// and null in lists (lab probe P2), so the serial alone decides.
func (c *Checker) Check(ctx context.Context, tenantID, deviceID, serial, hardwareUUID string) store.MDMCheck {
	if c == nil || tenantID != c.TenantID {
		return store.MDMNotChecked
	}
	id := strings.TrimSpace(deviceID)
	switch {
	case id == "":
		return store.MDMNotSent
	case !intune.ValidDeviceID(id):
		c.warnOnce(warnInvalidID, tenantID, serial)
		return store.MDMInvalidID
	}
	id = strings.ToLower(id)
	if check, ok := c.knownMissing(id); ok {
		if check == store.MDMInvalidID {
			c.warnOnce(warnEntraID, tenantID, serial)
		}
		return check
	}
	if c.Source == nil {
		return store.MDMUnavailable
	}
	d, err := live(c, ctx, tenantID, "device:"+id, func(ctx context.Context) (intune.Device, error) {
		d, err := c.Source.Device(ctx, id)
		if !errors.Is(err, intune.ErrNotFound) {
			return d, err
		}
		// A profile can name the Mac's Entra device ID by mistake: a GUID too, which only the
		// copy tells apart. A copy that can't be read leaves it unknown, and unremembered.
		entra, rerr := c.isEntraDeviceID(ctx, tenantID, id)
		switch {
		case rerr != nil:
			c.logger().Warn("can't read the copy of Intune's Macs", "tenant", tenantID, "err", rerr)
		case entra:
			c.rememberMissing(id, store.MDMInvalidID)
			return d, errEntraID
		default:
			c.rememberMissing(id, store.MDMUnknownID)
		}
		return d, err
	})
	switch {
	case errors.Is(err, errEntraID):
		c.warnOnce(warnEntraID, tenantID, serial)
		return store.MDMInvalidID
	case errors.Is(err, intune.ErrNotFound):
		return store.MDMUnknownID
	case err != nil:
		if !errors.Is(err, errUnavailable) {
			c.logger().Warn("Intune lookup of an enrolling Mac failed", "tenant", tenantID, "serial", serial,
				"err", redact(err.Error(), id))
		}
		return store.MDMUnavailable
	}
	intuneSerial := strings.TrimSpace(d.Serial)
	switch {
	case !isMac(d):
		return store.MDMMismatch
	case intuneSerial == "":
		return store.MDMUnknownID
	case intuneSerial != strings.TrimSpace(serial):
		return store.MDMMismatch
	default:
		return store.MDMMatch
	}
}

// SerialKnown reports whether Intune manages a Mac with serial. It is nil when that isn't
// known: Intune isn't connected for the tenant, the copy has never been synced, or the
// serial isn't in the copy and can't be looked up. With SerialFilter, a serial not in the
// copy, which is up to 15 minutes old, is looked up live, within the same bounds as Check;
// only a Mac counts. A serial Graph wouldn't take (intune.ValidSerial) isn't looked up, and
// costs none of the minute's lookups.
func (c *Checker) SerialKnown(ctx context.Context, tenantID, serial string) *bool {
	if c == nil || tenantID != c.TenantID || c.Store == nil {
		return nil
	}
	serial = strings.TrimSpace(serial)
	status, err := c.Store.MDMSyncStatus(ctx, tenantID, store.MDMIntune)
	if err != nil {
		c.logger().Warn("can't read the Intune sync's status", "tenant", tenantID, "err", err)
		return nil
	}
	if status.LastSuccessAt == nil {
		return nil
	}
	copies, err := c.Store.MDMDevicesBySerial(ctx, tenantID, store.MDMIntune, serial)
	if err != nil {
		c.logger().Warn("can't read the copy of Intune's Macs", "tenant", tenantID, "err", err)
		return nil
	}
	known := len(copies) > 0
	if known {
		return &known
	}
	if !c.SerialFilter || c.Source == nil || !intune.ValidSerial(serial) {
		return nil
	}
	devices, err := live(c, ctx, tenantID, "serial:"+serial, func(ctx context.Context) ([]intune.Device, error) {
		return c.Source.DevicesBySerial(ctx, serial)
	})
	if err != nil {
		if !errors.Is(err, errUnavailable) {
			c.logger().Warn("Intune lookup of an enrolling Mac's serial failed", "tenant", tenantID, "serial", serial, "err", err)
		}
		return nil
	}
	known = slices.ContainsFunc(devices, isMac)
	return &known
}

// isMac reports whether Intune's record is a Mac's.
func isMac(d intune.Device) bool {
	return strings.EqualFold(strings.TrimSpace(d.OperatingSystem), "macOS")
}

// live runs fn in a goroutine, so that a source that ignores its context (a token source
// that blocks) can't hold the caller, and waits for it for LookupTimeout at most. A lookup
// already in flight under key is waited for instead of starting another. A new one needs
// room in the minute's lookups. It gives errUnavailable when there is none, when the wait
// ends, or when ctx ends. The lookup itself runs on, up to LookupTimeout, for whoever else
// waits for it.
func live[T any](c *Checker, ctx context.Context, tenantID, key string, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	if ctx.Err() != nil {
		return zero, errUnavailable
	}
	timeout := c.LookupTimeout
	if timeout <= 0 {
		timeout = defaultLookupTimeout
	}
	c.mu.Lock()
	l, ok := c.inflight[key]
	if !ok {
		if !c.startLookup() {
			c.mu.Unlock()
			c.warnOnce(warnCapped, tenantID, "")
			return zero, errUnavailable
		}
		l = &lookup{done: make(chan struct{})}
		if c.inflight == nil {
			c.inflight = map[string]*lookup{}
		}
		c.inflight[key] = l
		go func() {
			lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
			defer cancel()
			v, err := fn(lctx)
			c.mu.Lock()
			l.val, l.err = v, err
			delete(c.inflight, key)
			c.mu.Unlock()
			close(l.done)
		}()
	}
	after := c.after
	c.mu.Unlock()
	if after == nil {
		after = time.After
	}
	select {
	case <-l.done:
		v, _ := l.val.(T)
		return v, l.err
	case <-after(timeout):
		c.warnOnce(warnTimedOut, tenantID, "")
		return zero, errUnavailable
	case <-ctx.Done():
		return zero, errUnavailable
	}
}

// startLookup expects c.mu held. It counts a new live lookup, unless maxLookups have
// started in the last minute.
func (c *Checker) startLookup() bool {
	now := c.now()
	kept := c.started[:0]
	for _, t := range c.started {
		if t.After(now.Add(-lookupWindow)) {
			kept = append(kept, t)
		}
	}
	c.started = kept
	if len(c.started) >= maxLookups {
		return false
	}
	c.started = append(c.started, now)
	return true
}

// isEntraDeviceID reports whether id, lower-cased, is the Entra device ID of a Mac in the
// copy. It reads the whole copy, so it runs only after Intune said it has no device id.
func (c *Checker) isEntraDeviceID(ctx context.Context, tenantID, id string) (bool, error) {
	if c.Store == nil {
		return false, nil
	}
	devices, err := c.Store.MDMDevices(ctx, tenantID, store.MDMIntune)
	if err != nil {
		return false, err
	}
	for _, d := range devices {
		if strings.EqualFold(strings.TrimSpace(d.EntraDeviceID), id) {
			return true, nil
		}
	}
	return false, nil
}

// knownMissing gives what an ID Intune said it didn't have in the last notFoundFor turned
// out to be, if it did.
func (c *Checker) knownMissing(id string) (store.MDMCheck, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.notFound[id]
	if !ok {
		return "", false
	}
	if c.now().Before(m.at.Add(notFoundFor)) {
		return m.check, true
	}
	delete(c.notFound, id)
	return "", false
}

// rememberMissing remembers that Intune has no device id, and what it turned out to be. The
// memory holds at most the IDs looked up in the last notFoundFor, which the cap on lookups
// bounds.
func (c *Checker) rememberMissing(id string, check store.MDMCheck) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, m := range c.notFound {
		if !now.Before(m.at.Add(notFoundFor)) {
			delete(c.notFound, k)
		}
	}
	if c.notFound == nil {
		c.notFound = map[string]missing{}
	}
	c.notFound[id] = missing{at: now, check: check}
}

// warnOnce logs msg as a warning, at most once every warnEvery for each message.
func (c *Checker) warnOnce(msg, tenantID, serial string) {
	c.mu.Lock()
	now := c.now()
	if last, ok := c.warned[msg]; ok && now.Before(last.Add(warnEvery)) {
		c.mu.Unlock()
		return
	}
	if c.warned == nil {
		c.warned = map[string]time.Time{}
	}
	c.warned[msg] = now
	c.mu.Unlock()
	args := []any{"tenant", tenantID}
	if serial != "" {
		args = append(args, "serial", serial)
	}
	c.logger().Warn(msg, args...)
}

func (c *Checker) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func (c *Checker) logger() interface{ Warn(string, ...any) } {
	if c.Log == nil {
		return discard{}
	}
	return c.Log
}

type discard struct{}

func (discard) Warn(string, ...any) {}

// redact takes id, a GUID, out of msg in any case: an error from Graph can quote the ID it
// was asked for, and the ID is never logged.
func redact(msg, id string) string {
	return regexp.MustCompile(`(?i)`+regexp.QuoteMeta(id)).ReplaceAllString(msg, "[device ID]")
}
