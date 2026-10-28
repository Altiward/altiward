package mdm_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/intune"
	"github.com/Altiward/altiward/backend/internal/mdm"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

const (
	macSerial = "C02XK0AAJGH5"
	intuneID  = "0a1b2c3d-0000-4000-8000-00000000000a"
	entraID   = "5e6f7a8b-0000-4000-8000-00000000000e"
)

// fakeIntune answers Device and DevicesBySerial from what it holds, and counts the calls.
// With block set, every call waits for it to close, whatever its context: a token source
// that never answers.
type fakeIntune struct {
	mu          sync.Mutex
	devices     map[string]intune.Device // by lower-case ID
	bySerial    map[string][]intune.Device
	err         error
	block       chan struct{}
	calls       int
	serialCalls int
}

func (f *fakeIntune) Macs(context.Context) ([]intune.Device, error) {
	return nil, errors.New("not used by the checker")
}

func (f *fakeIntune) Device(_ context.Context, id string) (intune.Device, error) {
	f.mu.Lock()
	f.calls++
	block, err := f.block, f.err
	d, ok := f.devices[strings.ToLower(strings.TrimSpace(id))]
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	switch {
	case err != nil:
		return intune.Device{}, err
	case !ok:
		return intune.Device{}, intune.ErrNotFound
	}
	return d, nil
}

func (f *fakeIntune) DevicesBySerial(_ context.Context, serial string) ([]intune.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.serialCalls++
	return f.bySerial[serial], f.err
}

func (f *fakeIntune) counts() (calls, serialCalls int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.serialCalls
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// logBuffer is a log the checker's goroutines can write to.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type checkEnv struct {
	c     *mdm.Checker
	src   *fakeIntune
	st    store.Store
	clock *fakeClock
	log   *logBuffer
}

// newCheck is a checker for acme whose Intune knows one Mac, intuneID with serial macSerial.
func newCheck(t *testing.T) *checkEnv {
	t.Helper()
	env := &checkEnv{
		src: &fakeIntune{devices: map[string]intune.Device{
			intuneID: {ID: intuneID, Serial: macSerial, EntraDeviceID: entraID, OperatingSystem: "macOS"},
		}},
		st:    store.NewMemory(nil),
		clock: &fakeClock{t: testfixture.Time(t, "2026-10-28T12:00:00Z")},
		log:   &logBuffer{},
	}
	env.c = &mdm.Checker{
		Store: env.st, Source: env.src, TenantID: "acme", Now: env.clock.now,
		Log: slog.New(slog.NewTextHandler(env.log, nil)),
	}
	return env
}

func (e *checkEnv) check(t *testing.T, deviceID, serial string) store.MDMCheck {
	t.Helper()
	return e.c.Check(context.Background(), "acme", deviceID, serial, "HW-"+serial)
}

func (e *checkEnv) want(t *testing.T, deviceID, serial string, want store.MDMCheck) {
	t.Helper()
	if got := e.check(t, deviceID, serial); got != want {
		t.Fatalf("Check(%q, %q) = %q, want %q", deviceID, serial, got, want)
	}
}

// The device ID never reaches a log line at info or above.
func (e *checkEnv) logHasNoID(t *testing.T, ids ...string) {
	t.Helper()
	logged := strings.ToLower(e.log.String())
	for _, id := range ids {
		if strings.Contains(logged, strings.ToLower(id)) {
			t.Fatalf("the log names the device ID %s:\n%s", id, logged)
		}
	}
}

func TestCheckMatch(t *testing.T) {
	env := newCheck(t)
	env.want(t, intuneID, macSerial, store.MDMMatch)
	// Intune's IDs are GUIDs in any case, and surrounding spaces don't count.
	env.want(t, " "+strings.ToUpper(intuneID)+" ", macSerial, store.MDMMatch)
	if calls, _ := env.src.counts(); calls != 2 {
		t.Fatalf("calls = %d, want one each", calls)
	}
	// Off for any other tenant, and nothing to look up without an ID.
	if got := env.c.Check(context.Background(), "other", intuneID, macSerial, "HW"); got != store.MDMNotChecked {
		t.Fatalf("another tenant = %q", got)
	}
	env.want(t, "", macSerial, store.MDMNotSent)
	env.want(t, "  ", macSerial, store.MDMNotSent)
	if calls, _ := env.src.counts(); calls != 2 {
		t.Fatalf("calls = %d, want no more", calls)
	}
	env.logHasNoID(t, intuneID)
}

func TestCheckMismatchBySerial(t *testing.T) {
	env := newCheck(t)
	env.want(t, intuneID, "C02OTHERMAC1", store.MDMMismatch)
	env.logHasNoID(t, intuneID)
}

func TestCheckSerialIsExact(t *testing.T) {
	env := newCheck(t)
	env.want(t, intuneID, strings.ToLower(macSerial), store.MDMMismatch)
	env.want(t, intuneID, macSerial+"0", store.MDMMismatch)
	// Surrounding spaces, on either side, are not part of a serial.
	env.want(t, intuneID, " "+macSerial+" ", store.MDMMatch)
	env.src.devices[intuneID] = intune.Device{ID: intuneID, Serial: macSerial + " ", OperatingSystem: "macOS"}
	env.want(t, intuneID, macSerial, store.MDMMatch)
}

func TestCheckUnknownIDIsRemembered(t *testing.T) {
	env := newCheck(t)
	const unknown = "ffffffff-0000-4000-8000-000000000001"
	env.want(t, unknown, macSerial, store.MDMUnknownID)
	env.clock.advance(5*time.Minute - time.Second)
	env.want(t, strings.ToUpper(unknown), macSerial, store.MDMUnknownID)
	if calls, _ := env.src.counts(); calls != 1 {
		t.Fatalf("calls = %d, want the second answered from memory", calls)
	}
	env.clock.advance(time.Second)
	env.want(t, unknown, macSerial, store.MDMUnknownID)
	if calls, _ := env.src.counts(); calls != 2 {
		t.Fatalf("calls = %d, want Intune asked again after 5 minutes", calls)
	}
	env.logHasNoID(t, unknown)
}

func TestCheckEmptyIntuneSerialIsUnknown(t *testing.T) {
	env := newCheck(t)
	env.src.devices[intuneID] = intune.Device{ID: intuneID, Serial: " ", OperatingSystem: "macOS"}
	env.want(t, intuneID, macSerial, store.MDMUnknownID)
}

// TestCheckMatchIsAMac: a Mac can't honestly send the ID of a device on another platform, so
// a record that isn't a Mac's is a mismatch, even with the Mac's serial.
func TestCheckMatchIsAMac(t *testing.T) {
	env := newCheck(t)
	for _, os := range []string{"Windows", "iOS", ""} {
		env.src.devices[intuneID] = intune.Device{ID: intuneID, Serial: macSerial, OperatingSystem: os}
		env.want(t, intuneID, macSerial, store.MDMMismatch)
	}
	// Even one without a serial.
	env.src.devices[intuneID] = intune.Device{ID: intuneID, Serial: "", OperatingSystem: "Windows"}
	env.want(t, intuneID, macSerial, store.MDMMismatch)
	// Graph's name for the platform, in any case.
	env.src.devices[intuneID] = intune.Device{ID: intuneID, Serial: macSerial, OperatingSystem: "macos"}
	env.want(t, intuneID, macSerial, store.MDMMatch)
}

func TestCheckUnavailableWhenIntuneFails(t *testing.T) {
	env := newCheck(t)
	env.src.err = fmt.Errorf("intune: HTTP 503 ServiceUnavailable: no device %s right now", intuneID)
	env.want(t, intuneID, macSerial, store.MDMUnavailable)
	if !strings.Contains(env.log.String(), "503") {
		t.Fatalf("the failure isn't logged:\n%s", env.log)
	}
	env.logHasNoID(t, intuneID)
	// Without a source to ask, nothing is known.
	env.c.Source = nil
	env.want(t, intuneID, macSerial, store.MDMUnavailable)
}

// TestCheckTimesOutBehindABlockedToken (Review Focus 2): the enrolment token can't stall an
// enrolment behind Intune. The source blocks forever, ignoring its context, and Check gives
// up once its 10 seconds have passed.
func TestCheckTimesOutBehindABlockedToken(t *testing.T) {
	env := newCheck(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	env.src.block = release
	asked, fire := make(chan time.Duration, 1), make(chan time.Time)
	restore := mdm.SetAfter(env.c, func(d time.Duration) <-chan time.Time {
		asked <- d
		return fire
	})
	defer restore()

	got := make(chan store.MDMCheck, 1)
	go func() { got <- env.check(t, intuneID, macSerial) }()
	if d := <-asked; d != 10*time.Second {
		t.Fatalf("Check waits %v, want the default 10 s", d)
	}
	select {
	case c := <-got:
		t.Fatalf("Check returned %q before its time was up", c)
	default:
	}
	fire <- env.clock.now().Add(10 * time.Second)
	if c := <-got; c != store.MDMUnavailable {
		t.Fatalf("Check = %q, want unavailable", c)
	}
	// A second time out within the hour isn't logged again.
	const warning = "Intune didn't answer an enrolment's lookup in time"
	go func() { got <- env.check(t, intuneID, macSerial) }()
	<-asked
	fire <- env.clock.now().Add(10 * time.Second)
	<-got
	if n := strings.Count(env.log.String(), warning); n != 1 {
		t.Fatalf("warned %d times, want once an hour:\n%s", n, env.log)
	}

	// The request's own context ends the wait too.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	restore()
	if c := env.c.Check(ctx, "acme", intuneID, macSerial, "HW"); c != store.MDMUnavailable {
		t.Fatalf("Check with a cancelled context = %q", c)
	}
}

// One lookup is in flight for an ID at a time: a second enrolment with it waits for the
// same answer.
func TestCheckOneLookupPerID(t *testing.T) {
	env := newCheck(t)
	release := make(chan struct{})
	env.src.block = release
	waiting := make(chan struct{}, 2)
	restore := mdm.SetAfter(env.c, func(d time.Duration) <-chan time.Time {
		waiting <- struct{}{}
		return time.After(time.Minute)
	})
	defer restore()
	got := make(chan store.MDMCheck, 2)
	for range 2 {
		go func() { got <- env.check(t, intuneID, macSerial) }()
	}
	<-waiting
	<-waiting
	close(release)
	for range 2 {
		if c := <-got; c != store.MDMMatch {
			t.Fatalf("Check = %q, want match", c)
		}
	}
	if calls, _ := env.src.counts(); calls != 1 {
		t.Fatalf("calls = %d, want one lookup for both", calls)
	}
}

// TestCheckCapsLiveLookups (Review Focus 2): the enrolment token can't spend Intune's
// Graph budget. Beyond 30 live lookups in a minute, Check gives unavailable without one.
func TestCheckCapsLiveLookups(t *testing.T) {
	env := newCheck(t)
	id := func(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }
	for i := range 30 {
		env.want(t, id(i), macSerial, store.MDMUnknownID)
		env.clock.advance(time.Second)
	}
	env.want(t, intuneID, macSerial, store.MDMUnavailable)
	if calls, _ := env.src.counts(); calls != 30 {
		t.Fatalf("calls = %d, want 30", calls)
	}
	// An ID Intune didn't know is still answered from memory, which costs nothing.
	env.want(t, id(29), macSerial, store.MDMUnknownID)
	// A minute after the first, there is room for one more.
	env.clock.advance(30 * time.Second)
	env.want(t, intuneID, macSerial, store.MDMMatch)
	if calls, _ := env.src.counts(); calls != 31 {
		t.Fatalf("calls = %d, want 31", calls)
	}
}

// TestCheckNamesTheEntraDeviceIDMistake (Review Focus 1): a profile that sends the Mac's
// Entra device ID instead of Intune's is an invalid ID, and the admin is told which mistake
// it is, at most once an hour, without the ID. Intune is asked first; the answer is
// remembered like any ID it doesn't know.
func TestCheckNamesTheEntraDeviceIDMistake(t *testing.T) {
	env := newCheck(t)
	if err := env.st.ReplaceMDMDevices(context.Background(), "acme", store.MDMIntune, []store.MDMDevice{
		{DeviceID: intuneID, Serial: macSerial, EntraDeviceID: strings.ToUpper(entraID)},
	}, env.clock.now()); err != nil {
		t.Fatal(err)
	}
	const warning = "MDMDeviceID is the Mac's Entra device ID: use {{deviceid}}"
	env.want(t, entraID, macSerial, store.MDMInvalidID)
	env.want(t, strings.ToUpper(entraID), macSerial, store.MDMInvalidID)
	if calls, _ := env.src.counts(); calls != 1 {
		t.Fatalf("calls = %d, want one, then the answer from memory", calls)
	}
	if n := strings.Count(env.log.String(), warning); n != 1 {
		t.Fatalf("warned %d times, want once:\n%s", n, env.log)
	}
	env.clock.advance(time.Hour)
	env.want(t, entraID, macSerial, store.MDMInvalidID)
	if n := strings.Count(env.log.String(), warning); n != 2 {
		t.Fatalf("warned %d times, want again after an hour:\n%s", n, env.log)
	}
	if !strings.Contains(env.log.String(), "level=WARN") {
		t.Fatalf("not a warning:\n%s", env.log)
	}
	env.logHasNoID(t, entraID, intuneID)
	// The Intune ID itself is still checked as usual.
	env.want(t, intuneID, macSerial, store.MDMMatch)
}

// countingStore counts the reads of the whole copy of Intune's Macs.
type countingStore struct {
	store.Store
	mu    sync.Mutex
	reads int
}

func (s *countingStore) MDMDevices(ctx context.Context, tenantID, source string) ([]store.MDMDevice, error) {
	s.mu.Lock()
	s.reads++
	s.mu.Unlock()
	return s.Store.MDMDevices(ctx, tenantID, source)
}

func (s *countingStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// The enrolment token can't make every enrolment read the whole copy: it is read only once
// Intune has said it doesn't know the ID, within the cap on lookups, and an Entra device ID
// sent again within 5 minutes costs neither a lookup nor a read.
func TestCheckReadsTheCopyOnlyForAnIDIntuneDoesNotKnow(t *testing.T) {
	env := newCheck(t)
	counting := &countingStore{Store: env.st}
	env.c.Store = counting
	if err := env.st.ReplaceMDMDevices(context.Background(), "acme", store.MDMIntune, []store.MDMDevice{
		{DeviceID: intuneID, Serial: macSerial, EntraDeviceID: entraID},
	}, env.clock.now()); err != nil {
		t.Fatal(err)
	}
	env.want(t, intuneID, macSerial, store.MDMMatch)
	env.want(t, "{{deviceid}}", macSerial, store.MDMInvalidID)
	if n := counting.count(); n != 0 {
		t.Fatalf("copy reads = %d, want none for an ID Intune knows or an invalid one", n)
	}
	env.want(t, entraID, macSerial, store.MDMInvalidID)
	calls, _ := env.src.counts()
	if n := counting.count(); n != 1 {
		t.Fatalf("copy reads = %d, want one", n)
	}
	for range 5 {
		env.clock.advance(time.Minute - time.Second)
		env.want(t, entraID, macSerial, store.MDMInvalidID)
	}
	if again, _ := env.src.counts(); again != calls || counting.count() != 1 {
		t.Fatalf("repeats made %d lookups and %d copy reads, want none", again-calls, counting.count()-1)
	}
	// An ID Intune doesn't know that isn't an Entra device ID reads the copy once too.
	const unknown = "ffffffff-0000-4000-8000-000000000001"
	env.want(t, unknown, macSerial, store.MDMUnknownID)
	env.want(t, unknown, macSerial, store.MDMUnknownID)
	if n := counting.count(); n != 2 {
		t.Fatalf("copy reads = %d, want two", n)
	}
	env.logHasNoID(t, entraID, intuneID, unknown)
}

func TestCheckInvalidID(t *testing.T) {
	env := newCheck(t)
	const warning = "MDMDeviceID isn't an Intune device ID: use {{deviceid}}"
	for _, id := range []string{"{{deviceid}}", "{{DeviceID}}", "abc"} {
		env.want(t, id, macSerial, store.MDMInvalidID)
	}
	if calls, _ := env.src.counts(); calls != 0 {
		t.Fatalf("calls = %d, want none", calls)
	}
	if n := strings.Count(env.log.String(), warning); n != 1 {
		t.Fatalf("warned %d times in the hour, want once:\n%s", n, env.log)
	}
	env.logHasNoID(t, "abc")
	env.clock.advance(time.Hour)
	env.want(t, "abc", macSerial, store.MDMInvalidID)
	if n := strings.Count(env.log.String(), warning); n != 2 {
		t.Fatalf("warned %d times, want again after an hour:\n%s", n, env.log)
	}
}

func TestSerialKnown(t *testing.T) {
	ctx := context.Background()
	is := func(t *testing.T, got *bool, want *bool) {
		t.Helper()
		if (got == nil) != (want == nil) || got != nil && *got != *want {
			t.Fatalf("SerialKnown = %v, want %v", show(got), show(want))
		}
	}
	yes, no := true, false

	env := newCheck(t)
	// Never synced: nothing is known yet.
	is(t, env.c.SerialKnown(ctx, "acme", macSerial), nil)
	if err := env.st.ReplaceMDMDevices(ctx, "acme", store.MDMIntune, []store.MDMDevice{
		{DeviceID: intuneID, Serial: macSerial},
	}, env.clock.now()); err != nil {
		t.Fatal(err)
	}
	is(t, env.c.SerialKnown(ctx, "acme", macSerial), &yes)
	is(t, env.c.SerialKnown(ctx, "other", macSerial), nil)
	// A miss, without a lookup by serial: the copy may be up to 15 minutes old.
	is(t, env.c.SerialKnown(ctx, "acme", "C02NEWMAC001"), nil)
	if _, serialCalls := env.src.counts(); serialCalls != 0 {
		t.Fatalf("serial lookups = %d, want none", serialCalls)
	}

	// With one, Intune is asked.
	env.c.SerialFilter = true
	env.src.bySerial = map[string][]intune.Device{"C02NEWMAC001": {{ID: intuneID, Serial: "C02NEWMAC001", OperatingSystem: "macOS"}}}
	is(t, env.c.SerialKnown(ctx, "acme", "C02NEWMAC001"), &yes)
	is(t, env.c.SerialKnown(ctx, "acme", "C02NOTKNOWN1"), &no)
	if _, serialCalls := env.src.counts(); serialCalls != 2 {
		t.Fatalf("serial lookups = %d, want 2", serialCalls)
	}
	env.src.err = errors.New("intune: HTTP 503")
	is(t, env.c.SerialKnown(ctx, "acme", "C02NOTKNOWN1"), nil)
}

// SerialKnown counts only Macs: another platform's device with the serial isn't the Mac.
func TestSerialKnownCountsOnlyMacs(t *testing.T) {
	ctx := context.Background()
	env := newCheck(t)
	env.c.SerialFilter = true
	if err := env.st.ReplaceMDMDevices(ctx, "acme", store.MDMIntune, nil, env.clock.now()); err != nil {
		t.Fatal(err)
	}
	env.src.bySerial = map[string][]intune.Device{
		"C02WINDOWS01": {{ID: intuneID, Serial: "C02WINDOWS01", OperatingSystem: "Windows"}},
		"C02BOTH00001": {{ID: intuneID, Serial: "C02BOTH00001", OperatingSystem: "Windows"},
			{ID: entraID, Serial: "C02BOTH00001", OperatingSystem: "macOS"}},
	}
	if got := env.c.SerialKnown(ctx, "acme", "C02WINDOWS01"); got == nil || *got {
		t.Fatalf("a Windows device's serial = %v, want false", show(got))
	}
	if got := env.c.SerialKnown(ctx, "acme", "C02BOTH00001"); got == nil || !*got {
		t.Fatalf("a serial a Mac has too = %v, want true", show(got))
	}
}

// SerialKnown checks a serial before it spends one of the minute's lookups on it: one Graph
// wouldn't take is unknown, with no lookup and nothing logged. Surrounding spaces don't count.
func TestSerialKnownChecksTheSerialFirst(t *testing.T) {
	ctx := context.Background()
	env := newCheck(t)
	env.c.SerialFilter = true
	if err := env.st.ReplaceMDMDevices(ctx, "acme", store.MDMIntune, nil, env.clock.now()); err != nil {
		t.Fatal(err)
	}
	for range 40 {
		for _, bad := range []string{"", "C02 XK", "x' or 1 eq 1", strings.Repeat("A", 33)} {
			if got := env.c.SerialKnown(ctx, "acme", bad); got != nil {
				t.Fatalf("SerialKnown(%q) = %v, want nil", bad, show(got))
			}
		}
	}
	if _, serialCalls := env.src.counts(); serialCalls != 0 {
		t.Fatalf("serial lookups = %d, want none", serialCalls)
	}
	if env.log.String() != "" {
		t.Fatalf("logged:\n%s", env.log)
	}
	// The cap is untouched, and a serial with spaces around it is looked up without them.
	env.src.bySerial = map[string][]intune.Device{"C02NEWMAC001": {{ID: intuneID, Serial: "C02NEWMAC001", OperatingSystem: "macOS"}}}
	if got := env.c.SerialKnown(ctx, "acme", " C02NEWMAC001 "); got == nil || !*got {
		t.Fatalf("a valid serial = %v, want true", show(got))
	}
}

func show(b *bool) string {
	if b == nil {
		return "nil"
	}
	return fmt.Sprint(*b)
}
