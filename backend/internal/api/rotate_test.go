package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

const (
	otherAgentToken = "agent-token-other-0001"
	rotatePath      = "/v1/agent/rotate"
)

// testClock is the server's clock, which a test moves.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *testClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// flakyStore fails the calls a test turns on, as a database that has gone away would.
type flakyStore struct {
	store.Store
	failRotate, failCredential, failIngest, failStaleKeyUsed bool
	// cancelledStaleKeyUsed and cancelledRotate fail a StaleKeyUsed or Rotate whose context is
	// cancelled, as a real store does; staleKeyDeadline and rotateDeadline are the deadlines
	// of the last one's context.
	cancelledStaleKeyUsed, cancelledRotate bool
	staleKeyDeadline, rotateDeadline       time.Time
	// held, when set, is sent the context of each Ingest of a rotated event, which then
	// waits until release is closed.
	held    chan<- context.Context
	release <-chan struct{}
}

func (f *flakyStore) Ingest(ctx context.Context, tenantID string, events []event.Event, receivedAt time.Time) (store.IngestResult, error) {
	if f.failIngest {
		return store.IngestResult{}, errors.New("disk full")
	}
	if f.held != nil && len(events) == 1 && events[0].Detail["state"] == event.EnrollmentStateRotated {
		f.held <- ctx
		<-f.release
	}
	return f.Store.Ingest(ctx, tenantID, events, receivedAt)
}

func (f *flakyStore) StaleKeyUsed(ctx context.Context, deviceID string, signedAt, now time.Time, alert store.ContestAlert) (*store.ContestResult, error) {
	if f.failStaleKeyUsed {
		return nil, errors.New("database unavailable")
	}
	f.staleKeyDeadline, _ = ctx.Deadline()
	if err := ctx.Err(); f.cancelledStaleKeyUsed && err != nil {
		return nil, err
	}
	return f.Store.StaleKeyUsed(ctx, deviceID, signedAt, now, alert)
}

func (f *flakyStore) Rotate(ctx context.Context, r store.RotateRequest) (store.RotateResult, error) {
	if f.failRotate {
		return store.RotateResult{}, errors.New("database unavailable")
	}
	f.rotateDeadline, _ = ctx.Deadline()
	if err := ctx.Err(); f.cancelledRotate && err != nil {
		return store.RotateResult{}, err
	}
	return f.Store.Rotate(ctx, r)
}

func (f *flakyStore) Credential(ctx context.Context, deviceID string) (store.DeviceCredential, error) {
	if f.failCredential {
		return store.DeviceCredential{}, errors.New("database unavailable")
	}
	return f.Store.Credential(ctx, deviceID)
}

// rotationHarness is a server with one enrolled Mac, whose key has been active for a day.
// Its clock starts at serverNow, when the Mac enrolled, and is moved to a day later by the
// constructor; every agent signs at the clock's time.
type rotationHarness struct {
	t          *testing.T
	h          http.Handler
	store      *store.Memory
	flaky      *flakyStore
	clock      *testClock
	agent      *agent // the enrolled Mac, signing with its first key
	enrolledAt time.Time
	logs       *strings.Builder
}

func newRotationServer(t *testing.T) *rotationHarness {
	t.Helper()
	tokens, err := auth.Parse("acme="+agentToken+",other="+otherAgentToken, "acme="+consoleToken)
	if err != nil {
		t.Fatal(err)
	}
	mem := store.NewMemory([]string{"splunk"}) // a sink, so stored events can be read back
	flaky := &flakyStore{Store: mem}
	rh := &rotationHarness{t: t, store: mem, flaky: flaky, clock: &testClock{t: serverNow(t)}, enrolledAt: serverNow(t), logs: &strings.Builder{}}
	rh.h = api.New(flaky, tokens, slog.New(slog.NewTextHandler(rh.logs, nil)), rh.clock.now)
	rh.agent = rh.enrol(fixtureSerial, "software")
	rh.clock.advance(store.MinRotationInterval)
	return rh
}

// enrol enrols a Mac with a fresh key at the clock's time.
func (rh *rotationHarness) enrol(serial, keyStorage string) *agent {
	rh.t.Helper()
	return enrollAs(rh.t, &agent{h: rh.h, key: newKey(rh.t), clock: rh.clock, keyStorage: keyStorage}, serial)
}

// body is a rotation request from `from` to the key `to`, which signs the proof.
func (rh *rotationHarness) body(from *agent, to *ecdsa.PrivateKey, keyStorage string) []byte {
	rh.t.Helper()
	return rotationBody(rh.t, from.deviceID, to, keyStorage)
}

func rotationBody(t testing.TB, deviceID string, to *ecdsa.PrivateKey, keyStorage string) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&to.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]string{
		"public_key": base64.StdEncoding.EncodeToString(spki), "key_storage": keyStorage,
		"proof": base64.StdEncoding.EncodeToString(rotationProof(t, deviceID, spki, to)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// rotationProof signs the statement for deviceID and spki with key.
func rotationProof(t testing.TB, deviceID string, spki []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(auth.RotationStatement(deviceID, spki)))
	proof, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// rotate posts body to the rotate endpoint, signed by from.
func (rh *rotationHarness) rotate(from *agent, body []byte) (*httptest.ResponseRecorder, map[string]any) {
	rh.t.Helper()
	return from.postTo(rh.t, rotatePath, body)
}

// rotated rotates the enrolled Mac to a fresh key and returns the agent holding it. It
// fails the test unless the server answers 201.
func (rh *rotationHarness) rotated() *agent {
	rh.t.Helper()
	next := newKey(rh.t)
	rec, out := rh.rotate(rh.agent, rh.body(rh.agent, next, "software"))
	if rec.Code != http.StatusCreated {
		rh.t.Fatalf("rotate: %d %s", rec.Code, rec.Body)
	}
	return &agent{h: rh.h, key: next, clock: rh.clock, deviceID: out["device_id"].(string), status: "active"}
}

func (rh *rotationHarness) credentials() []store.DeviceCredential {
	rh.t.Helper()
	creds, err := rh.store.ListCredentials(context.Background(), "acme", store.CredentialFilter{})
	if err != nil {
		rh.t.Fatal(err)
	}
	return creds
}

// polls reports the status a Mac's poll for commands gets.
func (rh *rotationHarness) polls(a *agent) int {
	rh.t.Helper()
	rec, _ := a.get(rh.t, "/v1/agent/commands")
	return rec.Code
}

func (rh *rotationHarness) revokeFromConsole(deviceID string) {
	rh.t.Helper()
	if rec, _ := do(rh.t, rh.h, "POST", "/v1/enrollments/"+deviceID+"/revoke", consoleToken, nil); rec.Code != http.StatusOK {
		rh.t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
}

// enrollmentEvents returns the stored agent.enrollment events in state, oldest first,
// failing the test if any of them doesn't validate.
func (rh *rotationHarness) enrollmentEvents(state string) []event.Event {
	rh.t.Helper()
	now := rh.clock.now()
	queued, err := rh.store.ClaimExports(context.Background(), "splunk", 1000, 0, now)
	if err != nil {
		rh.t.Fatal(err)
	}
	out := []event.Event{}
	for _, item := range queued {
		e := item.Event.Event
		if e.Type != event.AgentEnrollment || e.Detail["state"] != state {
			continue
		}
		if err := e.Validate(now); err != nil {
			rh.t.Fatalf("invalid agent.enrollment event %s: %v", e.EventID, err)
		}
		out = append(out, e)
	}
	return out
}

// activeKeys returns the device IDs of the tenant's active keys.
func (rh *rotationHarness) activeKeys() []string {
	rh.t.Helper()
	out := []string{}
	for _, c := range rh.credentials() {
		if c.Status == store.CredentialActive {
			out = append(out, c.DeviceID)
		}
	}
	return out
}

// wantStaleKeyUsed fails the test unless e reports a use of stale, the key that rotated to
// rotatedTo, revoking revoked ("" for none), sent by agent version agentVersion.
func wantStaleKeyUsed(t *testing.T, e event.Event, stale *agent, rotatedTo, revoked, agentVersion string) {
	t.Helper()
	want := map[string]any{
		"state":           event.EnrollmentStateRotatedKeyUsed,
		"device_id":       stale.deviceID,
		"key_fingerprint": publicKeyFingerprint(t, stale.key),
		"rotated_to":      rotatedTo,
	}
	if revoked != "" {
		want["revoked_device_id"] = revoked
	}
	if !reflect.DeepEqual(e.Detail, want) {
		t.Errorf("detail = %v, want %v", e.Detail, want)
	}
	wantDevice := event.Device{Serial: fixtureSerial, HardwareUUID: "HW-" + fixtureSerial, AgentVersion: agentVersion}
	if e.Device != wantDevice {
		t.Errorf("device = %+v, want %+v", e.Device, wantDevice)
	}
	// A random (version 4) ID, which no Mac can claim first.
	if len(e.EventID) != 36 || e.EventID[14] != '4' {
		t.Errorf("event_id = %s, want a random UUID", e.EventID)
	}
	if e.SessionID != nil || e.User != nil || e.Elevation != nil || e.Delayed {
		t.Errorf("event = %+v", e)
	}
}

func TestRotateActivatesTheNewKey(t *testing.T) {
	rh := newRotationServer(t)
	old := rh.agent
	next := newKey(t)
	rec, out := rh.rotate(old, rh.body(old, next, "software"))
	wantCode(t, rec, out, http.StatusCreated, "")
	id, _ := out["device_id"].(string)
	if id == "" || id == old.deviceID || out["status"] != "active" {
		t.Fatalf("answer = %s", rec.Body)
	}
	successor := &agent{h: rh.h, key: next, clock: rh.clock, deviceID: id}
	if got := rh.polls(successor); got != http.StatusOK {
		t.Fatalf("new key polls with %d", got)
	}
	rec, out = old.get(t, "/v1/agent/commands")
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")

	creds := rh.credentials()
	if len(creds) != 2 {
		t.Fatalf("%d credentials, want the old and the new", len(creds))
	}
	for _, c := range creds {
		switch c.DeviceID {
		case old.deviceID:
			if c.Status != store.CredentialRevoked {
				t.Errorf("old key is %s", c.Status)
			}
		case id:
			if c.Status != store.CredentialActive || c.RotatedFrom != old.deviceID || c.Serial != fixtureSerial ||
				c.KeyStorage != store.KeyStorageSoftware {
				t.Errorf("new key = %+v", c)
			}
		}
	}
	if logs := rh.logs.String(); !strings.Contains(logs, "device key rotated") || !strings.Contains(logs, "device_id="+id) {
		t.Errorf("log = %s", logs)
	}
}

func TestRotateRecordsKeyStorage(t *testing.T) {
	cases := []struct {
		name, sent string
		want       store.KeyStorage
	}{
		{"software", "software", store.KeyStorageSoftware},
		{"left out", "", store.KeyStorageUnknown},
		{"a value this server doesn't know", "tpm", store.KeyStorageUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rh := newRotationServer(t)
			rec, out := rh.rotate(rh.agent, rh.body(rh.agent, newKey(t), tc.sent))
			wantCode(t, rec, out, http.StatusCreated, "")
			c, err := rh.store.Credential(context.Background(), out["device_id"].(string))
			if err != nil || c.KeyStorage != tc.want {
				t.Fatalf("key storage = %q (%v), want %q", c.KeyStorage, err, tc.want)
			}
		})
	}
}

func TestRotateRetryAnswersMuchLater(t *testing.T) {
	rh := newRotationServer(t)
	next := newKey(t)
	body := rh.body(rh.agent, next, "software")
	rec, first := rh.rotate(rh.agent, body)
	wantCode(t, rec, first, http.StatusCreated, "")

	for _, later := range []time.Duration{0, 30 * 24 * time.Hour} {
		rh.clock.advance(later)
		rec, out := rh.rotate(rh.agent, body)
		wantCode(t, rec, out, http.StatusOK, "")
		if out["device_id"] != first["device_id"] || out["status"] != "active" {
			t.Fatalf("retry after %s = %s, want the first answer's device_id", later, rec.Body)
		}
	}
	if n := len(rh.credentials()); n != 2 {
		t.Fatalf("%d credentials after the retries, want 2", n)
	}
}

func TestRotateRetryAfterTheSuccessorWasRevoked(t *testing.T) {
	rh := newRotationServer(t)
	body := rh.body(rh.agent, newKey(t), "software")
	rec, first := rh.rotate(rh.agent, body)
	wantCode(t, rec, first, http.StatusCreated, "")
	rh.revokeFromConsole(first["device_id"].(string))

	rec, out := rh.rotate(rh.agent, body)
	wantCode(t, rec, out, http.StatusOK, "")
	if out["device_id"] != first["device_id"] || out["status"] != "revoked" {
		t.Fatalf("retry = %s", rec.Body)
	}
}

func TestRotateFromAPendingKey(t *testing.T) {
	rh := newRotationServer(t)
	// The same Mac enrolling from other hardware waits for approval.
	pending := enrollAs(t, &agent{h: rh.h, key: newKey(t), clock: rh.clock, hardwareUUID: "HW-another-board"}, fixtureSerial)
	if pending.status != "pending" {
		t.Fatalf("enrolled as %s, want pending", pending.status)
	}
	before := len(rh.credentials())
	rec, out := rh.rotate(pending, rh.body(pending, newKey(t), "software"))
	wantCode(t, rec, out, http.StatusForbidden, "enrollment_pending")
	if n := len(rh.credentials()); n != before {
		t.Fatalf("%d credentials, was %d", n, before)
	}
	// A pending key isn't stale, so a malformed request is still just malformed.
	rec, out = rh.rotate(pending, []byte(`{"public_key":`))
	wantCode(t, rec, out, http.StatusBadRequest, "rotation_invalid")
}

func TestRotateFromARevokedKey(t *testing.T) {
	rh := newRotationServer(t)
	rh.revokeFromConsole(rh.agent.deviceID)
	rec, out := rh.rotate(rh.agent, rh.body(rh.agent, newKey(t), "software"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	if n := len(rh.credentials()); n != 1 {
		t.Fatalf("%d credentials, want 1", n)
	}
}

func TestRotateRefusesABadRequest(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384SPKI, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	pk := func(k *ecdsa.PrivateKey) string {
		spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return b64(spki)
	}
	marshal := func(v map[string]string) []byte {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cases := []struct {
		name string
		body func(rh *rotationHarness) []byte
	}{
		{"a proof by another key", func(rh *rotationHarness) []byte {
			next, other := newKey(t), newKey(t)
			spki, _ := x509.MarshalPKIXPublicKey(&next.PublicKey)
			return marshal(map[string]string{"public_key": b64(spki), "proof": b64(rotationProof(t, rh.agent.deviceID, spki, other))})
		}},
		{"a proof for another device_id", func(rh *rotationHarness) []byte {
			return rotationBody(t, "0d9e8f7a-6b5c-4d3e-8f2a-1b0c9d8e7f6a", newKey(t), "software")
		}},
		{"a key that is not P-256", func(rh *rotationHarness) []byte {
			return marshal(map[string]string{"public_key": b64(p384SPKI), "proof": b64(rotationProof(t, rh.agent.deviceID, p384SPKI, p384))})
		}},
		{"the current key", func(rh *rotationHarness) []byte {
			return rh.body(rh.agent, rh.agent.key, "software")
		}},
		{"no proof", func(rh *rotationHarness) []byte {
			return marshal(map[string]string{"public_key": pk(newKey(t)), "key_storage": "software"})
		}},
		{"a proof that is not base64", func(rh *rotationHarness) []byte {
			return marshal(map[string]string{"public_key": pk(newKey(t)), "proof": "%%%"})
		}},
		{"no public_key", func(rh *rotationHarness) []byte {
			return marshal(map[string]string{"proof": "AAAA"})
		}},
		{"a body that is not JSON", func(rh *rotationHarness) []byte { return []byte(`{"public_key":`) }},
		{"an empty body", func(rh *rotationHarness) []byte { return nil }},
		{"fields of the wrong type", func(rh *rotationHarness) []byte { return []byte(`{"public_key":1,"proof":[]}`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rh := newRotationServer(t)
			rec, out := rh.rotate(rh.agent, tc.body(rh))
			wantCode(t, rec, out, http.StatusBadRequest, "rotation_invalid")
			if got := rh.polls(rh.agent); got != http.StatusOK {
				t.Fatalf("the old key polls with %d", got)
			}
			if n := len(rh.credentials()); n != 1 {
				t.Fatalf("%d credentials, want 1", n)
			}
		})
	}
}

func TestRotateRefusesAKeyInUse(t *testing.T) {
	rh := newRotationServer(t)
	here := rh.enrol("C02OTHERMAC", "software")

	elsewhereKey := newKey(t)
	spki, err := x509.MarshalPKIXPublicKey(&elsewhereKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := do(t, rh.h, "POST", "/v1/agent/enroll", otherAgentToken, map[string]string{
		"serial": "C02THEIRS", "hardware_uuid": "HW-theirs", "public_key": base64.StdEncoding.EncodeToString(spki),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("enrol in another tenant: %d %s", rec.Code, rec.Body)
	}

	for name, key := range map[string]*ecdsa.PrivateKey{"this tenant": here.key, "another tenant": elsewhereKey} {
		t.Run(name, func(t *testing.T) {
			rec, out := rh.rotate(rh.agent, rh.body(rh.agent, key, "software"))
			wantCode(t, rec, out, http.StatusConflict, "key_in_use")
			if got := rh.polls(rh.agent); got != http.StatusOK {
				t.Fatalf("the old key polls with %d", got)
			}
		})
	}
}

func TestRotateRefusesASecureEnclaveKey(t *testing.T) {
	rh := newRotationServer(t)
	enclave := rh.enrol("C02ENCLAVE", "secure_enclave")
	rh.clock.advance(store.MinRotationInterval) // old enough, so only the key's storage can refuse
	rec, out := rh.rotate(enclave, rh.body(enclave, newKey(t), "software"))
	wantCode(t, rec, out, http.StatusConflict, "rotation_not_allowed")
	if got := rh.polls(enclave); got != http.StatusOK {
		t.Fatalf("the Secure Enclave key polls with %d", got)
	}
}

func TestRotateTooSoon(t *testing.T) {
	rh := newRotationServer(t)
	body := rh.body(rh.agent, newKey(t), "software")
	rh.clock.set(rh.enrolledAt.Add(store.MinRotationInterval - time.Minute))
	rec, out := rh.rotate(rh.agent, body)
	wantCode(t, rec, out, http.StatusTooManyRequests, "rotation_rate_limited")
	if got := rec.Header().Get("Retry-After"); got != "60" {
		t.Fatalf("Retry-After = %q, want 60", got)
	}
	// Seconds are rounded up.
	rh.clock.set(rh.enrolledAt.Add(store.MinRotationInterval - 1500*time.Millisecond))
	if rec, _ := rh.rotate(rh.agent, body); rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("Retry-After = %q, want 2", rec.Header().Get("Retry-After"))
	}
	rh.clock.set(rh.enrolledAt.Add(store.MinRotationInterval))
	if rec, out := rh.rotate(rh.agent, body); rec.Code != http.StatusCreated {
		t.Fatalf("at 24 hours: %d %v", rec.Code, out)
	}
}

func TestRotatedKeyGetsCredentialInvalid(t *testing.T) {
	rh := newRotationServer(t)
	rh.rotated()
	rec, out := rh.agent.post(t, batch(t, "agent-health"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
}

func TestQueuedCommandReachesTheSuccessor(t *testing.T) {
	rh := newRotationServer(t)
	if rec, out := rh.agent.post(t, batch(t, "agent-health")); rec.Code != http.StatusOK {
		t.Fatalf("health: %d %v", rec.Code, out)
	}
	rec, cmd := do(t, rh.h, "POST", "/v1/devices/"+fixtureSerial+"/revoke", consoleToken, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("queue: %d %s", rec.Code, rec.Body)
	}
	successor := rh.rotated()
	rec, out := successor.get(t, "/v1/agent/commands")
	list, _ := out["commands"].([]any)
	if rec.Code != http.StatusOK || len(list) != 1 || list[0].(map[string]any)["command_id"] != cmd["command_id"] {
		t.Fatalf("successor poll: %d %s", rec.Code, rec.Body)
	}
}

func TestRotateServerFailures(t *testing.T) {
	t.Run("outside the clock window", func(t *testing.T) {
		rh := newRotationServer(t)
		late := *rh.agent
		late.skew = -6 * time.Minute
		rec, out := rh.rotate(&late, rh.body(rh.agent, newKey(t), "software"))
		wantCode(t, rec, out, http.StatusUnauthorized, "clock_skew")
		if got := rec.Header().Get("Date"); got != rh.clock.now().UTC().Format(http.TimeFormat) {
			t.Fatalf("Date = %q", got)
		}
		if n := len(rh.credentials()); n != 1 {
			t.Fatalf("%d credentials, want 1", n)
		}
	})
	t.Run("a body over the limit", func(t *testing.T) {
		rh := newRotationServer(t)
		rec, _ := rh.rotate(rh.agent, bytes.Repeat([]byte("x"), api.MaxBodyBytes+1))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("the store fails the rotation", func(t *testing.T) {
		rh := newRotationServer(t)
		rh.flaky.failRotate = true
		rec, _ := rh.rotate(rh.agent, rh.body(rh.agent, newKey(t), "software"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
		rh.flaky.failRotate = false
		if got := rh.polls(rh.agent); got != http.StatusOK {
			t.Fatalf("the old key polls with %d", got)
		}
	})
	t.Run("the store fails the credential lookup", func(t *testing.T) {
		rh := newRotationServer(t)
		rh.flaky.failCredential = true
		rec, _ := rh.rotate(rh.agent, rh.body(rh.agent, newKey(t), "software"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
	})
}

// The successor records when the Mac signed the rotation, by the Mac's clock, not when the
// server received it: that is what an old-key request signed at the same moment is
// compared with.
func TestRotateRecordsWhenTheMacSignedIt(t *testing.T) {
	rh := newRotationServer(t)
	behind := *rh.agent
	behind.skew = -30 * time.Second
	rec, out := rh.rotate(&behind, rh.body(rh.agent, newKey(t), "software"))
	wantCode(t, rec, out, http.StatusCreated, "")
	c, err := rh.store.Credential(context.Background(), out["device_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	signed := rh.clock.now().Add(-30 * time.Second)
	if c.RotationSignedAt == nil || !c.RotationSignedAt.Equal(signed) {
		t.Fatalf("rotation signed at %v, want %v", c.RotationSignedAt, signed)
	}
	if c.ActivatedAt == nil || !c.ActivatedAt.Equal(rh.clock.now()) {
		t.Fatalf("activated at %v, want %v", c.ActivatedAt, rh.clock.now())
	}
}

func TestRotationRaisesRotated(t *testing.T) {
	rh := newRotationServer(t)
	old := rh.agent
	old.userAgent = "altiward-agent/1.0.0"
	next := newKey(t)
	body := rh.body(old, next, "secure_enclave")
	rec, out := rh.rotate(old, body)
	wantCode(t, rec, out, http.StatusCreated, "")
	id := out["device_id"].(string)

	got := rh.enrollmentEvents(event.EnrollmentStateRotated)
	if len(got) != 1 {
		t.Fatalf("%d rotated events, want 1", len(got))
	}
	e := got[0]
	if want := event.RaisedID("acme/enrollment/" + id); e.EventID != want {
		t.Errorf("event_id = %s, want %s", e.EventID, want)
	}
	if !e.Timestamp.Equal(rh.clock.now()) || e.SessionID != nil || e.User != nil || e.Elevation != nil || e.Delayed {
		t.Errorf("event = %+v", e)
	}
	wantDevice := event.Device{Serial: fixtureSerial, HardwareUUID: "HW-" + fixtureSerial, AgentVersion: "1.0.0"}
	if e.Device != wantDevice {
		t.Errorf("device = %+v, want %+v", e.Device, wantDevice)
	}
	// No token: a rotation doesn't use one, and the Mac is the actor.
	wantDetail := map[string]any{
		"state":                 event.EnrollmentStateRotated,
		"device_id":             id,
		"key_fingerprint":       publicKeyFingerprint(t, next),
		"key_storage":           "secure_enclave",
		"previous_device_id":    old.deviceID,
		"previous_key_storage":  "software",
		"hardware_uuid_matches": true,
	}
	if !reflect.DeepEqual(e.Detail, wantDetail) {
		t.Errorf("detail = %v, want %v", e.Detail, wantDetail)
	}

	// A retry raises it again, and the same ID stores nothing new.
	for _, later := range []time.Duration{0, 30 * 24 * time.Hour} {
		rh.clock.advance(later)
		rec, out := rh.rotate(old, body)
		wantCode(t, rec, out, http.StatusOK, "")
		if n := len(rh.enrollmentEvents(event.EnrollmentStateRotated)); n != 1 {
			t.Fatalf("%d rotated events after a retry %s later, want 1", n, later)
		}
	}
	if n := len(rh.enrollmentEvents(event.EnrollmentStateRotatedKeyUsed)); n != 0 {
		t.Fatalf("%d rotated_key_used events, want none", n)
	}
}

// The new key is active whether or not the SIEM hears of it, and the agent's retry, which
// raises the event again, can still record it.
func TestRotateSucceedsWhenTheEventCannotBeRecorded(t *testing.T) {
	rh := newRotationServer(t)
	body := rh.body(rh.agent, newKey(t), "software")
	rh.flaky.failIngest = true
	rec, out := rh.rotate(rh.agent, body)
	wantCode(t, rec, out, http.StatusCreated, "")
	id := out["device_id"].(string)
	if logs := rh.logs.String(); !strings.Contains(logs, "level=ERROR") || !strings.Contains(logs, `msg="rotation event not recorded"`) ||
		!strings.Contains(logs, "device_id="+id) || !strings.Contains(logs, "disk full") {
		t.Fatalf("log = %s", logs)
	}
	rh.flaky.failIngest = false
	if n := len(rh.enrollmentEvents(event.EnrollmentStateRotated)); n != 0 {
		t.Fatalf("%d rotated events, want none yet", n)
	}
	rec, out = rh.rotate(rh.agent, body)
	wantCode(t, rec, out, http.StatusOK, "")
	got := rh.enrollmentEvents(event.EnrollmentStateRotated)
	if len(got) != 1 || got[0].Detail["device_id"] != id {
		t.Fatalf("events = %+v, want the rotation to %s", got, id)
	}
}

// answerWatch records when the handler starts its answer.
type answerWatch struct {
	*httptest.ResponseRecorder
	once    sync.Once
	written chan struct{}
}

func (w *answerWatch) WriteHeader(status int) {
	w.once.Do(func() { close(w.written) })
	w.ResponseRecorder.WriteHeader(status)
}

func (w *answerWatch) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.written) })
	return w.ResponseRecorder.Write(b)
}

// The answer names the new device_id, which the event's ID is made from, so the event is
// stored first: a Mac can't then claim that ID with an event of its own.
func TestRotatedEventIsStoredBeforeTheAnswer(t *testing.T) {
	rh := newRotationServer(t)
	held := make(chan context.Context, 1)
	release := make(chan struct{})
	rh.flaky.held, rh.flaky.release = held, release

	body := rh.body(rh.agent, newKey(t), "software")
	req := httptest.NewRequest("POST", rotatePath, bytes.NewReader(body))
	rh.agent.sign(t, req, body)
	w := &answerWatch{ResponseRecorder: httptest.NewRecorder(), written: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		rh.h.ServeHTTP(w, req)
	}()

	var ctx context.Context
	select {
	case ctx = <-held:
	case <-done:
		t.Fatalf("answered %d without storing the rotated event", w.Code)
	case <-time.After(10 * time.Second):
		t.Fatal("the rotated event was never stored")
	}
	select {
	case <-w.written:
		close(release)
		t.Fatal("the answer was written before the rotated event was stored")
	case <-time.After(100 * time.Millisecond):
	}
	// The write outlives the request, but not a database that never answers.
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 10*time.Second {
		t.Errorf("the event was written with deadline %v (set: %v), want at most 10s away", deadline, ok)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler did not finish")
	}
	if w.Code != http.StatusCreated {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	if n := len(rh.enrollmentEvents(event.EnrollmentStateRotated)); n != 1 {
		t.Fatalf("%d rotated events, want 1", n)
	}
}

func TestRotateFromAStaleKeyToAnotherKey(t *testing.T) {
	rh := newRotationServer(t)
	stale := rh.agent
	successor := rh.rotated()
	stale.userAgent = "altiward-agent/0.9.0"
	rec, out := rh.rotate(stale, rh.body(stale, newKey(t), "software"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")

	got := rh.enrollmentEvents(event.EnrollmentStateRotatedKeyUsed)
	if len(got) != 1 {
		t.Fatalf("%d rotated_key_used events, want 1", len(got))
	}
	wantStaleKeyUsed(t, got[0], stale, successor.deviceID, successor.deviceID, "0.9.0")
	if !got[0].Timestamp.Equal(rh.clock.now()) {
		t.Errorf("timestamp = %v, want %v", got[0].Timestamp, rh.clock.now())
	}
	if got := rh.polls(successor); got != http.StatusUnauthorized {
		t.Fatalf("the successor polls with %d, want 401", got)
	}
	if active := rh.activeKeys(); len(active) != 0 {
		t.Fatalf("active keys %v, want none", active)
	}
}

// A stale key's rotation that doesn't even check out is still a stale key's use: 401, and
// a contest once the rotation can no longer be in flight.
func TestStaleKeyWithABadRotationIsAContest(t *testing.T) {
	rh := newRotationServer(t)
	stale := rh.agent
	successor := rh.rotated()
	rh.clock.advance(store.InFlightGrace + time.Second)
	rec, out := rh.rotate(stale, []byte(`{"public_key":`))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")

	got := rh.enrollmentEvents(event.EnrollmentStateRotatedKeyUsed)
	if len(got) != 1 {
		t.Fatalf("%d rotated_key_used events, want 1", len(got))
	}
	wantStaleKeyUsed(t, got[0], stale, successor.deviceID, successor.deviceID, "")
	if got := rh.polls(successor); got != http.StatusUnauthorized {
		t.Fatalf("the successor polls with %d, want 401", got)
	}
}

func TestStaleKeyUseIsAContest(t *testing.T) {
	rh := newRotationServer(t)
	stale := rh.agent
	successor := rh.rotated()
	rh.clock.advance(2 * time.Minute)

	rec, out := stale.post(t, batch(t, "agent-health"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	rec, out = stale.get(t, "/v1/agent/commands")
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")

	got := rh.enrollmentEvents(event.EnrollmentStateRotatedKeyUsed)
	if len(got) != 1 {
		t.Fatalf("%d rotated_key_used events, want 1", len(got))
	}
	wantStaleKeyUsed(t, got[0], stale, successor.deviceID, successor.deviceID, "")
	if got := rh.polls(successor); got != http.StatusUnauthorized {
		t.Fatalf("the successor polls with %d, want 401", got)
	}
	if logs := rh.logs.String(); !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, `msg="rotated device key used"`) ||
		!strings.Contains(logs, "device_id="+stale.deviceID) || !strings.Contains(logs, "revoked_device_id="+successor.deviceID) {
		t.Errorf("log = %s", logs)
	}

	// Within a day, past midnight UTC, further uses report nothing.
	rh.clock.advance(23 * time.Hour)
	rec, out = stale.get(t, "/v1/agent/commands")
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	if n := len(rh.enrollmentEvents(event.EnrollmentStateRotatedKeyUsed)); n != 1 {
		t.Fatalf("%d rotated_key_used events within a day, want 1", n)
	}

	// A day on, one more, revoking nothing.
	rh.clock.advance(time.Hour + time.Second)
	rec, out = stale.post(t, batch(t, "agent-health"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	rec, out = stale.get(t, "/v1/agent/commands")
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	got = rh.enrollmentEvents(event.EnrollmentStateRotatedKeyUsed)
	if len(got) != 2 {
		t.Fatalf("%d rotated_key_used events a day later, want 2", len(got))
	}
	wantStaleKeyUsed(t, got[1], stale, successor.deviceID, "", "")
	if got[0].EventID == got[1].EventID {
		t.Fatalf("both reports have event_id %s", got[0].EventID)
	}
}

func TestInFlightOldKeyRequestRaisesNothing(t *testing.T) {
	rh := newRotationServer(t)
	successor := rh.rotated()
	// Signed at the rotation's own moment, by the Mac's clock, and received 30 seconds on.
	rh.clock.advance(30 * time.Second)
	inFlight := *rh.agent
	inFlight.skew = -30 * time.Second

	rec, out := inFlight.post(t, batch(t, "agent-health"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	rec, out = inFlight.get(t, "/v1/agent/commands")
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")

	if n := len(rh.enrollmentEvents(event.EnrollmentStateRotatedKeyUsed)); n != 0 {
		t.Fatalf("%d rotated_key_used events, want none", n)
	}
	if got := rh.polls(successor); got != http.StatusOK {
		t.Fatalf("the successor polls with %d, want 200", got)
	}
}

func TestConcurrentRotationsRaiseOneStaleKeyEvent(t *testing.T) {
	rh := newRotationServer(t)
	const n = 20
	bodies := make([][]byte, n)
	for i := range bodies {
		bodies[i] = rh.body(rh.agent, newKey(t), "software")
	}
	codes := make([]int, n)
	ids := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			rec, out := rh.agent.postTo(t, rotatePath, bodies[i])
			codes[i] = rec.Code
			ids[i], _ = out["device_id"].(string)
		})
	}
	wg.Wait()

	winner := ""
	for i, code := range codes {
		switch code {
		case http.StatusCreated:
			if winner != "" {
				t.Fatalf("two rotations committed: %s and %s", winner, ids[i])
			}
			winner = ids[i]
		case http.StatusUnauthorized:
		default:
			t.Fatalf("a rotation answered %d", code)
		}
	}
	if winner == "" {
		t.Fatalf("no rotation committed: %v", codes)
	}
	if active := rh.activeKeys(); len(active) != 0 {
		t.Fatalf("active keys %v, want none", active)
	}
	if n := len(rh.enrollmentEvents(event.EnrollmentStateRotated)); n != 1 {
		t.Fatalf("%d rotated events, want 1", n)
	}
	got := rh.enrollmentEvents(event.EnrollmentStateRotatedKeyUsed)
	if len(got) != 1 {
		t.Fatalf("%d rotated_key_used events, want 1", len(got))
	}
	wantStaleKeyUsed(t, got[0], rh.agent, winner, winner, "")
}

func TestRevokedKeyWithoutSuccessorRaisesNothing(t *testing.T) {
	rh := newRotationServer(t)
	rh.revokeFromConsole(rh.agent.deviceID)
	rh.clock.advance(time.Hour)

	rec, out := rh.agent.post(t, batch(t, "agent-health"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	rec, out = rh.agent.get(t, "/v1/agent/commands")
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	rec, out = rh.rotate(rh.agent, rh.body(rh.agent, newKey(t), "software"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	rec, out = rh.rotate(rh.agent, []byte(`{"public_key":`))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")

	for _, state := range []string{event.EnrollmentStateRotated, event.EnrollmentStateRotatedKeyUsed} {
		if n := len(rh.enrollmentEvents(state)); n != 0 {
			t.Fatalf("%d %s events, want none", n, state)
		}
	}
}

// A store that fails the contest still leaves the stale key refused, and says why.
func TestStaleKeyUseWhenTheContestFails(t *testing.T) {
	rh := newRotationServer(t)
	stale := rh.agent
	successor := rh.rotated()
	rh.clock.advance(2 * time.Minute)
	rh.flaky.failStaleKeyUsed = true
	rec, out := stale.get(t, "/v1/agent/commands")
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	if logs := rh.logs.String(); !strings.Contains(logs, "level=ERROR") || !strings.Contains(logs, "device_id="+stale.deviceID) ||
		!strings.Contains(logs, "database unavailable") {
		t.Fatalf("log = %s", logs)
	}
	if got := rh.polls(successor); got != http.StatusOK {
		t.Fatalf("the successor polls with %d, want 200", got)
	}
}

// A client that gives up mid-request doesn't stop the contest its stale key started, but a
// database that never answers still can't hold the handler: the contest gets ten seconds.
func TestStaleKeyContestOutlivesTheRequest(t *testing.T) {
	rh := newRotationServer(t)
	stale := rh.agent
	successor := rh.rotated()
	rh.clock.advance(2 * time.Minute)
	rh.flaky.cancelledStaleKeyUsed = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := batch(t, "agent-health")
	started := time.Now()
	rec, out := stale.send(t, httptest.NewRequest("POST", "/v1/agent/events", bytes.NewReader(body)).WithContext(ctx), body)
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	if strings.Contains(rh.logs.String(), "stale key contest") {
		t.Fatalf("log = %s", rh.logs.String())
	}
	if n := len(rh.enrollmentEvents(event.EnrollmentStateRotatedKeyUsed)); n != 1 {
		t.Fatalf("%d rotated_key_used events, want 1", n)
	}
	if got := rh.polls(successor); got != http.StatusUnauthorized {
		t.Fatalf("the successor polls with %d, want 401", got)
	}
	deadline := rh.flaky.staleKeyDeadline
	if deadline.IsZero() {
		t.Fatal("the contest ran without a deadline")
	}
	if latest := time.Now().Add(10 * time.Second); !deadline.After(started) || deadline.After(latest) {
		t.Fatalf("deadline %v after the request started, want at most 10s", deadline.Sub(started))
	}
}

// The same for a stale key's rotate request: its contest is the store's Rotate.
func TestStaleKeyRotationContestOutlivesTheRequest(t *testing.T) {
	rh := newRotationServer(t)
	stale := rh.agent
	successor := rh.rotated()
	rh.clock.advance(2 * time.Minute)
	rh.flaky.cancelledRotate = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := rh.body(stale, newKey(t), "software")
	started := time.Now()
	rec, out := stale.send(t, httptest.NewRequest("POST", rotatePath, bytes.NewReader(body)).WithContext(ctx), body)
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	if n := len(rh.enrollmentEvents(event.EnrollmentStateRotatedKeyUsed)); n != 1 {
		t.Fatalf("%d rotated_key_used events, want 1", n)
	}
	if got := rh.polls(successor); got != http.StatusUnauthorized {
		t.Fatalf("the successor polls with %d, want 401", got)
	}
	deadline := rh.flaky.rotateDeadline
	if deadline.IsZero() {
		t.Fatal("the rotation ran without a deadline")
	}
	if latest := time.Now().Add(10 * time.Second); !deadline.After(started) || deadline.After(latest) {
		t.Fatalf("deadline %v after the request started, want at most 10s", deadline.Sub(started))
	}
}

// An event ID that a Mac can work out can be taken first by an event of its own, which
// would make the alert a duplicate. The alert's ID is random, so it is stored anyway.
func TestPreclaimedIDsDoNotHideTheAlert(t *testing.T) {
	rh := newRotationServer(t)
	stale := rh.agent
	day := rh.clock.now().UTC().Format("2006-01-02")
	claimed := event.RaisedID("acme/rotated-key-used/" + stale.deviceID + "/" + day)
	var health map[string]any
	if err := json.Unmarshal(testfixture.Raw(t, "agent-health"), &health); err != nil {
		t.Fatal(err)
	}
	health["event_id"] = claimed
	raw, err := json.Marshal(map[string]any{"events": []any{health}})
	if err != nil {
		t.Fatal(err)
	}
	rec, out := stale.post(t, raw)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), claimed) {
		t.Fatalf("pre-claim: %d %v", rec.Code, out)
	}

	successor := rh.rotated()
	rh.clock.advance(2 * time.Minute)
	rec, out = stale.post(t, batch(t, "agent-health"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")

	got := rh.enrollmentEvents(event.EnrollmentStateRotatedKeyUsed)
	if len(got) != 1 {
		t.Fatalf("%d rotated_key_used events, want 1", len(got))
	}
	if got[0].EventID == claimed {
		t.Fatalf("the alert has the pre-claimed ID %s", claimed)
	}
	wantStaleKeyUsed(t, got[0], stale, successor.deviceID, successor.deviceID, "")
}

func TestListEnrollmentsShowsLineage(t *testing.T) {
	rh := newRotationServer(t)
	old := rh.agent
	next := rh.rotated()

	rec, out := do(t, rh.h, "GET", "/v1/enrollments", consoleToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	rows, _ := out["enrollments"].([]any)
	if len(rows) != 2 {
		t.Fatalf("%d enrollments, want the old key and its successor: %s", len(rows), rec.Body)
	}
	for _, r := range rows {
		row := r.(map[string]any)
		switch row["device_id"] {
		case old.deviceID:
			if row["status"] != "revoked" || row["rotated_to"] != next.deviceID || row["rotated_from"] != nil {
				t.Errorf("stale key = %v", row)
			}
		case next.deviceID:
			if row["status"] != "active" || row["rotated_from"] != old.deviceID || row["rotated_to"] != nil {
				t.Errorf("successor = %v", row)
			}
		default:
			t.Errorf("unexpected key %v", row["device_id"])
		}
	}
}

func TestRevokeARotatedKeyNamesTheKeyInUse(t *testing.T) {
	rh := newRotationServer(t)
	old := rh.agent
	next := rh.rotated()
	before, err := rh.store.ListAudit(context.Background(), "acme", store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}

	rec, out := do(t, rh.h, "POST", "/v1/enrollments/"+old.deviceID+"/revoke", consoleToken, nil)
	wantCode(t, rec, out, http.StatusConflict, "credential_rotated")
	if out["current_device_id"] != next.deviceID {
		t.Fatalf("current_device_id = %v, want %s", out["current_device_id"], next.deviceID)
	}
	if got := rh.polls(next); got != http.StatusOK {
		t.Errorf("the key in use polls with %d after the refused revoke", got)
	}
	after, err := rh.store.ListAudit(context.Background(), "acme", store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("%d audit entries, want %d: a refused revoke changes nothing", len(after), len(before))
	}

	// Once the key in use is revoked, the stale key is already revoked: 200, as for any revoke.
	rh.revokeFromConsole(next.deviceID)
	if rec, _ := do(t, rh.h, "POST", "/v1/enrollments/"+old.deviceID+"/revoke", consoleToken, nil); rec.Code != http.StatusOK {
		t.Errorf("revoking the stale key of a revoked lineage: %d %s", rec.Code, rec.Body)
	}
}
