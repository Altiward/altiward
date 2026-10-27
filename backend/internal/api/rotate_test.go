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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
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
	failRotate, failCredential bool
}

func (f *flakyStore) Rotate(ctx context.Context, r store.RotateRequest) (store.RotateResult, error) {
	if f.failRotate {
		return store.RotateResult{}, errors.New("database unavailable")
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
	mem := store.NewMemory(nil)
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
