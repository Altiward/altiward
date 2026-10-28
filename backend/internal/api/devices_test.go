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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// fixtureSerial is the device serial in docs/schema/examples.
const fixtureSerial = "C02XK0AAJGH5"

// agent is a fake Mac: it enrolls with the enrollment token, then signs requests.
type agent struct {
	h        http.Handler
	key      *ecdsa.PrivateKey
	deviceID string
	status   string
	skew     time.Duration // added to the server's clock when signing
	// clock, when set, is the server's clock; without it the server's clock is serverNow.
	clock *testClock

	// What the Mac says when it enrols. Left empty, the hardware UUID is "HW-" and the
	// serial, and the key storage and User-Agent are left out.
	hardwareUUID, keyStorage, userAgent string
	// ctx, when set, is the context of the enrol request.
	ctx context.Context
}

func enrollAgent(t *testing.T, h http.Handler, serial string) *agent {
	t.Helper()
	return enrollAs(t, &agent{h: h, key: newKey(t)}, serial)
}

// enrollAs enrols a, which must say what it needs to before enrolling, and fails the test
// unless the server accepts it.
func enrollAs(t *testing.T, a *agent, serial string) *agent {
	t.Helper()
	rec, out := a.enroll(t, serial)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	a.deviceID, a.status = out["device_id"].(string), out["status"].(string)
	return a
}

func (a *agent) enroll(t *testing.T, serial string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&a.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"serial": serial, "hardware_uuid": "HW-" + serial, "public_key": base64.StdEncoding.EncodeToString(spki),
	}
	if a.hardwareUUID != "" {
		body["hardware_uuid"] = a.hardwareUUID
	}
	if a.keyStorage != "" {
		body["key_storage"] = a.keyStorage
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/agent/enroll", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+agentToken)
	if a.userAgent != "" {
		req.Header.Set("User-Agent", a.userAgent)
	}
	if a.ctx != nil {
		req = req.WithContext(a.ctx)
	}
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func (a *agent) post(t *testing.T, body []byte) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	return a.send(t, httptest.NewRequest("POST", "/v1/agent/events", bytes.NewReader(body)), body)
}

// send signs req over body and serves it. The test server's clock is serverNow.
func (a *agent) send(t *testing.T, req *http.Request, body []byte) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	a.sign(t, req, body)
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

// sign sets the headers of a request signed by a over body at the clock's time plus its
// skew, and its User-Agent when it has one.
func (a *agent) sign(t *testing.T, req *http.Request, body []byte) {
	t.Helper()
	now := serverNow(t)
	if a.clock != nil {
		now = a.clock.now()
	}
	ts := now.Add(a.skew).Unix()
	digest := sha256.Sum256([]byte(auth.CanonicalString(req.Method, req.URL.RequestURI(), ts, body)))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "AltiwardDevice "+a.deviceID)
	req.Header.Set("X-Altiward-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Altiward-Signature", base64.StdEncoding.EncodeToString(sig))
	if a.userAgent != "" {
		req.Header.Set("User-Agent", a.userAgent)
	}
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serverNow(t *testing.T) time.Time { return testfixture.Time(t, "2026-10-16T12:00:00Z") }

func wantCode(t *testing.T, rec *httptest.ResponseRecorder, out map[string]any, status int, code string) {
	t.Helper()
	if rec.Code != status || (code != "" && out["code"] != code) {
		t.Fatalf("got %d %s, want %d code %q", rec.Code, rec.Body, status, code)
	}
}

func TestEnrollmentIsActiveAndRetrySafe(t *testing.T) {
	h := newServer(t)
	a := enrollAgent(t, h, fixtureSerial)
	if a.status != "active" {
		t.Fatalf("status = %s", a.status)
	}
	rec, out := a.enroll(t, fixtureSerial)
	if rec.Code != http.StatusOK || out["device_id"] != a.deviceID {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body)
	}
}

func TestEnrollRecordsKeyStorage(t *testing.T) {
	h := newServer(t)
	cases := []struct {
		name string
		sent any // nil leaves the field out, as agents before 0.2.0 do
		want string
	}{
		{"secure enclave", "secure_enclave", "secure_enclave"},
		{"software", "software", "software"},
		{"agent before 0.2.0", nil, ""},
		{"a value this server doesn't know", "tpm", ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serial := fmt.Sprintf("C02KEY%d", i)
			key := newKey(t)
			spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			body := map[string]any{
				"serial": serial, "hardware_uuid": "HW-" + serial, "public_key": base64.StdEncoding.EncodeToString(spki),
				// Agents add fields; the server must keep accepting ones it doesn't know.
				"added_by_a_later_agent": true,
			}
			if tc.sent != nil {
				body["key_storage"] = tc.sent
			}
			if rec, _ := do(t, h, "POST", "/v1/agent/enroll", agentToken, body); rec.Code != http.StatusCreated {
				t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
			}
			rec, out := do(t, h, "GET", "/v1/enrollments?serial="+serial, consoleToken, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("list: %d %s", rec.Code, rec.Body)
			}
			list, _ := out["enrollments"].([]any)
			if len(list) != 1 || list[0].(map[string]any)["key_storage"] != tc.want {
				t.Fatalf("enrollments = %v, want key_storage %q", list, tc.want)
			}
		})
	}
}

func TestEnrollValidation(t *testing.T) {
	h := newServer(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	cases := map[string]map[string]any{
		"no serial":   {"hardware_uuid": "HW", "public_key": base64.StdEncoding.EncodeToString(der)},
		"bad key":     {"serial": "S", "hardware_uuid": "HW", "public_key": "bm90IGEga2V5"},
		"P-384 key":   {"serial": "S", "hardware_uuid": "HW", "public_key": base64.StdEncoding.EncodeToString(der)},
		"no hardware": {"serial": "S", "public_key": base64.StdEncoding.EncodeToString(der)},
	}
	for name, body := range cases {
		if rec, _ := do(t, h, "POST", "/v1/agent/enroll", agentToken, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestSignedRequestFailures(t *testing.T) {
	h := newServer(t)
	a := enrollAgent(t, h, fixtureSerial)
	body := batch(t, "elevation-granted")

	t.Run("bearer enrollment token no longer ingests", func(t *testing.T) {
		rec, out := do(t, h, "POST", "/v1/agent/events", agentToken, body)
		wantCode(t, rec, out, http.StatusUnauthorized, "")
	})
	t.Run("signature over a different body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/agent/events", bytes.NewReader(body))
		rec, out := a.send(t, req, []byte(`{"events":[]}`))
		wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	})
	t.Run("unknown device", func(t *testing.T) {
		stranger := &agent{h: h, key: newKey(t), deviceID: "0d9e8f7a-6b5c-4d3e-8f2a-1b0c9d8e7f6a"}
		rec, out := stranger.post(t, body)
		wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	})
	t.Run("someone else's device ID", func(t *testing.T) {
		impostor := &agent{h: h, key: newKey(t), deviceID: a.deviceID}
		rec, out := impostor.post(t, body)
		wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	})
	t.Run("clock skew reports server time", func(t *testing.T) {
		late := *a
		late.skew = -6 * time.Minute
		rec, out := late.post(t, body)
		wantCode(t, rec, out, http.StatusUnauthorized, "clock_skew")
		if got := rec.Header().Get("Date"); got != serverNow(t).UTC().Format(http.TimeFormat) {
			t.Fatalf("Date = %q", got)
		}
	})
	t.Run("within skew is fine", func(t *testing.T) {
		early := *a
		early.skew = 4 * time.Minute
		rec, out := early.post(t, body)
		wantCode(t, rec, out, http.StatusOK, "")
	})
}

func TestEventsMustComeFromTheirOwnDevice(t *testing.T) {
	h := newServer(t)
	a := enrollAgent(t, h, "SOMEONE-ELSE")
	rec, out := a.post(t, batch(t, "elevation-granted"))
	if rec.Code != 200 || len(out["rejected"].([]any)) != 1 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// An agent keeps the events a mismatch names as its own Mac's, so only that rejection
// carries a code; any other reason for rejecting an event doesn't.
func TestIngestMarksEventsFromAnotherMac(t *testing.T) {
	h := newServer(t)
	a := enrollAgent(t, h, "SOMEONE-ELSE")
	bad := strings.Replace(string(testfixture.Raw(t, "elevation-revoked")), `"schema_version": 1`, `"schema_version": 9`, 1)
	body, _ := json.Marshal(map[string]any{"events": []json.RawMessage{
		testfixture.Raw(t, "elevation-granted"), // names fixtureSerial, not this Mac's
		json.RawMessage(bad),
	}})
	rec, out := a.post(t, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rejected := out["rejected"].([]any)
	if len(rejected) != 2 {
		t.Fatalf("rejected = %v", rejected)
	}
	mismatch, invalid := rejected[0].(map[string]any), rejected[1].(map[string]any)
	if mismatch["code"] != "device_mismatch" {
		t.Fatalf("serial mismatch rejection = %v", mismatch)
	}
	if _, ok := invalid["code"]; ok || !strings.Contains(invalid["error"].(string), "schema_version") {
		t.Fatalf("invalid event rejection = %v", invalid)
	}
}

func TestReenrollmentReplacesOnlyAfterExplicitOptOut(t *testing.T) {
	h := newServer(t)
	if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"reenrollment_requires_approval": false}); rec.Code != http.StatusOK {
		t.Fatalf("opt-out: %d %s", rec.Code, rec.Body)
	}
	old := enrollAgent(t, h, fixtureSerial)
	reinstalled := enrollAgent(t, h, fixtureSerial)
	if reinstalled.status != "active" {
		t.Fatalf("status = %s", reinstalled.status)
	}
	rec, out := old.post(t, batch(t, "elevation-granted"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	rec, out = reinstalled.post(t, batch(t, "elevation-granted"))
	wantCode(t, rec, out, http.StatusOK, "")
}

func TestReenrollmentApprovalFlow(t *testing.T) {
	h := newServer(t)
	rec, out := do(t, h, "GET", "/v1/settings", consoleToken, nil)
	if rec.Code != 200 || out["reenrollment_requires_approval"] != true {
		t.Fatalf("default settings: %d %s", rec.Code, rec.Body)
	}
	old := enrollAgent(t, h, fixtureSerial)
	pending := enrollAgent(t, h, fixtureSerial)
	if pending.status != "pending" {
		t.Fatalf("status = %s", pending.status)
	}
	if rec, out := pending.enroll(t, fixtureSerial); rec.Code != http.StatusOK || out["device_id"] != pending.deviceID || out["status"] != "pending" {
		t.Fatalf("pending retry: %d %s", rec.Code, rec.Body)
	}
	rec, out = pending.post(t, batch(t, "elevation-granted"))
	wantCode(t, rec, out, http.StatusForbidden, "enrollment_pending")
	rec, out = old.post(t, batch(t, "elevation-granted"))
	wantCode(t, rec, out, http.StatusOK, "")

	rec, out = do(t, h, "GET", "/v1/enrollments?status=pending", consoleToken, nil)
	list := out["enrollments"].([]any)
	if rec.Code != 200 || len(list) != 1 || list[0].(map[string]any)["device_id"] != pending.deviceID {
		t.Fatalf("pending list: %d %s", rec.Code, rec.Body)
	}
	if _, has := list[0].(map[string]any)["public_key"]; !has {
		t.Fatal("list should show the public key so an admin can compare it")
	}
	// It names the token that enrolled the key, so an admin can find the keys a leaked token made.
	if got := list[0].(map[string]any)["token"]; got != agentTokenActor() {
		t.Fatalf("token = %v, want %s", got, agentTokenActor())
	}

	if rec, _ := do(t, h, "POST", "/v1/enrollments/"+pending.deviceID+"/approve", otherConsole, nil); rec.Code != 404 {
		t.Fatalf("other tenant approve: %d", rec.Code)
	}
	rec, out = do(t, h, "POST", "/v1/enrollments/"+pending.deviceID+"/approve", consoleToken, nil)
	if rec.Code != 200 || out["status"] != "active" {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := do(t, h, "POST", "/v1/enrollments/"+pending.deviceID+"/approve", consoleToken, nil); rec.Code != http.StatusConflict {
		t.Fatalf("second approve: %d", rec.Code)
	}
	rec, out = pending.post(t, batch(t, "elevation-revoked"))
	wantCode(t, rec, out, http.StatusOK, "")
	rec, out = old.post(t, batch(t, "elevation-revoked"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
}

func TestRevokeCredential(t *testing.T) {
	h := newServer(t)
	a := enrollAgent(t, h, fixtureSerial)
	rec, out := do(t, h, "POST", "/v1/enrollments/"+a.deviceID+"/revoke", consoleToken, nil)
	if rec.Code != 200 || out["status"] != "revoked" {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	rec, out = a.post(t, batch(t, "elevation-granted"))
	wantCode(t, rec, out, http.StatusUnauthorized, "credential_invalid")
	if rec, _ := do(t, h, "POST", "/v1/enrollments/not-a-uuid/revoke", consoleToken, nil); rec.Code != 404 {
		t.Fatalf("bad id: %d", rec.Code)
	}
}

// revokeEntry is the audit entry of the tenant's newest revoke_enrollment.
func revokeEntry(t *testing.T, h http.Handler) map[string]any {
	t.Helper()
	_, out := do(t, h, "GET", "/v1/audit", consoleToken, nil)
	for _, e := range out["entries"].([]any) {
		if m := e.(map[string]any); m["action"] == "revoke_enrollment" {
			return m
		}
	}
	t.Fatalf("no revoke_enrollment entry in %v", out)
	return nil
}

func TestRevokeEnrollmentAuditRecordsWhatItEnds(t *testing.T) {
	h := newServer(t)
	a := enrollAgent(t, h, fixtureSerial)
	if rec, _ := a.post(t, batch(t, "elevation-granted", "agent-health")); rec.Code != 200 {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := do(t, h, "POST", "/v1/enrollments/"+a.deviceID+"/revoke", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	detail := revokeEntry(t, h)["detail"].(map[string]any)
	if detail["serial"] != fixtureSerial || detail["open_sessions"] != 1.0 || detail["failing_checks"] != true || detail["retired"] != true {
		t.Fatalf("detail = %v, want 1 open session, a failing check and retired", detail)
	}
	_, out := do(t, h, "GET", "/v1/devices", consoleToken, nil)
	devices := out["devices"].([]any)
	if len(devices) != 1 || devices[0].(map[string]any)["retired_at"] == nil || devices[0].(map[string]any)["serial"] != fixtureSerial {
		t.Fatalf("devices = %v, want the Mac flat with retired_at", devices)
	}
}

func TestRevokeEnrollmentAuditOmitsWhatIsNotThere(t *testing.T) {
	h := newServer(t)
	a := enrollAgent(t, h, fixtureSerial)
	if rec, _ := a.post(t, batch(t, "elevation-granted", "elevation-revoked")); rec.Code != 200 {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := do(t, h, "POST", "/v1/enrollments/"+a.deviceID+"/revoke", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	detail := revokeEntry(t, h)["detail"].(map[string]any)
	if _, has := detail["open_sessions"]; has {
		t.Fatalf("detail = %v, want no open_sessions", detail)
	}
	if _, has := detail["failing_checks"]; has {
		t.Fatalf("detail = %v, want no failing_checks", detail)
	}
}

// newServerWithQueue is newServer with its store and one SIEM sink exposed, so a test can
// read the events the server queued for export.
func newServerWithQueue(t *testing.T) (http.Handler, *store.Memory) {
	t.Helper()
	st := store.NewMemory([]string{"splunk"})
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken+",other="+otherConsole)
	if err != nil {
		t.Fatal(err)
	}
	now := serverNow(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.New(st, tokens, log, func() time.Time { return now }), st
}

// queuedEnrollments returns the agent.enrollment events queued for export, oldest first.
func queuedEnrollments(t *testing.T, st store.Store) []event.Event {
	t.Helper()
	queued, err := st.ClaimExports(context.Background(), "splunk", 100, 0, serverNow(t))
	if err != nil {
		t.Fatal(err)
	}
	out := []event.Event{}
	for _, item := range queued {
		if item.Event.Type == event.AgentEnrollment {
			e := item.Event.Event
			if err := e.Validate(serverNow(t)); err != nil {
				t.Fatalf("invalid agent.enrollment event %s: %v", e.EventID, err)
			}
			out = append(out, e)
		}
	}
	return out
}

// publicKeyFingerprint is how the test says what the event's key_fingerprint should be:
// the lower-case hex SHA-256 of the key's SubjectPublicKeyInfo DER.
func publicKeyFingerprint(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	return fmt.Sprintf("%x", sum)
}

// agentTokenActor is the audit name of the agent enrolment token: "token:" and the first
// 8 hex digits of its SHA-256.
func agentTokenActor() string {
	sum := sha256.Sum256([]byte(agentToken))
	return fmt.Sprintf("token:%x", sum[:4])
}

func TestEnrollRaisesEnrolledEvent(t *testing.T) {
	h, st := newServerWithQueue(t)
	a := enrollAs(t, &agent{h: h, key: newKey(t), keyStorage: "secure_enclave", userAgent: "altiward-agent/0.8.0"}, fixtureSerial)

	got := queuedEnrollments(t, st)
	if len(got) != 1 {
		t.Fatalf("%d agent.enrollment events queued, want 1", len(got))
	}
	e := got[0]
	if want := event.RaisedID("acme/enrollment/" + a.deviceID); e.EventID != want {
		t.Errorf("event_id = %s, want %s", e.EventID, want)
	}
	if !e.Timestamp.Equal(serverNow(t)) || e.SessionID != nil || e.User != nil || e.Elevation != nil || e.Delayed {
		t.Errorf("event = %+v", e)
	}
	wantDevice := event.Device{Serial: fixtureSerial, HardwareUUID: "HW-" + fixtureSerial, OSVersion: "", AgentVersion: "0.8.0"}
	if e.Device != wantDevice {
		t.Errorf("device = %+v, want %+v", e.Device, wantDevice)
	}
	wantDetail := map[string]any{
		"state":           "enrolled",
		"device_id":       a.deviceID,
		"key_fingerprint": publicKeyFingerprint(t, a.key),
		"key_storage":     "secure_enclave",
		"token":           agentTokenActor(),
	}
	if !reflect.DeepEqual(e.Detail, wantDetail) {
		t.Errorf("detail = %v, want %v", e.Detail, wantDetail)
	}
}

func TestReenrollRaisesPendingWithPrevious(t *testing.T) {
	h, st := newServerWithQueue(t)
	first := enrollAs(t, &agent{h: h, key: newKey(t), hardwareUUID: "HW-FIRST", keyStorage: "software"}, fixtureSerial)
	second := enrollAs(t, &agent{h: h, key: newKey(t), hardwareUUID: "HW-OTHER", keyStorage: "secure_enclave"}, fixtureSerial)
	if second.status != "pending" {
		t.Fatalf("status = %s", second.status)
	}

	got := queuedEnrollments(t, st)
	if len(got) != 2 {
		t.Fatalf("%d agent.enrollment events queued, want 2", len(got))
	}
	if got[0].Detail["state"] != "enrolled" || got[0].Detail["device_id"] != first.deviceID {
		t.Errorf("first event = %v", got[0].Detail)
	}
	e := got[1]
	if e.Device.HardwareUUID != "HW-OTHER" || e.Device.AgentVersion != "" {
		t.Errorf("device = %+v, want the new key's hardware UUID and no agent version", e.Device)
	}
	wantDetail := map[string]any{
		"state":                 "pending",
		"device_id":             second.deviceID,
		"key_fingerprint":       publicKeyFingerprint(t, second.key),
		"key_storage":           "secure_enclave",
		"token":                 agentTokenActor(),
		"previous_device_id":    first.deviceID,
		"previous_key_storage":  "software",
		"hardware_uuid_matches": false,
	}
	if !reflect.DeepEqual(e.Detail, wantDetail) {
		t.Errorf("detail = %v, want %v", e.Detail, wantDetail)
	}
}

func TestReenrollRaisesReplaced(t *testing.T) {
	h, st := newServerWithQueue(t)
	if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"reenrollment_requires_approval": false}); rec.Code != http.StatusOK {
		t.Fatalf("opt-out: %d %s", rec.Code, rec.Body)
	}
	first := enrollAs(t, &agent{h: h, key: newKey(t), keyStorage: "software"}, fixtureSerial)
	second := enrollAs(t, &agent{h: h, key: newKey(t), keyStorage: "secure_enclave"}, fixtureSerial)
	if second.status != "active" {
		t.Fatalf("status = %s", second.status)
	}

	got := queuedEnrollments(t, st)
	if len(got) != 2 {
		t.Fatalf("%d agent.enrollment events queued, want 2", len(got))
	}
	wantDetail := map[string]any{
		"state":                 "replaced",
		"device_id":             second.deviceID,
		"key_fingerprint":       publicKeyFingerprint(t, second.key),
		"key_storage":           "secure_enclave",
		"token":                 agentTokenActor(),
		"previous_device_id":    first.deviceID,
		"previous_key_storage":  "software",
		"hardware_uuid_matches": true,
	}
	if !reflect.DeepEqual(got[1].Detail, wantDetail) {
		t.Errorf("detail = %v, want %v", got[1].Detail, wantDetail)
	}
}

func TestEnrollRetryRaisesNothingNew(t *testing.T) {
	h, st := newServerWithQueue(t)
	first := enrollAs(t, &agent{h: h, key: newKey(t)}, fixtureSerial)
	if rec, _ := first.enroll(t, fixtureSerial); rec.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body)
	}
	if got := queuedEnrollments(t, st); len(got) != 1 {
		t.Fatalf("%d events after retrying a first enrolment, want 1", len(got))
	}

	pending := enrollAs(t, &agent{h: h, key: newKey(t)}, fixtureSerial)
	if rec, _ := pending.enroll(t, fixtureSerial); rec.Code != http.StatusOK {
		t.Fatalf("pending retry: %d %s", rec.Code, rec.Body)
	}
	got := queuedEnrollments(t, st)
	if len(got) != 2 || got[1].Detail["state"] != "pending" {
		t.Fatalf("%d events after retrying a pending enrolment, want the first and one pending", len(got))
	}
}

// What the server can't say is left out of the event, not sent empty.
func TestEnrollmentEventOmitsWhatItDoesNotKnow(t *testing.T) {
	h, st := newServerWithQueue(t)
	first := enrollAs(t, &agent{h: h, key: newKey(t), userAgent: "curl/8.7.1"}, fixtureSerial) // no key storage, not an Altiward agent
	if rec, _ := do(t, h, "POST", "/v1/enrollments/"+first.deviceID+"/revoke", consoleToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	// Nothing is active now, so the next key waits for approval with no key to compare to.
	second := enrollAs(t, &agent{h: h, key: newKey(t)}, fixtureSerial)
	if second.status != "pending" {
		t.Fatalf("status = %s", second.status)
	}

	got := queuedEnrollments(t, st)
	if len(got) != 2 {
		t.Fatalf("%d agent.enrollment events queued, want 2", len(got))
	}
	for i, e := range got {
		if e.Device.AgentVersion != "" {
			t.Errorf("event %d agent_version = %q, want none", i, e.Device.AgentVersion)
		}
		if _, has := e.Detail["key_storage"]; has {
			t.Errorf("event %d detail has key_storage: %v", i, e.Detail)
		}
	}
	wantDetail := map[string]any{
		"state":           "pending",
		"device_id":       second.deviceID,
		"key_fingerprint": publicKeyFingerprint(t, second.key),
		"token":           agentTokenActor(),
	}
	if !reflect.DeepEqual(got[1].Detail, wantDetail) {
		t.Errorf("detail = %v, want %v", got[1].Detail, wantDetail)
	}
}

// The version comes from the User-Agent the agent sets, "altiward-agent/<version>"; anything
// else is not taken as a version, because the header is the caller's to write.
func TestEnrollmentEventAgentVersion(t *testing.T) {
	for _, c := range []struct{ name, userAgent, want string }{
		{"release", "altiward-agent/0.8.0", "0.8.0"},
		{"pre-release", "altiward-agent/0.8.0-rc.1", "0.8.0-rc.1"},
		{"no header", "", ""},
		{"no version", "altiward-agent/", ""},
		{"no slash", "altiward-agent", ""},
		{"extra words", "altiward-agent/0.8.0 (extra)", ""},
		{"control character", "altiward-agent/0.8.0\tx", ""},
		{"another client", "curl/8.7.1", ""},
		{"not at the start", "Mozilla/5.0 altiward-agent/1", ""},
		{"too long", "altiward-agent/" + strings.Repeat("9", 300), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, st := newServerWithQueue(t)
			enrollAs(t, &agent{h: h, key: newKey(t), userAgent: c.userAgent}, fixtureSerial)
			got := queuedEnrollments(t, st)
			if len(got) != 1 {
				t.Fatalf("%d agent.enrollment events queued, want 1", len(got))
			}
			if got[0].Device.AgentVersion != c.want {
				t.Fatalf("agent_version = %q, want %q", got[0].Device.AgentVersion, c.want)
			}
		})
	}
}

// failingIngest stands in for a store that can't record the event.
type failingIngest struct{ store.Store }

func (failingIngest) Ingest(context.Context, string, []event.Event, time.Time) (store.IngestResult, error) {
	return store.IngestResult{}, errors.New("disk full")
}

// The Mac is enrolled whether or not the SIEM hears of it: the credential is already stored,
// and the agent can't retry its way to a second chance at an event.
func TestEnrollSucceedsWhenTheEventCannotBeRecorded(t *testing.T) {
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	if err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, nil))
	now := serverNow(t)
	h := api.New(failingIngest{store.NewMemory(nil)}, tokens, log, func() time.Time { return now })

	a := enrollAgent(t, h, fixtureSerial)
	if a.status != "active" || a.deviceID == "" {
		t.Fatalf("enrolled as %q %q", a.deviceID, a.status)
	}
	if out := logs.String(); !strings.Contains(out, "level=ERROR") || !strings.Contains(out, `msg="enrollment event not recorded"`) ||
		!strings.Contains(out, "tenant=acme") || !strings.Contains(out, "serial="+fixtureSerial) ||
		!strings.Contains(out, "device_id="+a.deviceID) || !strings.Contains(out, "disk full") {
		t.Fatalf("log = %s", out)
	}
}

// cancelAfterEnroll cancels the request once the credential is stored, as a client that
// gives up at that moment would, and fails an Ingest whose context is cancelled, as a real
// store does.
type cancelAfterEnroll struct {
	store.Store
	cancel context.CancelFunc
}

func (c cancelAfterEnroll) Enroll(ctx context.Context, cred store.DeviceCredential, limits store.EnrollLimits) (store.EnrollResult, error) {
	res, err := c.Store.Enroll(ctx, cred, limits)
	c.cancel()
	return res, err
}

func (c cancelAfterEnroll) Ingest(ctx context.Context, tenantID string, events []event.Event, receivedAt time.Time) (store.IngestResult, error) {
	if err := ctx.Err(); err != nil {
		return store.IngestResult{}, err
	}
	return c.Store.Ingest(ctx, tenantID, events, receivedAt)
}

// The agent's retry of a stored key raises nothing, so an enrolment whose request is
// cancelled after the credential is stored must still be reported.
func TestEnrollEventIsRecordedWhenTheRequestIsCancelled(t *testing.T) {
	st := store.NewMemory([]string{"splunk"})
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	if err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	now := serverNow(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := api.New(cancelAfterEnroll{st, cancel}, tokens, slog.New(slog.NewTextHandler(&logs, nil)), func() time.Time { return now })

	a := enrollAs(t, &agent{h: h, key: newKey(t), ctx: ctx}, fixtureSerial)
	if ctx.Err() == nil {
		t.Fatal("the request was not cancelled, so the test proves nothing")
	}
	got := queuedEnrollments(t, st)
	if len(got) != 1 || got[0].Detail["device_id"] != a.deviceID || got[0].Detail["state"] != "enrolled" {
		t.Fatalf("events = %+v, want the enrolment of %s", got, a.deviceID)
	}
	if strings.Contains(logs.String(), "enrollment event not recorded") {
		t.Fatalf("log = %s", logs.String())
	}
}

// deadlineIngest records the deadline of the context each Ingest is given.
type deadlineIngest struct {
	store.Store
	deadlines chan<- time.Time
}

func (d deadlineIngest) Ingest(ctx context.Context, tenantID string, events []event.Event, receivedAt time.Time) (store.IngestResult, error) {
	deadline, _ := ctx.Deadline() // zero without one
	d.deadlines <- deadline
	return d.Store.Ingest(ctx, tenantID, events, receivedAt)
}

// The enrolment event outlives the request, but not a database that never answers: its
// write gets ten seconds.
func TestEnrollEventWriteHasADeadline(t *testing.T) {
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	if err != nil {
		t.Fatal(err)
	}
	now := serverNow(t)
	deadlines := make(chan time.Time, 1)
	h := api.New(deadlineIngest{store.NewMemory(nil), deadlines}, tokens, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() time.Time { return now })

	started := time.Now()
	enrollAgent(t, h, fixtureSerial)
	deadline := <-deadlines
	if deadline.IsZero() {
		t.Fatal("the enrolment event was written without a deadline")
	}
	if latest := time.Now().Add(10 * time.Second); !deadline.After(started) || deadline.After(latest) {
		t.Fatalf("deadline %v after the request started, want at most 10s from the write", deadline.Sub(started))
	}
}

// newLimitedServer is a server with options, its store with one SIEM sink, and its log.
func newLimitedServer(t *testing.T, opts ...api.Option) (http.Handler, *store.Memory, *strings.Builder) {
	t.Helper()
	st := store.NewMemory([]string{"splunk"})
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken+",other="+otherConsole)
	if err != nil {
		t.Fatal(err)
	}
	logs := &strings.Builder{}
	now := serverNow(t)
	return api.New(st, tokens, slog.New(slog.NewTextHandler(logs, nil)), func() time.Time { return now }, opts...), st, logs
}

// wantRateLimited fails the test unless rec refuses an enrolment as the agent expects to
// read it: 429 with the code it backs off on and the seconds to wait.
func wantRateLimited(t *testing.T, rec *httptest.ResponseRecorder, out map[string]any) {
	t.Helper()
	wantCode(t, rec, out, http.StatusTooManyRequests, "enrollment_rate_limited")
	if got := rec.Header().Get("Retry-After"); got != "3600" {
		t.Errorf("Retry-After = %q, want 3600", got)
	}
	if msg, _ := out["error"].(string); msg == "" {
		t.Errorf("body = %s, want an error message", rec.Body)
	}
}

func TestEnrollRateLimitedAnswers429(t *testing.T) {
	t.Run("new Macs per hour", func(t *testing.T) {
		h, st, logs := newLimitedServer(t, api.WithEnrollLimits(store.EnrollLimits{NewMacsPerHour: 1}))
		first := enrollAgent(t, h, fixtureSerial)
		refused := &agent{h: h, key: newKey(t)}
		rec, out := refused.enroll(t, "C02SECOND")
		wantRateLimited(t, rec, out)
		// A second refusal in the same hour isn't logged on its own.
		rec, out = (&agent{h: h, key: newKey(t)}).enroll(t, "C02THIRD")
		wantRateLimited(t, rec, out)

		if logged := logs.String(); !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, `msg="enrolment rate limited"`) ||
			!strings.Contains(logged, "tenant=acme") || !strings.Contains(logged, "serial=C02SECOND") ||
			!strings.Contains(logged, "limit=new_macs_per_hour") || strings.Count(logged, "rate limited") != 1 {
			t.Errorf("log = %s", logged)
		}
		// Nothing was stored or reported for the refused Mac, and the enrolled one carries on.
		if got := queuedEnrollments(t, st); len(got) != 1 || got[0].Detail["device_id"] != first.deviceID {
			t.Errorf("events = %+v, want only the first Mac's enrolment", got)
		}
		if rec, out := do(t, h, "GET", "/v1/enrollments?serial=C02SECOND", consoleToken, nil); rec.Code != http.StatusOK || len(out["enrollments"].([]any)) != 0 {
			t.Errorf("enrollments for the refused Mac: %d %s", rec.Code, rec.Body)
		}
		if rec, _ := first.enroll(t, fixtureSerial); rec.Code != http.StatusOK {
			t.Errorf("the first Mac's retry: %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("keys per Mac per day", func(t *testing.T) {
		h, st, logs := newLimitedServer(t, api.WithEnrollLimits(store.EnrollLimits{KeysPerMacPerDay: 2}))
		enrollAgent(t, h, fixtureSerial)
		second := enrollAgent(t, h, fixtureSerial)
		rec, out := (&agent{h: h, key: newKey(t)}).enroll(t, fixtureSerial)
		wantRateLimited(t, rec, out)
		rec, out = (&agent{h: h, key: newKey(t)}).enroll(t, fixtureSerial)
		wantRateLimited(t, rec, out)

		if logged := logs.String(); !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, "serial="+fixtureSerial) ||
			!strings.Contains(logged, "limit=keys_per_mac_per_day") || strings.Count(logged, "rate limited") != 1 {
			t.Errorf("log = %s", logged)
		}
		if got := queuedEnrollments(t, st); len(got) != 2 {
			t.Errorf("%d agent.enrollment events, want the two that enrolled", len(got))
		}
		// Another Mac of the same tenant, and a retry of a key that is already in, are fine.
		enrollAgent(t, h, "C02OTHER")
		if rec, _ := second.enroll(t, fixtureSerial); rec.Code != http.StatusOK {
			t.Errorf("a retry at the limit: %d %s", rec.Code, rec.Body)
		}
	})
}

// A server started without the option still limits, at the defaults: 1000 new Macs an hour
// and 5 keys for one Mac a day.
func TestEnrollLimitsApplyByDefault(t *testing.T) {
	h := newServer(t)
	var last *agent
	for i := 0; i < 5; i++ {
		last = enrollAgent(t, h, fixtureSerial)
	}
	rec, out := (&agent{h: h, key: newKey(t)}).enroll(t, fixtureSerial)
	wantRateLimited(t, rec, out)
	if rec, _ := last.enroll(t, fixtureSerial); rec.Code != http.StatusOK {
		t.Fatalf("a retry at the limit: %d %s", rec.Code, rec.Body)
	}
}

func TestEnrollLimitsCanBeTurnedOff(t *testing.T) {
	h, _, _ := newLimitedServer(t, api.WithEnrollLimits(store.EnrollLimits{}))
	for i := 0; i < 8; i++ {
		enrollAgent(t, h, fixtureSerial)
	}
}

// A key from different hardware waits for approval even when the tenant has turned
// approval off, and the event says the hardware differed.
func TestNewHardwareUUIDWaitsEvenWithApprovalOff(t *testing.T) {
	h, st, _ := newLimitedServer(t)
	if rec, _ := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"reenrollment_requires_approval": false}); rec.Code != http.StatusOK {
		t.Fatalf("opt-out: %d %s", rec.Code, rec.Body)
	}
	first := enrollAs(t, &agent{h: h, key: newKey(t), hardwareUUID: "HW-ORIGINAL"}, fixtureSerial)
	other := enrollAs(t, &agent{h: h, key: newKey(t), hardwareUUID: "HW-SOMEONE-ELSE"}, fixtureSerial)
	if other.status != "pending" {
		t.Fatalf("status = %s, want pending", other.status)
	}
	rec, out := other.post(t, batch(t, "elevation-granted"))
	wantCode(t, rec, out, http.StatusForbidden, "enrollment_pending")
	rec, out = first.post(t, batch(t, "elevation-granted"))
	wantCode(t, rec, out, http.StatusOK, "")

	got := queuedEnrollments(t, st)
	if len(got) != 2 || got[1].Detail["state"] != "pending" || got[1].Detail["hardware_uuid_matches"] != false {
		t.Fatalf("events = %+v, want a pending enrolment that does not match the hardware", got)
	}

	// The same hardware replaces the key, as the tenant chose.
	same := enrollAs(t, &agent{h: h, key: newKey(t), hardwareUUID: "HW-ORIGINAL"}, fixtureSerial)
	if same.status != "active" {
		t.Fatalf("same hardware status = %s, want active", same.status)
	}
}
