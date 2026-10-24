package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
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
}

func enrollAgent(t *testing.T, h http.Handler, serial string) *agent {
	t.Helper()
	a := &agent{h: h, key: newKey(t)}
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
	return do(t, a.h, "POST", "/v1/agent/enroll", agentToken, map[string]any{
		"serial": serial, "hardware_uuid": "HW-" + serial, "public_key": base64.StdEncoding.EncodeToString(spki),
	})
}

func (a *agent) post(t *testing.T, body []byte) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	return a.send(t, httptest.NewRequest("POST", "/v1/agent/events", bytes.NewReader(body)), body)
}

// send signs req over body and serves it. The test server's clock is serverNow.
func (a *agent) send(t *testing.T, req *http.Request, body []byte) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	ts := serverNow(t).Add(a.skew).Unix()
	digest := sha256.Sum256([]byte(auth.CanonicalString(req.Method, req.URL.RequestURI(), ts, body)))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "AltiwardDevice "+a.deviceID)
	req.Header.Set("X-Altiward-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Altiward-Signature", base64.StdEncoding.EncodeToString(sig))
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
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

func TestReenrollmentReplacesByDefault(t *testing.T) {
	h := newServer(t)
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
	if rec.Code != 200 || out["reenrollment_requires_approval"] != false {
		t.Fatalf("default settings: %d %s", rec.Code, rec.Body)
	}
	rec, _ = do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"reenrollment_requires_approval": true})
	if rec.Code != 200 {
		t.Fatalf("put settings: %d %s", rec.Code, rec.Body)
	}

	old := enrollAgent(t, h, fixtureSerial)
	pending := enrollAgent(t, h, fixtureSerial)
	if pending.status != "pending" {
		t.Fatalf("status = %s", pending.status)
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
