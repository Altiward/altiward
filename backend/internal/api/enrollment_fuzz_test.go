package api_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func FuzzEnrollmentRequest(f *testing.F) {
	v := testfixture.Signature(f)
	seed := map[string]any{
		"serial":        testfixture.Event(f, "agent-health").Device.Serial,
		"hardware_uuid": "fuzz-hardware",
		"public_key":    base64.StdEncoding.EncodeToString(v.PublicKeySPKI),
		"key_storage":   "software",
	}
	validSeeds := map[string]bool{}
	add := func(valid bool) {
		raw, err := json.Marshal(seed)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
		validSeeds[string(raw)] = valid
	}
	add(true)
	// Older servers deliberately ignore fields and key-storage values from newer agents.
	seed["future_agent_field"] = map[string]any{"nested": true}
	seed["key_storage"] = "future_storage"
	add(true)
	seed["serial"] = strings.Repeat("s", event.MaxNameLength)
	add(true)
	seed["serial"] = strings.Repeat("s", event.MaxNameLength+1)
	add(false)
	seed["serial"] = "fuzz-mac"
	seed["future_agent_field"] = strings.Repeat("x", 64<<10)
	add(false)
	for _, raw := range []string{"", "null", "{}", `{"serial":1}`, `{"serial":"mac","hardware_uuid":"hw","public_key":"%%%"}`} {
		f.Add([]byte(raw))
	}
	tokens, err := auth.Parse("acme="+agentToken, "")
	if err != nil {
		f.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := testfixture.Time(f, "2026-10-26T12:00:00Z")
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 128<<10 {
			t.Skip()
		}
		// A fresh store prevents fuzz iteration order from changing limits or credentials.
		st := store.NewMemory([]string{"fuzz"})
		h := api.New(st, tokens, log, func() time.Time { return now })
		send := func(body []byte) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, "/v1/agent/enroll", bytes.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+agentToken)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			return rec
		}
		rec := send(raw)
		if valid, seed := validSeeds[string(raw)]; seed && valid != (rec.Code == http.StatusCreated) {
			t.Fatalf("enrolment seed acceptance changed: valid=%v, HTTP %d", valid, rec.Code)
		}
		var compact bytes.Buffer
		if json.Compact(&compact, raw) == nil && compact.Len() > 64<<10 && rec.Code != http.StatusBadRequest {
			t.Fatal("accepted an enrolment object larger than the decoder limit")
		}
		creds, err := st.ListCredentials(context.Background(), "acme", store.CredentialFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if rec.Code == http.StatusBadRequest {
			if len(creds) != 0 {
				t.Fatal("rejected enrolment persisted a credential")
			}
			return
		}
		if rec.Code != http.StatusCreated || len(creds) != 1 {
			t.Fatalf("fresh enrolment: HTTP %d, %d credentials: %s", rec.Code, len(creds), rec.Body)
		}
		cred := creds[0]
		if cred.Serial == "" || len(cred.Serial) > event.MaxNameLength || cred.HardwareUUID == "" || len(cred.HardwareUUID) > event.MaxNameLength {
			t.Fatal("accepted enrolment violated device identifier bounds")
		}
		if _, err := auth.ParsePublicKey(cred.PublicKey); err != nil {
			t.Fatalf("accepted enrolment persisted an invalid public key: %v", err)
		}
		if cred.TenantID != "acme" || cred.Token == "" || cred.Status != store.CredentialActive {
			t.Fatal("first enrolment lost its tenant, origin or default active status")
		}
		var reply map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil || reply["device_id"] != cred.DeviceID || reply["status"] != string(cred.Status) {
			t.Fatalf("response did not identify the persisted credential: %v", err)
		}
		retry := send(raw)
		if retry.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), retry.Body.Bytes()) {
			t.Fatalf("retry changed enrolment: HTTP %d: %s", retry.Code, retry.Body)
		}
		creds, err = st.ListCredentials(context.Background(), "acme", store.CredentialFilter{})
		if err != nil || len(creds) != 1 {
			t.Fatalf("retry created another credential: %v", err)
		}
		// Adding a future field must preserve the same key and its recorded storage claim.
		compatible, err := json.Marshal(map[string]any{
			"serial": cred.Serial, "hardware_uuid": cred.HardwareUUID,
			"public_key":  base64.StdEncoding.EncodeToString(cred.PublicKey),
			"key_storage": cred.KeyStorage, "fuzz_future_field": []any{true, "value"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if extra := send(compatible); extra.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), extra.Body.Bytes()) {
			t.Fatalf("future field changed enrolment compatibility: HTTP %d", extra.Code)
		}
		items, err := st.ClaimExports(context.Background(), "fuzz", 10, time.Minute, now)
		if err != nil || len(items) != 1 || items[0].Event.Type != event.AgentEnrollment {
			t.Fatalf("enrolment retries duplicated or lost their export event: %d items, %v", len(items), err)
		}
	})
}

// FuzzRotationRequest sends arbitrary bodies, signed by the current key, to a healthy
// server. Whatever the body: no 5xx, no key is activated unless the body carries a proof
// by it for this device, and the same body again gives the same device_id.
func FuzzRotationRequest(f *testing.F) {
	const deviceID = "0d9e8f7a-6b5c-4d3e-8f2a-1b0c9d8e7f6a"
	oldKey, nextKey := newKey(f), newKey(f)
	oldSPKI, err := x509.MarshalPKIXPublicKey(&oldKey.PublicKey)
	if err != nil {
		f.Fatal(err)
	}
	valid := rotationBody(f, deviceID, nextKey, "software")
	f.Add(valid)
	f.Add(rotationBody(f, "another-device", nextKey, "software")) // a proof for another device
	f.Add(rotationBody(f, deviceID, oldKey, "software"))          // the current key
	f.Add(bytes.Replace(valid, []byte(`"software"`), []byte(`"future_storage","future_field":{"a":[1]}`), 1))
	for _, raw := range []string{"", "null", "{}", `{"public_key":1}`, `{"public_key":"%%%","proof":"%%%"}`} {
		f.Add([]byte(raw))
	}
	tokens, err := auth.Parse("acme="+agentToken, "")
	if err != nil {
		f.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	enrolledAt := testfixture.Time(f, "2026-10-26T12:00:00Z")
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 128<<10 {
			t.Skip()
		}
		// A fresh store, so an earlier iteration's rotation can't change this one's answer.
		st := store.NewMemory(nil)
		clock := &testClock{t: enrolledAt}
		h := api.New(st, tokens, log, clock.now)
		if _, err := st.Enroll(context.Background(), store.DeviceCredential{
			DeviceID: deviceID, TenantID: "acme", Serial: fixtureSerial, HardwareUUID: "fuzz-hardware",
			PublicKey: oldSPKI, KeyStorage: store.KeyStorageSoftware, Token: "fuzz", CreatedAt: enrolledAt,
		}, store.DefaultEnrollLimits()); err != nil {
			t.Fatal(err)
		}
		clock.advance(store.MinRotationInterval)
		mac := &agent{h: h, key: oldKey, deviceID: deviceID, clock: clock}

		rec, _ := mac.postTo(t, rotatePath, raw)
		if rec.Code >= 500 {
			t.Fatalf("HTTP %d: %s", rec.Code, rec.Body)
		}
		if bytes.Equal(raw, valid) && rec.Code != http.StatusCreated {
			t.Fatalf("the valid seed got HTTP %d: %s", rec.Code, rec.Body)
		}
		creds, err := st.ListCredentials(context.Background(), "acme", store.CredentialFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusCreated {
			if len(creds) != 1 || creds[0].DeviceID != deviceID || creds[0].Status != store.CredentialActive {
				t.Fatalf("HTTP %d changed the credentials: %+v", rec.Code, creds)
			}
			return
		}
		if len(creds) != 2 {
			t.Fatalf("HTTP 201 left %d credentials", len(creds))
		}
		// The key that was activated must have signed the statement for this device.
		var req struct {
			PublicKey string `json:"public_key"`
			Proof     string `json:"proof"`
		}
		if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&req); err != nil {
			t.Fatalf("accepted a body that doesn't decode: %v", err)
		}
		spki, err1 := base64.StdEncoding.DecodeString(req.PublicKey)
		proof, err2 := base64.StdEncoding.DecodeString(req.Proof)
		if err1 != nil || err2 != nil || auth.VerifyRotationProof(deviceID, spki, proof) != nil {
			t.Fatalf("activated a key without a valid proof: %s", raw)
		}
		var reply map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil || reply["status"] != "active" {
			t.Fatalf("answer = %s (%v)", rec.Body, err)
		}
		retry, _ := mac.postTo(t, rotatePath, raw)
		var again map[string]string
		if err := json.Unmarshal(retry.Body.Bytes(), &again); err != nil || retry.Code != http.StatusOK || again["device_id"] != reply["device_id"] {
			t.Fatalf("retry: HTTP %d %s, want 200 and device_id %s", retry.Code, retry.Body, reply["device_id"])
		}
		if creds, err = st.ListCredentials(context.Background(), "acme", store.CredentialFilter{}); err != nil || len(creds) != 2 {
			t.Fatalf("the retry changed the credentials: %v", err)
		}
	})
}
