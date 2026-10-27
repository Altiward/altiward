package api

// POST /v1/agent/rotate: a Mac replaces its device key with a new one it proves it holds.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
)

// Codes on a rotation's refusals. The agent keeps its key on all of them: a malformed
// request (rotationInvalid) won't succeed unchanged, and the others say to wait.
// credentialRotated names a key that was rotated away and is used again.
const (
	codeRotationInvalid     = "rotation_invalid"
	codeKeyInUse            = "key_in_use"
	codeRotationNotAllowed  = "rotation_not_allowed"
	codeRotationRateLimited = "rotation_rate_limited"
	codeCredentialRotated   = "credential_rotated"
)

// maxRotateBytes bounds a rotation request. A real one is a few hundred bytes.
const maxRotateBytes = 64 << 10

// rotateRequest is decoded leniently, like enrolment: agents add fields, and older servers
// must ignore them.
type rotateRequest struct {
	PublicKey  string `json:"public_key"`  // base64 SubjectPublicKeyInfo DER of the new key
	KeyStorage string `json:"key_storage"` // as in enrolment; an unknown value is kept as unknown
	Proof      string `json:"proof"`       // base64 DER ECDSA signature by the new key
}

// rotate replaces the key that signed the request with the one in its body. The request is
// authenticated like any other agent request, but the status of the key is the store's
// call: it decides under the Mac's lock, so a retry of a rotation that already happened
// is told so even though the key that signed it is revoked by now.
//
// A key that rotation replaced and that asks for anything else shows a second holder of
// the Mac's identity: the store's contest settles it, and this raises rotated_key_used
// when the contest calls for it.
func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	cred, sr, body, ok := s.authenticateDevice(w, r)
	if !ok {
		return
	}
	req, spki, problem := checkRotationBody(cred, body)
	if problem != "" {
		if cred.Status != store.CredentialRevoked {
			writeCodedError(w, http.StatusBadRequest, codeRotationInvalid, problem)
			return
		}
		// A revoked key is refused for being revoked, whatever it asks. A retry of a real
		// rotation carries the body that worked, so a replaced key sending a bad one is a
		// stale key's use like any other.
		if cred.RotatedTo != "" {
			s.staleKeyUsed(r, cred, sr)
		}
		writeCodedError(w, http.StatusUnauthorized, codeCredentialInvalid, "device credential revoked")
		return
	}
	id, err := store.NewDeviceID()
	if err != nil {
		s.serverError(w, "device id", err)
		return
	}
	now := s.now()
	res, err := s.store.Rotate(r.Context(), store.RotateRequest{
		TenantID: cred.TenantID, FromDeviceID: cred.DeviceID, DeviceID: id, PublicKey: spki,
		KeyStorage: store.ParseKeyStorage(req.KeyStorage), SignedAt: time.Unix(sr.Timestamp, 0), Now: now,
	})
	switch {
	case errors.Is(err, store.ErrRotatedElsewhere), errors.Is(err, store.ErrRevoked), errors.Is(err, store.ErrNotFound):
		// A key that has been rotated away, whoever now holds it, is as dead as a revoked one.
		if res.Contest != nil {
			s.reportStaleKeyUse(r, cred.TenantID, *res.Contest, now)
		}
		writeCodedError(w, http.StatusUnauthorized, codeCredentialInvalid, "device credential revoked")
	case errors.Is(err, store.ErrInvalidState):
		writeCodedError(w, http.StatusForbidden, codeEnrollmentPending, "this enrollment is awaiting approval in the console")
	case errors.Is(err, store.ErrRotationNotAllowed):
		writeCodedError(w, http.StatusConflict, codeRotationNotAllowed, "a key held in the Secure Enclave is not rotated")
	case errors.Is(err, store.ErrKeyInUse):
		writeCodedError(w, http.StatusConflict, codeKeyInUse, "this key is already enrolled; generate a new one")
	case errors.Is(err, store.ErrRotationTooSoon):
		w.Header().Set("Retry-After", strconv.Itoa(rotationRetryAfter(res.Previous, now)))
		writeCodedError(w, http.StatusTooManyRequests, codeRotationRateLimited, "this key was activated less than 24 hours ago; try again later")
	case err != nil:
		s.log.Error("rotate", "tenant", cred.TenantID, "serial", cred.Serial, "device_id", cred.DeviceID, "err", err)
		writeError(w, http.StatusServiceUnavailable, "could not rotate; retry later")
	default:
		// The same request again (a retry) is answered with the rotation's current state.
		// Either way the event goes first: the answer names the successor's device_id,
		// which the event's ID is made from, so the event must be stored before a Mac can
		// claim that ID with one of its own. A retry raises it again, and the store keeps
		// one. A Mac that can't be reported still rotates, and a retry, if one comes, tries again.
		c, status := res.Credential, http.StatusCreated
		if res.Retry {
			status = http.StatusOK
		}
		if err := s.storeRaised(r, c.TenantID, rotationEvent(c.TenantID, res, r.UserAgent(), now), now); err != nil {
			s.log.Error("rotation event not recorded", "tenant", c.TenantID, "serial", c.Serial, "device_id", c.DeviceID, "err", err)
		}
		if !res.Retry {
			s.log.Info("device key rotated", "tenant", c.TenantID, "serial", c.Serial, "device_id", c.DeviceID,
				"from_device_id", cred.DeviceID, "key_storage", c.KeyStorage)
		}
		writeJSON(w, status, map[string]string{"device_id": c.DeviceID, "status": string(c.Status)})
	}
}

// checkRotationBody requires a body that decodes, with a P-256 key that isn't the
// signer's own and a proof by that key for the signer's device ID. It returns the request
// and the new key's DER, or what is wrong with the body.
func checkRotationBody(cred store.DeviceCredential, body []byte) (rotateRequest, []byte, string) {
	var req rotateRequest
	refuse := func(msg string) (rotateRequest, []byte, string) {
		return req, nil, msg
	}
	if len(body) > maxRotateBytes {
		return refuse("body too large")
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&req); err != nil {
		return refuse("body must be {public_key, key_storage, proof}: " + err.Error())
	}
	spki, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err == nil {
		_, err = auth.ParsePublicKey(spki)
	}
	if err != nil {
		return refuse("public_key must be a base64 P-256 SubjectPublicKeyInfo")
	}
	if bytes.Equal(spki, cred.PublicKey) {
		return refuse("public_key is the key that signed this request")
	}
	proof, err := base64.StdEncoding.DecodeString(req.Proof)
	if err == nil {
		err = auth.VerifyRotationProof(cred.DeviceID, spki, proof)
	}
	if err != nil {
		return refuse("proof must be a base64 signature by the new key over the rotation statement")
	}
	return req, spki, ""
}

// rotationRetryAfter is the whole seconds until prev may rotate, rounded up and at least 1.
func rotationRetryAfter(prev store.DeviceCredential, now time.Time) int {
	if prev.ActivatedAt == nil {
		return 1
	}
	left := prev.ActivatedAt.Add(store.MinRotationInterval).Sub(now)
	return max(1, int(math.Ceil(left.Seconds())))
}
