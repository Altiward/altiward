package api

// Fleet inventory, device enrollment and signed agent requests.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
)

// Codes on agent-facing errors. The agent re-enrolls on credentialInvalid, waits on
// enrollmentPending and corrects its clock from the Date header on clockSkew. It treats
// enrollmentRateLimited, like any other refusal to enrol, as a reason to try again later.
const (
	codeCredentialInvalid     = "credential_invalid"
	codeEnrollmentPending     = "enrollment_pending"
	codeClockSkew             = "clock_skew"
	codeEnrollmentRateLimited = "enrollment_rate_limited"
)

// enrollRetryAfter is the seconds a refused enrolment is told to wait. The shortest limit
// counts over an hour.
const enrollRetryAfter = "3600"

// enrollEventTimeout bounds the write of an enrolment's event, which doesn't stop when the
// request does.
const enrollEventTimeout = 10 * time.Second

// requireDevice authenticates a request signed by an enrolled Mac and hands the
// handler a principal carrying its tenant, device ID and serial.
func (s *Server) requireDevice(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sr, ok := auth.ParseSignedRequest(r)
		if !ok {
			writeCodedError(w, http.StatusUnauthorized, codeCredentialInvalid, "missing or malformed device signature")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		cred, err := s.store.Credential(r.Context(), sr.DeviceID)
		if errors.Is(err, store.ErrNotFound) {
			writeCodedError(w, http.StatusUnauthorized, codeCredentialInvalid, "unknown device credential")
			return
		}
		if err != nil {
			s.log.Error("credential lookup", "err", err)
			writeError(w, http.StatusServiceUnavailable, "could not check credential; retry later")
			return
		}
		key, err := auth.ParsePublicKey(cred.PublicKey)
		if err == nil {
			err = auth.Verify(key, auth.CanonicalString(r.Method, r.URL.RequestURI(), sr.Timestamp, body), sr.Signature)
		}
		if err != nil {
			writeCodedError(w, http.StatusUnauthorized, codeCredentialInvalid, "signature does not verify")
			return
		}
		now := s.now()
		if skew := time.Unix(sr.Timestamp, 0).Sub(now); skew > auth.MaxClockSkew || skew < -auth.MaxClockSkew {
			w.Header().Set("Date", now.UTC().Format(http.TimeFormat))
			writeCodedError(w, http.StatusUnauthorized, codeClockSkew, "request timestamp is more than 5 minutes from server time")
			return
		}
		switch cred.Status {
		case store.CredentialPending:
			writeCodedError(w, http.StatusForbidden, codeEnrollmentPending, "this enrollment is awaiting approval in the console")
			return
		case store.CredentialRevoked:
			writeCodedError(w, http.StatusUnauthorized, codeCredentialInvalid, "device credential revoked")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h(w, r, auth.Principal{TenantID: cred.TenantID, Role: auth.RoleAgent, DeviceID: cred.DeviceID, Serial: cred.Serial})
	})
}

// enrollRequest is decoded leniently: agents add fields, and older servers must ignore
// them (agent 0.2.0 added key_storage).
type enrollRequest struct {
	Serial       string `json:"serial"`
	HardwareUUID string `json:"hardware_uuid"`
	PublicKey    string `json:"public_key"`  // base64 SubjectPublicKeyInfo DER
	KeyStorage   string `json:"key_storage"` // "secure_enclave" or "software"; absent before agent 0.2.0
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	var req enrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be {serial, hardware_uuid, public_key}: "+err.Error())
		return
	}
	if req.Serial == "" || req.HardwareUUID == "" || len(req.Serial) > event.MaxNameLength || len(req.HardwareUUID) > event.MaxNameLength {
		writeError(w, http.StatusBadRequest, "serial and hardware_uuid are required (at most 255 bytes)")
		return
	}
	spki, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err == nil {
		_, err = auth.ParsePublicKey(spki)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "public_key must be a base64 P-256 SubjectPublicKeyInfo")
		return
	}
	id, err := store.NewDeviceID()
	if err != nil {
		s.serverError(w, "device id", err)
		return
	}
	now := s.now()
	res, err := s.store.Enroll(r.Context(), store.DeviceCredential{
		DeviceID: id, TenantID: p.TenantID, Serial: req.Serial, HardwareUUID: req.HardwareUUID,
		PublicKey: spki, KeyStorage: store.ParseKeyStorage(req.KeyStorage), CreatedAt: now,
	}, s.enrollLimits)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "this key is enrolled elsewhere; generate a new one")
		return
	}
	if errors.Is(err, store.ErrRateLimited) {
		limit, window, msg := "keys_per_mac_per_day", store.KeysPerMacWindow, "too many keys have been enrolled for this Mac in the last 24 hours; try again later"
		if errors.Is(err, store.ErrNewMacsLimited) {
			limit, window, msg = "new_macs_per_hour", store.NewMacsWindow, "too many new Macs have been enrolled in the last hour; try again later"
		}
		s.logEnrollmentLimit(p.TenantID, req.Serial, limit, window)
		w.Header().Set("Retry-After", enrollRetryAfter)
		writeCodedError(w, http.StatusTooManyRequests, codeEnrollmentRateLimited, msg)
		return
	}
	if err != nil {
		s.log.Error("enroll", "tenant", p.TenantID, "serial", req.Serial, "err", err)
		writeError(w, http.StatusServiceUnavailable, "could not enroll; retry later")
		return
	}
	c := res.Credential
	status := http.StatusOK // the same key again: a retry, which raises nothing
	if c.DeviceID == id {
		status = http.StatusCreated
		// The credential is stored either way; a Mac that can't be reported still enrols. The
		// agent's retry gets the stored credential and raises nothing, so a client that gives
		// up now must not stop the event being stored. A database that doesn't answer still
		// mustn't hold the handler, so the write gets enrollEventTimeout.
		e := enrollmentEvent(p.TenantID, res, r.UserAgent(), p.Actor, now)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), enrollEventTimeout)
		_, err := s.store.Ingest(ctx, p.TenantID, []event.Event{e}, now)
		cancel()
		if err != nil {
			s.log.Error("enrollment event not recorded", "tenant", p.TenantID, "serial", c.Serial, "device_id", c.DeviceID, "err", err)
		}
		s.log.Info("device enrolled", "tenant", p.TenantID, "serial", c.Serial, "device_id", c.DeviceID,
			"state", e.Detail["state"], "key_storage", c.KeyStorage)
	}
	writeJSON(w, status, map[string]string{"device_id": c.DeviceID, "status": string(c.Status)})
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	f := store.CredentialFilter{Status: store.CredentialStatus(r.URL.Query().Get("status")), Serial: r.URL.Query().Get("serial")}
	switch f.Status {
	case "", store.CredentialActive, store.CredentialPending, store.CredentialRevoked:
	default:
		writeError(w, http.StatusBadRequest, "status must be active, pending or revoked")
		return
	}
	creds, err := s.store.ListCredentials(r.Context(), p.TenantID, f)
	if err != nil {
		s.serverError(w, "list enrollments", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrollments": creds})
}

func (s *Server) approveEnrollment(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	a, ok := s.enrollmentAudit(w, r, p, store.AuditApproveEnrollment)
	if !ok {
		return
	}
	c, err := s.store.ApproveCredential(r.Context(), p.TenantID, r.PathValue("id"), s.now(), a)
	s.credentialResult(w, "approve enrollment", c, err)
	if err == nil {
		s.log.Info("device enrollment approved", "tenant", p.TenantID, "serial", c.Serial, "device_id", c.DeviceID)
	}
}

func (s *Server) revokeEnrollment(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	a, ok := s.enrollmentAudit(w, r, p, store.AuditRevokeEnrollment)
	if !ok {
		return
	}
	c, err := s.store.RevokeCredential(r.Context(), p.TenantID, r.PathValue("id"), s.now(), a)
	s.credentialResult(w, "revoke enrollment", c, err)
	if err == nil {
		s.log.Info("device credential revoked", "tenant", p.TenantID, "serial", c.Serial, "device_id", c.DeviceID)
	}
}

// enrollmentAudit starts the audit entry for a change to the credential in the path,
// naming its Mac when the credential is the tenant's. The store call reports a missing one.
func (s *Server) enrollmentAudit(w http.ResponseWriter, r *http.Request, p auth.Principal, action string) (store.AuditEntry, bool) {
	deviceID := r.PathValue("id")
	detail := map[string]any{}
	if c, err := s.store.Credential(r.Context(), deviceID); err == nil && c.TenantID == p.TenantID {
		detail["serial"] = c.Serial
	}
	a, err := s.auditEntry(p, action, deviceID, detail)
	if err != nil {
		s.serverError(w, "audit entry", err)
		return a, false
	}
	return a, true
}

func (s *Server) credentialResult(w http.ResponseWriter, what string, c store.DeviceCredential, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "enrollment not found")
	case errors.Is(err, store.ErrInvalidState):
		writeError(w, http.StatusConflict, "only a pending enrollment can be approved")
	case err != nil:
		s.serverError(w, what, err)
	default:
		writeJSON(w, http.StatusOK, c)
	}
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	devices, err := s.store.ListDevices(r.Context(), p.TenantID)
	if err != nil {
		s.serverError(w, "list devices", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}
