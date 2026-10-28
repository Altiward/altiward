package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
)

// IngestResponse mirrors IngestResponse in the Swift agent. Every event in the request
// appears in exactly one list; the agent deletes all three from its queue, except a
// rejection with a Code that it acts on (see RejectDeviceMismatch).
type IngestResponse struct {
	Accepted  []string    `json:"accepted"`
	Duplicate []string    `json:"duplicate"`
	Rejected  []Rejection `json:"rejected"`
}

// RejectDeviceMismatch is the Code of a rejection because the event names another serial
// than the one the signing credential was enrolled with. An agent whose own events get it
// has the wrong key (such as a store copied from another Mac): it keeps them, drops the
// key and enrols again. Events naming another Mac are stale, and it deletes those.
const RejectDeviceMismatch = "device_mismatch"

type Rejection struct {
	EventID string `json:"event_id"`
	Error   string `json:"error"`
	// Code is set only where an agent does something other than delete the event.
	Code string `json:"code,omitempty"`
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	var body struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "body must be {\"events\": [...]}: "+err.Error())
		return
	}
	if len(body.Events) > MaxBatchEvents {
		writeError(w, http.StatusRequestEntityTooLarge, "at most "+strconv.Itoa(MaxBatchEvents)+" events per batch")
		return
	}

	now := s.now()
	resp := IngestResponse{Accepted: []string{}, Duplicate: []string{}, Rejected: []Rejection{}}
	valid := make([]event.Event, 0, len(body.Events))
	seen := map[string]bool{}
	for _, raw := range body.Events {
		e, err := event.Decode(raw)
		if err == nil {
			err = e.Validate(now)
		}
		if err == nil && e.Type.IsServerRaised() {
			err = errors.New(string(e.Type) + " is raised only by the server")
		}
		code := ""
		if err == nil && e.Device.Serial != p.Serial {
			err = errors.New("device.serial does not match the sending device")
			code = RejectDeviceMismatch
		}
		if err == nil && seen[e.EventID] {
			resp.Duplicate = append(resp.Duplicate, e.EventID)
			continue
		}
		if err != nil {
			resp.Rejected = append(resp.Rejected, Rejection{EventID: event.PeekID(raw), Error: err.Error(), Code: code})
			continue
		}
		seen[e.EventID] = true
		valid = append(valid, e)
	}

	res, err := s.store.Ingest(r.Context(), p.TenantID, valid, now)
	if err != nil {
		// Nothing was stored; the agent keeps the batch and retries.
		if errors.Is(err, store.ErrSessionOwnerConflict) {
			s.log.Warn("session ownership conflict", "tenant", p.TenantID, "device", p.Serial, "err", err)
			writeError(w, http.StatusConflict, "session ownership conflicts with this device or account; no events were stored")
			return
		}
		s.log.Error("ingest failed", "tenant", p.TenantID, "events", len(valid), "err", err)
		writeError(w, http.StatusServiceUnavailable, "could not store events; retry later")
		return
	}
	resp.Accepted = append(resp.Accepted, res.Accepted...)
	resp.Duplicate = append(resp.Duplicate, res.Duplicate...)
	// The IDs of events the server raises derive from the installation's secret, so one
	// already stored as something else was forged. The server's event wasn't stored; the
	// Mac's events were, and are acknowledged.
	for _, id := range res.RaisedIDTaken {
		s.log.Error("raised event ID already taken", "tenant", p.TenantID, "device", p.Serial, "event_id", id)
	}
	if len(resp.Rejected) > 0 {
		s.log.Warn("rejected events", "tenant", p.TenantID, "device", p.Serial, "count", len(resp.Rejected), "first", resp.Rejected[0].Error)
	}
	writeJSON(w, http.StatusOK, resp)
}
