// Package command defines remote commands for the agent and their results,
// matching the wire format in docs/schema/commands.
package command

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const TypeRevokeAdmin = "revoke_admin"

// Lifetime is how long a command waits for its Mac before it expires undelivered.
const Lifetime = 24 * time.Hour

type Status string

const (
	StatusPending   Status = "pending"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusSkipped   Status = "skipped"
	StatusExpired   Status = "expired"
)

// Reasons a user was skipped.
const (
	SkipPermanentAdmin = "permanent_admin"
	SkipNotAdmin       = "not_admin"
	SkipSessionEnded   = "session_ended"
)

// Command is one instruction for one Mac.
type Command struct {
	CommandID   string     `json:"command_id"`
	TenantID    string     `json:"tenant_id"`
	Serial      string     `json:"serial"`
	Type        string     `json:"type"`
	User        *string    `json:"user"`       // nil: every admin except permanent admins
	SessionID   *string    `json:"session_id"` // set: act only while this session is open
	IssuedBy    string     `json:"issued_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	DeliveredAt *time.Time `json:"delivered_at"`
	ResultAt    *time.Time `json:"result_at"` // when the server received the result
	Result      *Result    `json:"result"`
}

// Status is the result's status, or pending/expired while there is none.
func (c Command) Status(now time.Time) Status {
	switch {
	case c.Result != nil:
		return c.Result.Status
	case now.After(c.ExpiresAt):
		return StatusExpired
	}
	return StatusPending
}

// Result is what the agent reports after running a command.
type Result struct {
	Status      Status      `json:"status"`
	Error       *string     `json:"error"`
	Revoked     []string    `json:"revoked"`
	Failed      []UserError `json:"failed"`
	Skipped     []UserSkip  `json:"skipped"`
	CompletedAt time.Time   `json:"completed_at"`
}

type UserError struct {
	User  string `json:"user"`
	Error string `json:"error"`
}

type UserSkip struct {
	User   string `json:"user"`
	Reason string `json:"reason"`
}

// DecodeResult parses a result strictly and validates it.
func DecodeResult(raw []byte) (Result, error) {
	var r Result
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Result{}, fmt.Errorf("decode: %w", err)
	}
	switch r.Status {
	case StatusCompleted, StatusFailed, StatusSkipped:
	default:
		return Result{}, fmt.Errorf("status must be completed, failed or skipped, not %q", r.Status)
	}
	for _, s := range r.Skipped {
		switch s.Reason {
		case SkipPermanentAdmin, SkipNotAdmin, SkipSessionEnded:
		default:
			return Result{}, fmt.Errorf("unknown skip reason %q", s.Reason)
		}
	}
	if r.CompletedAt.IsZero() {
		return Result{}, errors.New("completed_at is required")
	}
	if len(r.Revoked)+len(r.Failed)+len(r.Skipped) > 1000 {
		return Result{}, errors.New("too many users in result")
	}
	if r.Revoked == nil {
		r.Revoked = []string{}
	}
	if r.Failed == nil {
		r.Failed = []UserError{}
	}
	if r.Skipped == nil {
		r.Skipped = []UserSkip{}
	}
	return r, nil
}

// AgentView is a command as the agent receives it.
type AgentView struct {
	CommandID string    `json:"command_id"`
	Type      string    `json:"type"`
	User      *string   `json:"user"`
	SessionID *string   `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AgentList is the body of GET /v1/agent/commands.
func AgentList(cmds []Command) map[string][]AgentView {
	out := make([]AgentView, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, AgentView{CommandID: c.CommandID, Type: c.Type, User: c.User, SessionID: c.SessionID, ExpiresAt: c.ExpiresAt.UTC()})
	}
	return map[string][]AgentView{"commands": out}
}
