package store

import (
	"context"
	"time"

	"github.com/Altiward/altiward/backend/internal/command"
)

// Remote commands.

type CommandFilter struct {
	Serial string
	Status command.Status // empty = any; pending and expired are computed from now
}

type Commands interface {
	// CreateCommand queues c and records a, the console action that asked for it.
	CreateCommand(ctx context.Context, c command.Command, a AuditEntry) error
	// PendingCommands returns the Mac's commands that have no result and have not
	// expired, oldest first, stamping delivered_at on first delivery.
	PendingCommands(ctx context.Context, tenantID, serial string, now time.Time) ([]command.Command, error)
	// RecordCommandResult stores the first result for one of the Mac's commands and
	// returns the command. Later results are ignored. ErrNotFound if the command is
	// not this Mac's.
	RecordCommandResult(ctx context.Context, tenantID, serial, commandID string, r command.Result, receivedAt time.Time) (command.Command, error)
	GetCommand(ctx context.Context, tenantID, commandID string) (command.Command, error)
	// WatchCommands returns a channel that is closed when a command is next queued for
	// the Mac, by this or any other API instance sharing the store, and a function that
	// stops watching. Waking is best effort, and may also happen with nothing queued:
	// callers check for commands again when woken, and wait with a timeout.
	WatchCommands(tenantID, serial string) (<-chan struct{}, func())
	// ListCommands returns the tenant's commands, newest first.
	ListCommands(ctx context.Context, tenantID string, f CommandFilter, now time.Time) ([]command.Command, error)
}
