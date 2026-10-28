package store

import (
	"context"
	"time"
)

// Installation describes this server as a whole, not a tenant.
type Installation struct {
	// CreatedAt is when this server's database was set up.
	CreatedAt time.Time
	// RaisedIDSecret keys the IDs of events the server raises itself, so they are stable
	// for one installation and cannot be forged from outside. 32 bytes, set once.
	RaisedIDSecret []byte `json:"-"`
	// AdminGroupStartedAt is when this installation began keeping the admin group history:
	// readings from before it are covered by the backfill, not by live raising.
	AdminGroupStartedAt time.Time
	// AdminGroupBackfilledAt is when the one-off job that raises the admin-group events
	// for readings stored before the upgrade finished. Nil until it has; history expiry
	// doesn't start before then.
	AdminGroupBackfilledAt *time.Time
}

type Installations interface {
	Installation(ctx context.Context) (Installation, error)
}
