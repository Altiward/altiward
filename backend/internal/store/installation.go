package store

import (
	"context"
	"time"
)

// Installation describes this server as a whole, not a tenant.
type Installation struct {
	// CreatedAt is when this server's database was set up.
	CreatedAt time.Time
}

type Installations interface {
	Installation(ctx context.Context) (Installation, error)
}
