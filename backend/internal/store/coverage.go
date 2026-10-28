package store

import (
	"context"
	"time"
)

// Coverage records, for each SIEM sink, from when it has been sent everything. A sink is
// covered from the first time a server started with it configured, and from earlier once
// replay-exports has sent it older history. Under the default history period nothing
// received before the latest coverage start is removed, so connecting a SIEM to an old
// database never deletes what the SIEM was not given.
type Coverage interface {
	// RecordSinks notes that sinks are configured as of now: each one not yet recorded is
	// covered from now, and one already recorded keeps its time.
	RecordSinks(ctx context.Context, sinks []string, now time.Time) error
	// SinkCoverage is the latest covered-from time among sinks, or nil when none of them
	// is recorded (including when sinks is empty).
	SinkCoverage(ctx context.Context, sinks []string) (*time.Time, error)
}
