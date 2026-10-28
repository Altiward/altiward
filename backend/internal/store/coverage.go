package store

import (
	"context"
	"time"
)

// CoverageGrace is how long after a start a newly configured SIEM sink counts as covered:
// longer than a rolling update, during which a replica that doesn't have the sink yet can
// still store events without queuing them for it.
const CoverageGrace = time.Hour

// Coverage records, for each SIEM sink, from when it has been sent everything. A sink is
// covered from an hour after the first time a server started with it configured, and from
// earlier once replay-exports has sent it older history. Under the default history period
// nothing received before the latest coverage start is removed, so connecting a SIEM to an
// old database never deletes what the SIEM was not given.
type Coverage interface {
	// RecordSinks notes, at a start, that exactly sinks are configured. Times come from the
	// database's clock (the process clock for the memory store), never the caller's. A sink
	// not yet recorded is covered from now plus CoverageGrace, and one recorded keeps its
	// time. A recorded sink missing from sinks is marked absent from now, unless it is
	// already; one that comes back after being absent has its coverage moved forward to now
	// plus CoverageGrace, since nothing was queued for it in between.
	RecordSinks(ctx context.Context, sinks []string) error
	// SinkCoverage is the latest covered-from time among sinks, or nil when none of them
	// is recorded (including when sinks is empty).
	SinkCoverage(ctx context.Context, sinks []string) (*time.Time, error)
}
