package api

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// The server logs at Info, so a refusal it doesn't warn about isn't logged at all: the next
// warning says how many there were.
func TestEnrollmentRefusalWarningsAreBoundedAndCountTheRest(t *testing.T) {
	var logs bytes.Buffer
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	s := Server{log: slog.New(slog.NewTextHandler(&logs, nil)), now: func() time.Time { return now }}
	lines := func() []string {
		defer logs.Reset()
		return strings.Split(strings.TrimSpace(logs.String()), "\n")
	}

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() { s.logEnrollmentLimit("acme", "MAC", "new_macs_per_hour", time.Hour) })
	}
	wg.Wait()
	if got := lines(); len(got) != 1 || !strings.Contains(got[0], "level=WARN") || !strings.Contains(got[0], "not_logged=0") {
		t.Fatalf("100 concurrent refusals logged %q, want one warning", got)
	}

	// Each tenant and limit has its own window.
	s.logEnrollmentLimit("other", "MAC", "new_macs_per_hour", time.Hour)
	s.logEnrollmentLimit("acme", "MAC", "keys_per_mac_per_day", 24*time.Hour)
	if got := lines(); len(got) != 2 {
		t.Fatalf("another tenant and another limit logged %q, want a warning each", got)
	}

	now = now.Add(time.Hour)
	s.logEnrollmentLimit("acme", "ANOTHER-MAC", "new_macs_per_hour", time.Hour)
	s.logEnrollmentLimit("acme", "ANOTHER-MAC", "keys_per_mac_per_day", 24*time.Hour)
	if got := lines(); len(got) != 1 || !strings.Contains(got[0], "serial=ANOTHER-MAC") ||
		!strings.Contains(got[0], "limit=new_macs_per_hour") || !strings.Contains(got[0], "not_logged=99") {
		t.Fatalf("an hour on logged %q, want the hourly limit's warning counting the 99 before it", got)
	}

	now = now.Add(23 * time.Hour)
	s.logEnrollmentLimit("acme", "MAC", "keys_per_mac_per_day", 24*time.Hour)
	if got := lines(); len(got) != 1 || !strings.Contains(got[0], "limit=keys_per_mac_per_day") || !strings.Contains(got[0], "not_logged=1") {
		t.Fatalf("a day on logged %q, want the daily limit's warning counting the one before it", got)
	}
}
