package api

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnrollmentRefusalWarningsAreBoundedAndTenantScoped(t *testing.T) {
	var logs bytes.Buffer
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	s := Server{log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		now: func() time.Time { return now }}
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() { s.logEnrollmentLimit("acme", "MAC", "new_macs_per_hour") })
	}
	wg.Wait()
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Fatalf("concurrent refusals gave %d warnings, want 1", n)
	}
	if n := strings.Count(logs.String(), "level=DEBUG"); n != 99 {
		t.Fatalf("concurrent refusals gave %d debug messages, want 99", n)
	}
	s.logEnrollmentLimit("other", "MAC", "new_macs_per_hour")
	s.logEnrollmentLimit("acme", "MAC", "keys_per_mac_per_day")
	now = now.Add(time.Hour)
	s.logEnrollmentLimit("acme", "ANOTHER-MAC", "new_macs_per_hour")
	s.logEnrollmentLimit("acme", "ANOTHER-MAC", "keys_per_mac_per_day")
	if n := strings.Count(logs.String(), "level=WARN"); n != 4 {
		t.Fatalf("independent tenant, limit and hourly reset gave %d warnings, want 4", n)
	}
	now = now.Add(23 * time.Hour)
	s.logEnrollmentLimit("acme", "MAC", "keys_per_mac_per_day")
	if n := strings.Count(logs.String(), "level=WARN"); n != 5 {
		t.Fatalf("daily reset gave %d warnings, want 5", n)
	}
}
