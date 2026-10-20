package main

import (
	"testing"
	"time"
)

func TestParseSince(t *testing.T) {
	for in, want := range map[string]time.Time{
		"2026-10-01":                time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		"2026-10-01T09:30:00Z":      time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC),
		"2026-10-01T09:30:00+01:00": time.Date(2026, 10, 1, 8, 30, 0, 0, time.UTC),
	} {
		got, err := parseSince(in)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseSince(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "yesterday", "01/10/2026"} {
		if _, err := parseSince(in); err == nil {
			t.Errorf("parseSince(%q) accepted", in)
		}
	}
}
