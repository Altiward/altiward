package event_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func FuzzDecodeValidateEvent(f *testing.F) {
	// Include every current example and every frozen supported-agent event.
	for _, pattern := range []string{"examples/*.json", "compat/agent-*/*.json"} {
		paths, err := filepath.Glob(filepath.Join("..", "..", "..", "docs", "schema", pattern))
		if err != nil || len(paths) == 0 {
			f.Fatalf("fixture glob %s: %v (%d files)", pattern, err, len(paths))
		}
		for _, path := range paths {
			raw, err := os.ReadFile(path)
			if err != nil {
				f.Fatal(err)
			}
			e, err := event.Decode(raw)
			if err != nil || e.Validate(e.Timestamp) != nil {
				f.Fatalf("invalid contract fixture %s", path)
			}
			f.Add(raw)
		}
	}
	for _, raw := range []string{"", "null", "{}", `{"schema_version":1,"unexpected":true}`, `{} {}`} {
		f.Add([]byte(raw))
	}
	// A fixed clock gives the future-timestamp check the same meaning on every run.
	now := testfixture.Time(f, "2026-10-26T12:00:00Z")
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 128<<10 {
			t.Skip()
		}
		_ = event.PeekID(raw) // Rejection attribution must also tolerate malformed input.
		e, err := event.Decode(raw)
		if err != nil || e.Validate(now) != nil {
			return
		}
		encoded, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("validated event cannot be encoded: %v", err)
		}
		round, err := event.Decode(encoded)
		if err != nil || round.Validate(now) != nil {
			t.Fatalf("validated event does not survive a wire round-trip: %s (%v)", encoded, err)
		}
		again, err := json.Marshal(round)
		if err != nil || !bytes.Equal(encoded, again) {
			t.Fatalf("event normalisation is not stable: %v", err)
		}
		if e.EventID != event.PeekID(encoded) {
			t.Fatal("rejection attribution changed the accepted event ID")
		}
		// Decode, unlike enrolment, deliberately rejects added contract fields.
		withUnknown := append([]byte(`{"fuzz_unknown_field":true,`), encoded[1:]...)
		if _, err := event.Decode(withUnknown); err == nil {
			t.Fatal("accepted an unknown event field")
		}
		// Validation is stable when repeated at the same instant.
		if err := round.Validate(now); err != nil {
			t.Fatalf("second validation changed the verdict: %v", err)
		}
	})
}
