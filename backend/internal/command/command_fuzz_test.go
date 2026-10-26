package command_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Altiward/altiward/backend/internal/command"
)

func FuzzDecodeCommandResult(f *testing.F) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schema", "commands", "command-result.json"))
	if err != nil {
		f.Fatal(err)
	}
	if _, err := command.DecodeResult(raw); err != nil {
		f.Fatalf("invalid command-result fixture: %v", err)
	}
	f.Add(raw)
	for _, seed := range []string{"", "null", "{}", `{"status":"pending"}`, `{"status":"skipped","completed_at":"2026-10-16T09:20:31.250Z"}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 128<<10 {
			t.Skip()
		}
		r, err := command.DecodeResult(raw)
		if err != nil {
			return
		}
		if r.Revoked == nil || r.Failed == nil || r.Skipped == nil {
			t.Fatal("accepted result did not normalise user lists")
		}
		switch r.Status {
		case command.StatusCompleted, command.StatusFailed, command.StatusSkipped:
		default:
			t.Fatal("accepted an unknown or non-terminal result status")
		}
		for _, user := range r.Skipped {
			switch user.Reason {
			case command.SkipPermanentAdmin, command.SkipNotAdmin, command.SkipSessionEnded:
			default:
				t.Fatal("accepted an unknown skip reason")
			}
		}
		if r.CompletedAt.IsZero() || len(r.Revoked)+len(r.Failed)+len(r.Skipped) > 1000 {
			t.Fatal("accepted result violates time or user-count bounds")
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		round, err := command.DecodeResult(encoded)
		if err != nil {
			t.Fatalf("accepted result cannot be decoded after encoding: %v", err)
		}
		again, err := json.Marshal(round)
		if err != nil || !bytes.Equal(encoded, again) {
			t.Fatalf("result normalisation is not stable: %v", err)
		}
		withUnknown := append([]byte(`{"fuzz_unknown_field":true,`), encoded[1:]...)
		if _, err := command.DecodeResult(withUnknown); err == nil {
			t.Fatal("accepted an unknown command-result field")
		}
	})
}
