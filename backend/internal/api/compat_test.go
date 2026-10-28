package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
)

// TestOlderAgentsStillReport posts the events each supported agent release sends, frozen
// in docs/schema/compat, and requires every one to be accepted: sites upgrade the server
// first and roll agents out later, so the server accepts every supported agent minor release.
func TestOlderAgentsStillReport(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "schema", "compat")
	releases, err := filepath.Glob(filepath.Join(root, "agent-*"))
	if err != nil || len(releases) == 0 {
		t.Fatalf("no frozen agent fixtures in %s (%v)", root, err)
	}
	if len(releases) > 2 {
		t.Errorf("%d frozen agent releases; keep the newest two (docs/schema/compat/README.md)", len(releases))
	}
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range releases {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
			sort.Strings(files)
			raws := []json.RawMessage{}
			// The server's clock is serverNow, or the newest event's time if that is later,
			// so an event frozen with a later timestamp isn't refused as from the future.
			clock := &testClock{t: serverNow(t)}
			for _, f := range files {
				b, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				var e struct {
					Timestamp time.Time `json:"timestamp"`
				}
				if err := json.Unmarshal(b, &e); err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				if e.Timestamp.After(clock.now()) {
					clock.set(e.Timestamp)
				}
				raws = append(raws, b)
			}
			body, _ := json.Marshal(map[string]any{"events": raws})
			h := api.New(store.NewMemory(nil), tokens, slog.New(slog.NewTextHandler(io.Discard, nil)), clock.now)
			rec, out := enrollAs(t, &agent{h: h, key: newKey(t), clock: clock}, fixtureSerial).post(t, body)
			accepted, _ := out["accepted"].([]any)
			if rec.Code != 200 || len(accepted) != len(files) {
				t.Fatalf("%d of %d accepted: %d %s", len(accepted), len(files), rec.Code, rec.Body)
			}
		})
	}
}
