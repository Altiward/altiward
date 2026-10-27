package release_test

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/Altiward/altiward/backend/internal/release"
)

func TestOldestSupportedAgentMatchesTheFrozenFixtures(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dirs, _ := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "schema", "compat", "agent-*"))
	if len(dirs) == 0 {
		t.Fatal("no frozen agent fixtures")
	}
	versions := make([][2]int, len(dirs))
	for i, d := range dirs {
		if _, err := fmt.Sscanf(filepath.Base(d), "agent-%d.%d", &versions[i][0], &versions[i][1]); err != nil {
			t.Fatalf("%s: want agent-X.Y", d)
		}
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i][0] < versions[j][0] || versions[i][0] == versions[j][0] && versions[i][1] < versions[j][1]
	})
	oldest := fmt.Sprintf("%d.%d", versions[0][0], versions[0][1])
	if oldest != release.OldestSupportedAgent {
		t.Fatalf("oldest frozen fixtures are agent-%s but OldestSupportedAgent is %s: update them together",
			oldest, release.OldestSupportedAgent)
	}
}

func TestAgentSupported(t *testing.T) {
	for v, want := range map[string]bool{
		"1.0.0": true, "1.0.7": true, "1.1.0": true, "2.0.4": true, "1.0": true,
		"0.9.9": false, "0.9": false, "0.10.0": false, "0.0": false,
		"": true, "dev": true, "1.x": true, "1.2.3.4": true, // unreadable: not flagged
	} {
		if got := release.AgentSupported(v); got != want {
			t.Errorf("AgentSupported(%q) = %v, want %v", v, got, want)
		}
	}
}
