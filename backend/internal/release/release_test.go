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
		"1.1.0": true, "1.1.7": true, "1.2.0": true, "2.0.4": true, "1.1": true,
		"1.0.9": false, "1.0": false, "0.11.0": false, "0.0": false,
		"": true, "dev": true, "1.x": true, "1.2.3.4": true, // unreadable: not flagged
	} {
		if got := release.AgentSupported(v); got != want {
			t.Errorf("AgentSupported(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestAgentSupportedReadsPreReleases(t *testing.T) {
	for v, want := range map[string]bool{
		"1.1.0-rc.1": true, "1.0.0-rc.4": false, "1.2.0+build.7": true,
		"1.0-rc.1": false, // a pre-release of 1.0: read, and too old
		"1.0.x":    true,  // unreadable: not flagged
	} {
		if got := release.AgentSupported(v); got != want {
			t.Errorf("AgentSupported(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestAgentAtLeast(t *testing.T) {
	for v, want := range map[string]bool{
		"1.2.0": true, "1.2": true, "1.10.0": true, "2.0.0": true, "1.2.0-rc.4": true,
		"1.1.0": false, "1.1.9": false, "0.12.0": false, "1.1.0-rc.1": false,
		"": true, "dev": true, "1.x": true, // unreadable: counts as new enough
	} {
		if got := release.AgentAtLeast(v, "1.2"); got != want {
			t.Errorf("AgentAtLeast(%q, 1.2) = %v, want %v", v, got, want)
		}
	}
}

func TestNewerAgent(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"1.2.0", "1.1.0", true}, {"1.1.0", "1.2.0", false}, {"1.2.0", "1.2.0", false},
		{"1.2.1", "1.2.0", true}, {"1.10.0", "1.9.9", true}, {"1.2.0", "1.2.0-rc.4", true},
		{"1.2.0-rc.4", "1.2.0", false}, {"1.2.0-rc.4", "1.1.0", true},
		{"1.2.0", "", true}, {"1.2.0", "dev", true}, {"dev", "1.0.0", false}, {"", "", false},
		// Numeric pre-release parts compare as numbers, and fewer parts come first.
		{"1.2.0-rc.10", "1.2.0-rc.9", true}, {"1.2.0-rc.9", "1.2.0-rc.10", false},
		{"1.2.0-rc.1.1", "1.2.0-rc.1", true}, {"1.2.0-rc", "1.2.0-1", true}, {"1.2.0-beta", "1.2.0-alpha", true},
		// Versions that read the same are ordered by their text, so either order agrees.
		{"1.2.0+b", "1.2.0+a", true}, {"1.2.0+a", "1.2.0+b", false}, {"01.2.0", "1.2.0", false}, {"1.2.0", "01.2.0", true},
	} {
		if got := release.NewerAgent(c.a, c.b); got != c.want {
			t.Errorf("NewerAgent(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
