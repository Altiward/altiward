// Package release holds what the server knows about versions: the oldest agent
// release it still accepts.
package release

import (
	"strconv"
	"strings"
)

// OldestSupportedAgent is the oldest agent minor release the server accepts: the oldest
// directory in docs/schema/compat. Update both together when an agent release ships.
const OldestSupportedAgent = "0.2"

// AgentSupported reports whether an agent version is at least OldestSupportedAgent.
// A version that can't be read counts as supported: nothing to flag with confidence.
func AgentSupported(version string) bool {
	v, ok := minor(version)
	if !ok {
		return true
	}
	oldest, _ := minor(OldestSupportedAgent)
	return v[0] > oldest[0] || v[0] == oldest[0] && v[1] >= oldest[1]
}

// minor reads the major and minor numbers of "X.Y" or "X.Y.Z".
func minor(version string) ([2]int, bool) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return [2]int{}, false
	}
	var out [2]int
	for i := range out {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return [2]int{}, false
		}
		out[i] = n
	}
	return out, true
}
