// Package release holds what the server knows about versions: the oldest agent
// release it still accepts.
package release

import (
	"strconv"
	"strings"
)

// OldestSupportedAgent is the oldest agent minor release the server accepts: the oldest
// directory in docs/schema/compat. Update both together when an agent release ships.
const OldestSupportedAgent = "1.0"

// AgentSupported reports whether an agent version is at least OldestSupportedAgent.
// A version that can't be read counts as supported: nothing to flag with confidence.
func AgentSupported(version string) bool { return AgentAtLeast(version, OldestSupportedAgent) }

// AgentAtLeast reports whether an agent version is at least the minor release oldest
// ("X.Y"). A version that can't be read counts as new enough, as in AgentSupported.
func AgentAtLeast(version, oldest string) bool {
	v, ok := parse(version)
	if !ok {
		return true
	}
	o, _ := parse(oldest)
	return v.major > o.major || v.major == o.major && v.minor >= o.minor
}

// NewerAgent reports whether agent version a is newer than b. A version that can't be read
// is never newer, and any readable version is newer than one that can't be read. A release
// is newer than its own pre-releases.
func NewerAgent(a, b string) bool {
	va, ok := parse(a)
	if !ok {
		return false
	}
	vb, ok := parse(b)
	if !ok {
		return true
	}
	for _, d := range [][2]int{{va.major, vb.major}, {va.minor, vb.minor}, {va.patch, vb.patch}} {
		if d[0] != d[1] {
			return d[0] > d[1]
		}
	}
	switch {
	case va.pre == "" || vb.pre == "":
		return va.pre == "" && vb.pre != ""
	default:
		return va.pre > vb.pre
	}
}

type version struct {
	major, minor, patch int
	pre                 string // the pre-release, such as "rc.4"; empty for a release
}

// parse reads "X.Y" or "X.Y.Z", with an optional pre-release ("-rc.4") and build ("+7").
func parse(s string) (version, bool) {
	s, _, _ = strings.Cut(s, "+")
	s, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return version{}, false
	}
	var n [3]int
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return version{}, false
		}
		n[i] = v
	}
	return version{major: n[0], minor: n[1], patch: n[2], pre: pre}, true
}
