package mdm

import "time"

// SetPassTimeout shortens a pass's deadline for a test, and returns what puts it back.
func SetPassTimeout(d time.Duration) (restore func()) {
	old := passTimeout
	passTimeout = d
	return func() { passTimeout = old }
}
