package mdm

import "time"

// SetPassTimeout shortens a pass's deadline for a test, and returns what puts it back.
func SetPassTimeout(d time.Duration) (restore func()) {
	old := passTimeout
	passTimeout = d
	return func() { passTimeout = old }
}

// SetAfter makes c wait for a lookup with after instead of time.After, and returns what
// puts it back.
func SetAfter(c *Checker, after func(time.Duration) <-chan time.Time) (restore func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.after
	c.after = after
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.after = old
	}
}
