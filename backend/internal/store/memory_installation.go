package store

import (
	"context"
	"crypto/rand"
	"time"
)

// newMemoryInstallation starts a memory store's record: a fresh secret and the time it
// started, since each run is a new server.
func newMemoryInstallation() Installation {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("store: no randomness for the installation secret: " + err.Error())
	}
	now := time.Now().UTC()
	return Installation{CreatedAt: now, RaisedIDSecret: secret, AdminGroupStartedAt: now}
}

func (m *Memory) Installation(context.Context) (Installation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.installation, nil
}
