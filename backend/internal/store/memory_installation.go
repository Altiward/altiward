package store

import "context"

func (m *Memory) Installation(context.Context) (Installation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.installation, nil
}
