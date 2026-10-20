package store

import "sync"

// commandWatchers wakes requests waiting for a Mac's next command (long-polling).
// The zero value is ready to use.
type commandWatchers struct {
	mu      sync.Mutex
	waiting map[[2]string]map[chan struct{}]struct{} // by tenant and serial
}

// watch returns a channel that is closed at the next notify for the Mac, and a function
// that stops watching. Calling stop more than once, or after the wake, is fine.
func (w *commandWatchers) watch(tenantID, serial string) (<-chan struct{}, func()) {
	k := [2]string{tenantID, serial}
	ch := make(chan struct{})
	w.mu.Lock()
	if w.waiting == nil {
		w.waiting = map[[2]string]map[chan struct{}]struct{}{}
	}
	if w.waiting[k] == nil {
		w.waiting[k] = map[chan struct{}]struct{}{}
	}
	w.waiting[k][ch] = struct{}{}
	w.mu.Unlock()
	return ch, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if set := w.waiting[k]; set != nil {
			delete(set, ch)
			if len(set) == 0 {
				delete(w.waiting, k)
			}
		}
	}
}

// notify wakes everyone watching the Mac.
func (w *commandWatchers) notify(tenantID, serial string) {
	k := [2]string{tenantID, serial}
	w.mu.Lock()
	defer w.mu.Unlock()
	for ch := range w.waiting[k] {
		close(ch)
	}
	delete(w.waiting, k)
}

// notifyAll wakes every watcher, so each checks for commands it may have missed.
func (w *commandWatchers) notifyAll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, set := range w.waiting {
		for ch := range set {
			close(ch)
		}
	}
	w.waiting = nil
}
