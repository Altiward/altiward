package api

// Console token use. A console token's request is served only once the audit log holds a
// sign-in by that token from the hour before it, so every hour of use leaves an entry,
// across restarts and replicas. The store decides; the cache below only saves asking it
// on every request.

import (
	"net/http"
	"sync"
	"time"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
)

// tokenUseEntry is how long one token's last sign-in covers it. Its own lock makes
// concurrent first requests for the token wait for one store call, rather than each
// holding a database connection while they queue for the store's lock.
type tokenUseEntry struct {
	mu    sync.Mutex
	until time.Time
}

// recordTokenUse makes sure the audit log holds a sign-in covering p's request, recording
// one if it doesn't. The handler must not run if it returns an error.
func (s *Server) recordTokenUse(r *http.Request, p auth.Principal) error {
	key := p.TenantID + "/" + p.Actor
	s.tokenUseMu.Lock()
	e := s.tokenUse[key]
	if e == nil {
		e = &tokenUseEntry{}
		s.tokenUse[key] = e
	}
	s.tokenUseMu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if s.now().Before(e.until) {
		return nil
	}
	// The route, never the path: the path is the caller's text, of any length.
	a, err := s.auditEntry(p, store.AuditSignIn, "console",
		map[string]any{"method": "token", "role": string(p.ConsoleRole), "route": r.Pattern})
	if err != nil {
		return err
	}
	covering, err := s.store.RecordTokenSignIn(r.Context(), a, TokenSignInEvery)
	if err != nil {
		return err
	}
	// An entry from a server whose clock is ahead covers no longer than one made now, and
	// building until from now (the entry's s.now()) keeps its monotonic reading.
	now := a.At
	if covering.After(now) {
		covering = now
	}
	e.until = now.Add(TokenSignInEvery - now.Sub(covering))
	return nil
}
