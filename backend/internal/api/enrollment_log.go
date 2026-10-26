package api

import "time"

type enrollLogKey struct{ tenant, limit string }

// enrollLogWindow is when a tenant's limit last warned, and the refusals since then that
// weren't logged.
type enrollLogWindow struct {
	warned    time.Time
	notLogged int
}

// logEnrollmentLimit warns once per tenant and limit window, across all its serials, and
// counts the other refusals in that window into the next warning: the server logs at Info,
// so a refusal it doesn't warn about isn't logged at all. The key space is bounded by the
// configured tenants and the server's limits. Each server instance starts a new warning
// window when it restarts.
func (s *Server) logEnrollmentLimit(tenant, serial, limit string, window time.Duration) {
	now := s.now()
	key := enrollLogKey{tenant, limit}
	s.enrollLogMu.Lock()
	w, seen := s.enrollLog[key]
	warn := !seen || !now.Before(w.warned.Add(window))
	notLogged := w.notLogged
	if warn {
		if s.enrollLog == nil {
			s.enrollLog = make(map[enrollLogKey]enrollLogWindow)
		}
		s.enrollLog[key] = enrollLogWindow{warned: now}
	} else {
		w.notLogged++
		s.enrollLog[key] = w
	}
	s.enrollLogMu.Unlock()
	if warn {
		s.log.Warn("enrolment rate limited", "tenant", tenant, "serial", serial, "limit", limit, "not_logged", notLogged)
	}
}
