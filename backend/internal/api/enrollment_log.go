package api

import "time"

type enrollLogKey struct{ tenant, limit string }

// logEnrollmentLimit warns once per tenant and limit window, across all its serials.
// The key space is bounded by the configured tenants and the two server limits.
// Each server instance starts a new warning window when it restarts.
func (s *Server) logEnrollmentLimit(tenant, serial, limit string) {
	window := time.Hour
	if limit == "keys_per_mac_per_day" {
		window = 24 * time.Hour
	}
	now := s.now()
	key := enrollLogKey{tenant, limit}
	s.enrollLogMu.Lock()
	last, seen := s.enrollLogLast[key]
	warn := !seen || !now.Before(last.Add(window))
	if warn {
		if s.enrollLogLast == nil {
			s.enrollLogLast = make(map[enrollLogKey]time.Time)
		}
		s.enrollLogLast[key] = now
	}
	s.enrollLogMu.Unlock()
	if warn {
		s.log.Warn("enrolment rate limited", "tenant", tenant, "serial", serial, "limit", limit)
	} else {
		s.log.Debug("enrolment rate limited", "tenant", tenant, "serial", serial, "limit", limit)
	}
}
