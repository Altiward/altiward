package api

import (
	"context"
	"net/http"
	"slices"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
)

// The SIEM exports as the console shows them. Sinks are set in the server's environment
// (one configuration per deployment), so the console reads their queues and can send a
// test event or retry now, but never changes their settings.

// WithSinks names the configured export sinks, in the order the server set them up.
func WithSinks(names []string) Option { return func(s *Server) { s.sinks = names } }

func (s *Server) listExports(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	out, err := s.sinkStatus(r.Context(), p.TenantID)
	if err != nil {
		s.serverError(w, "export status", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sinks": out})
}

// sinkStatus is each configured sink's export status for the tenant, in configured order.
func (s *Server) sinkStatus(ctx context.Context, tenantID string) ([]store.ExportBacklog, error) {
	queued, err := s.store.ExportStatus(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := []store.ExportBacklog{}
	for _, sink := range s.sinks {
		b := store.ExportBacklog{Sink: sink}
		if i := slices.IndexFunc(queued, func(q store.ExportBacklog) bool { return q.Sink == sink }); i >= 0 {
			b = queued[i]
		}
		out = append(out, b)
	}
	return out, nil
}

// testExport records a test_export console action. Like every console action it is queued
// for each sink, so it reaches the SIEM through the same queue, sign-in and mapping as real
// events.
func (s *Server) testExport(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	if len(s.sinks) == 0 {
		writeError(w, http.StatusConflict, "no SIEM is configured: set one up in the server's .env")
		return
	}
	a, err := s.auditEntry(p, store.AuditTestExport, "exports", map[string]any{"sinks": s.sinks})
	if err != nil {
		s.serverError(w, "audit entry", err)
		return
	}
	if err := s.store.RecordAudit(r.Context(), a); err != nil {
		s.serverError(w, "test export", err)
		return
	}
	s.log.Info("SIEM test event queued", "tenant", p.TenantID, "sinks", s.sinks, "actor", p.Actor)
	writeJSON(w, http.StatusAccepted, map[string]any{"queued_for": s.sinks, "audit_id": a.ID})
}

// retryExports makes a sink's waiting exports due now, for after a fix, instead of when their
// backoff (up to an hour) ends.
func (s *Server) retryExports(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	sink := r.PathValue("sink")
	if !slices.Contains(s.sinks, sink) {
		writeError(w, http.StatusNotFound, "no such SIEM is configured")
		return
	}
	a, err := s.auditEntry(p, store.AuditRetryExports, sink, nil)
	if err != nil {
		s.serverError(w, "audit entry", err)
		return
	}
	n, err := s.store.RetryExportsNow(r.Context(), p.TenantID, sink, s.now(), a)
	if err != nil {
		s.serverError(w, "retry exports", err)
		return
	}
	s.log.Info("SIEM exports retried now", "tenant", p.TenantID, "sink", sink, "items", n, "actor", p.Actor)
	writeJSON(w, http.StatusOK, map[string]any{"retried": n})
}
