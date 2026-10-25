package export_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/export"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
	"github.com/Altiward/altiward/integrations/splunk"
)

func TestSplunkAmbiguousAcknowledgementKeepsExportQueued(t *testing.T) {
	for name, body := range map[string]string{
		"HTML": `<html>Sign in</html>`, "missing code": `{"text":"Success"}`,
		"null code": `{"code":null}`, "truncated": `{"code":0`, "redirect": "",
	} {
		t.Run(name, func(t *testing.T) {
			var recovered atomic.Bool
			var redirected atomic.Int32
			var mu sync.Mutex
			var attempts []string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/services/collector/event" {
					redirected.Add(1)
					io.WriteString(w, `<html>Sign in</html>`)
					return
				}
				b, _ := io.ReadAll(r.Body)
				mu.Lock()
				attempts = append(attempts, string(b))
				mu.Unlock()
				if recovered.Load() {
					io.WriteString(w, `{"code":0}`)
				} else if name == "redirect" {
					http.Redirect(w, r, "/sign-in", http.StatusFound)
				} else {
					io.WriteString(w, body)
				}
			}))
			defer srv.Close()
			ctx := context.Background()
			now := testfixture.Time(t, "2026-10-25T12:00:00Z")
			s := store.NewMemory([]string{"splunk"})
			e := testfixture.Event(t, "elevation-granted")
			if _, err := s.Ingest(ctx, "acme", []event.Event{e}, now); err != nil {
				t.Fatal(err)
			}
			sink := &export.SplunkSink{Client: &splunk.Client{URL: srv.URL, HTTP: srv.Client()}}
			worker := &export.Worker{
				Store: s, BatchSize: 10, Lease: time.Minute,
				Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now },
			}
			if sent, err := worker.Drain(ctx, sink); err == nil || sent != 0 {
				t.Fatalf("ambiguous acknowledgement: sent %d, err %v", sent, err)
			}
			status, err := s.ExportStatus(ctx, "acme")
			if err != nil || len(status) != 1 || status[0].Pending != 1 || status[0].Failing != 1 ||
				status[0].LastError == "" || status[0].LastDeliveredAt != nil {
				t.Fatalf("event was not retained as failed: %+v, %v", status, err)
			}
			if redirected.Load() != 0 {
				t.Fatal("delivery followed the sign-in redirect")
			}
			recovered.Store(true)
			now = now.Add(export.Backoff(1) + time.Second)
			if sent, err := worker.Drain(ctx, sink); err != nil || sent != 1 {
				t.Fatalf("confirmed retry: sent %d, err %v", sent, err)
			}
			status, err = s.ExportStatus(ctx, "acme")
			if err != nil || len(status) != 1 || status[0].Pending != 0 || status[0].LastDeliveredAt == nil {
				t.Fatalf("accepted retry did not complete: %+v, %v", status, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(attempts) != 2 || attempts[0] != attempts[1] {
				t.Fatalf("retry changed or lost the queued batch: %v", attempts)
			}
		})
	}
}
