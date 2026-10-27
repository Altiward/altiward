package export_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Altiward/altiward/backend/internal/export"
	"github.com/Altiward/altiward/backend/internal/ocsf"
	"github.com/Altiward/altiward/backend/internal/store"
	"github.com/Altiward/altiward/backend/internal/testfixture"
	"github.com/Altiward/altiward/integrations/sentinel"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

func TestSentinelPreservesEnrolmentActorsAndExistingUsers(t *testing.T) {
	var got []sentinel.Row
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer zr.Close()
		if err := json.NewDecoder(zr).Decode(&got); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	sink := export.SentinelSink{Client: &sentinel.Client{
		Endpoint: srv.URL, RuleID: "dcr-test", Stream: "Custom-AltiwardOCSF", Tokens: staticToken("test"),
	}}
	audit := store.AuditEntry{ID: "audit-test", TenantID: "acme", Actor: "admin@example.com",
		At: testfixture.Time(t, "2026-10-26T12:00:00Z"), Action: store.AuditApproveEnrollment,
		Target: "device-test", Detail: map[string]any{"serial": "AUDIT-MAC"}}
	records := []export.Record{record(t, "agent-enrollment-pending"), record(t, "elevation-granted"),
		{TenantID: "acme", Audit: &audit, OCSF: ocsf.MapAudit(audit)}}
	if err := sink.Send(context.Background(), records); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("rows = %d, want 3", len(got))
	}
	for i, want := range []string{"token:1a2b3c4d", "jdoe", "admin@example.com"} {
		if got[i].UserName != want {
			t.Errorf("row %d UserName = %q, want %q", i, got[i].UserName, want)
		}
	}
	if got[2].DeviceSerial != "AUDIT-MAC" {
		t.Fatalf("audit serial = %q", got[2].DeviceSerial)
	}
}

func TestSentinelRowsForRotation(t *testing.T) {
	var got []sentinel.Row
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer zr.Close()
		if err := json.NewDecoder(zr).Decode(&got); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	sink := export.SentinelSink{Client: &sentinel.Client{
		Endpoint: srv.URL, RuleID: "dcr-test", Stream: "Custom-AltiwardOCSF", Tokens: staticToken("test"),
	}}
	records := []export.Record{record(t, "agent-enrollment-rotated"), record(t, "agent-enrollment-rotated-key-used")}
	if err := sink.Send(context.Background(), records); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %d, want 2", len(got))
	}
	for i, want := range []struct {
		activity, severity int
		message            string
	}{
		{3, 1, "C02XK0AAJGH5 replaced its key by rotation"},
		{99, 4, "C02XK0AAJGH5 used a key it had already replaced"},
	} {
		row := got[i]
		if row.ClassUid != 6003 || row.ActivityId != want.activity || row.SeverityId != want.severity ||
			row.Message != want.message || row.UserName != "C02XK0AAJGH5" || row.DeviceSerial != "C02XK0AAJGH5" {
			t.Errorf("row %d = %+v", i, row)
		}
	}
}
