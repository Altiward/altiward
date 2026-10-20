package splunk_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Altiward/altiward/integrations/splunk"
)

func TestSendBatchesAndAuthenticates(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/collector/event" || r.Header.Get("Authorization") != "Splunk tok" {
			http.Error(w, `{"text":"Invalid token","code":4}`, http.StatusForbidden)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	c := &splunk.Client{URL: srv.URL + "/", Token: "tok", MaxBatchBytes: 200}
	events := []splunk.Event{}
	for i := 0; i < 5; i++ {
		events = append(events, splunk.Event{Time: 1792142043.12, Host: "C02", SourceType: "altiward:ocsf", Event: map[string]any{"i": i, "pad": strings.Repeat("x", 40)}})
	}
	if err := c.Send(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if len(bodies) < 2 {
		t.Fatalf("expected several requests under a 200-byte cap, got %d", len(bodies))
	}
	// Every body is a stream of whole JSON objects; together they hold all events in order.
	var got []int
	for _, b := range bodies {
		dec := json.NewDecoder(bytes.NewReader(b))
		for dec.More() {
			var e struct {
				Event struct{ I int } `json:"event"`
			}
			if err := dec.Decode(&e); err != nil {
				t.Fatal(err)
			}
			got = append(got, e.Event.I)
		}
	}
	if len(got) != 5 || got[0] != 0 || got[4] != 4 {
		t.Fatalf("events = %v", got)
	}
}

func TestSendReportsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"text":"Invalid token","code":4}`, http.StatusForbidden)
	}))
	defer srv.Close()
	err := (&splunk.Client{URL: srv.URL, Token: "bad"}).Send(context.Background(), []splunk.Event{{Event: 1}})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

func TestSendNothingIsNoop(t *testing.T) {
	if err := (&splunk.Client{URL: "http://127.0.0.1:1"}).Send(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}
