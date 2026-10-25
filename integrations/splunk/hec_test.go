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
	"sync/atomic"
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSendRequiresExplicitAcceptedAcknowledgement(t *testing.T) {
	cases := []struct {
		name, body string
		accepted   bool
	}{
		{"success", `{"text":"Success","code":0}`, true},
		{"explicit code", `{"code":0}`, true},
		{"queue capacity warning", `{"text":"HEC queue is approaching its capacity limit","code":24}`, true},
		{"ack capacity warning", `{"text":"HEC ACK is approaching its capacity limit","code":25}`, true},
		{"extra fields", `{"code":0,"ackId":123}`, true},
		{"surrounding whitespace", " \n\t{\"code\":0}\r\n", true},
		{"empty", "", false},
		{"whitespace", " \n\t", false},
		{"HTML", `<html><title>Sign in</title></html>`, false},
		{"malformed", `{"code":`, false},
		{"truncated", `{"code":0`, false},
		{"missing code", `{"text":"Success"}`, false},
		{"empty object", `{}`, false},
		{"null object", `null`, false},
		{"array", `[{"code":0}]`, false},
		{"string", `"Success"`, false},
		{"null code", `{"code":null}`, false},
		{"string code", `{"code":"0"}`, false},
		{"boolean code", `{"code":false}`, false},
		{"fractional code", `{"code":0.0}`, false},
		{"exponent code", `{"code":0e0}`, false},
		{"case mismatch", `{"Code":0}`, false},
		{"health code", `{"code":17}`, false},
		{"rejection", `{"text":"Invalid token","code":4}`, false},
		{"unknown code", `{"code":99}`, false},
		{"capacity rejection", `{"code":26}`, false},
		{"duplicate rejected code", `{"code":0,"code":4}`, false},
		{"duplicate accepted code", `{"code":4,"code":0}`, false},
		{"duplicate other field", `{"code":0,"text":"x","text":"Success"}`, false},
		{"trailing object", `{"code":0}{"code":4}`, false},
		{"trailing null", `{"code":0}null`, false},
		{"trailing junk", `{"code":0}<html>`, false},
		{"oversized success prefix", `{"code":0}` + strings.Repeat(" ", 4096), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &splunk.Client{URL: "https://splunk.example.invalid", HTTP: &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
				}),
			}}
			err := c.Send(context.Background(), []splunk.Event{{Event: 1}})
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted = %v, want %v: %v", err == nil, tc.accepted, err)
			}
		})
	}
}

type interruptedBody struct {
	io.Reader
	closed bool
}

func (b *interruptedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (b *interruptedBody) Close() error { b.closed = true; return nil }

func TestSendRejectsReadFailureAfterValidAcknowledgementPrefix(t *testing.T) {
	body := &interruptedBody{Reader: strings.NewReader(`{"code":0}`)}
	c := &splunk.Client{URL: "https://splunk.example.invalid", HTTP: &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
		}),
	}}
	err := c.Send(context.Background(), []splunk.Event{{Event: 1}})
	if err == nil || !strings.Contains(err.Error(), "read acknowledgement") || !body.closed {
		t.Fatalf("err = %v, body closed = %v", err, body.closed)
	}
}

func TestSendNeverFollowsRedirectsOrChangesTheSharedClient(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var redirected, policyCalls atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/services/collector/event" {
					http.Redirect(w, r, "/sign-in", status)
					return
				}
				redirected.Add(1)
				io.WriteString(w, `{"code":0}`)
			}))
			defer srv.Close()
			shared := srv.Client()
			shared.CheckRedirect = func(*http.Request, []*http.Request) error { policyCalls.Add(1); return nil }
			c := &splunk.Client{URL: srv.URL, Token: "tok", HTTP: shared}
			if err := c.Send(context.Background(), []splunk.Event{{Event: 1}}); err == nil {
				t.Fatal("redirect counted as accepted")
			}
			if redirected.Load() != 0 || policyCalls.Load() != 0 {
				t.Fatal("Splunk delivery followed a redirect or used the shared redirect policy")
			}
			// The client belongs to other transports too. Its original policy must remain.
			if shared.CheckRedirect == nil {
				t.Fatal("shared redirect policy was cleared")
			}
			shared.CheckRedirect(nil, nil)
			if policyCalls.Load() != 1 {
				t.Fatal("shared redirect policy was replaced")
			}
		})
	}
}

func TestSendDefaultClientDoesNotFollowRedirect(t *testing.T) {
	var redirected atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/collector/event" {
			http.Redirect(w, r, "/sign-in", http.StatusFound)
			return
		}
		redirected.Add(1)
		io.WriteString(w, `<html>Sign in</html>`)
	}))
	defer srv.Close()
	if err := (&splunk.Client{URL: srv.URL}).Send(context.Background(), []splunk.Event{{Event: 1}}); err == nil {
		t.Fatal("redirect counted as accepted")
	}
	if redirected.Load() != 0 {
		t.Fatal("default client followed a redirect")
	}
}
