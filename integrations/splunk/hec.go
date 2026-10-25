// Package splunk sends events to a Splunk HTTP Event Collector (HEC).
package splunk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Event is one HEC event envelope.
type Event struct {
	Time       float64 `json:"time"` // epoch seconds, millisecond precision
	Host       string  `json:"host,omitempty"`
	Source     string  `json:"source,omitempty"`
	SourceType string  `json:"sourcetype,omitempty"`
	Index      string  `json:"index,omitempty"`
	Event      any     `json:"event"`
}

// Client posts to {URL}/services/collector/event with "Authorization: Splunk <token>".
// Redirects are never followed, including when HTTP supplies a shared client.
type Client struct {
	URL   string // e.g. https://splunk.example.com:8088
	Token string
	HTTP  *http.Client
	// MaxBatchBytes caps one request body; HEC's default limit is 1 MB.
	MaxBatchBytes int
}

// Send delivers events in as few requests as the size cap allows. HEC accepts
// concatenated JSON objects in one body.
func (c *Client) Send(ctx context.Context, events []Event) error {
	limit := c.MaxBatchBytes
	if limit <= 0 {
		limit = 800 << 10
	}
	var body bytes.Buffer
	for _, e := range events {
		b, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("splunk: encode event: %w", err)
		}
		if body.Len() > 0 && body.Len()+len(b) > limit {
			if err := c.post(ctx, body.Bytes()); err != nil {
				return err
			}
			body.Reset()
		}
		body.Write(b)
	}
	if body.Len() == 0 {
		return nil
	}
	return c.post(ctx, body.Bytes())
}

func (c *Client) post(ctx context.Context, body []byte) error {
	url := strings.TrimRight(c.URL, "/") + "/services/collector/event"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("splunk: %w", err)
	}
	defer resp.Body.Close()
	// An acknowledgement is small. Read one byte past the cap so a valid JSON prefix
	// followed by an oversized or interrupted body can never count as accepted.
	const maxAcknowledgementBytes = 4096
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAcknowledgementBytes+1))
	if err != nil {
		return fmt.Errorf("splunk: read acknowledgement: %w", err)
	}
	if len(respBody) > maxAcknowledgementBytes {
		return fmt.Errorf("splunk: acknowledgement exceeds %d bytes", maxAcknowledgementBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("splunk: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	code, text, err := acknowledgement(respBody)
	if err != nil {
		return fmt.Errorf("splunk: invalid acknowledgement: %w", err)
	}
	// Splunk also accepts data with capacity warning codes 24 and 25. Health code 17
	// belongs to the health endpoint and does not acknowledge this event batch.
	// https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.2/get-data-with-http-event-collector/troubleshoot-http-event-collector
	switch code {
	case 0, 24, 25:
		return nil
	default:
		return fmt.Errorf("splunk: code %d: %s", code, text)
	}
}

// acknowledgement requires one complete object and an explicit, non-null integer code.
// Duplicate fields are ambiguous and must not turn a rejected batch into an accepted one.
func acknowledgement(body []byte) (code int, text string, err error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	first, err := dec.Token()
	if err != nil {
		return 0, "", err
	}
	if first != json.Delim('{') {
		return 0, "", fmt.Errorf("expected an object")
	}
	seen := map[string]bool{}
	var acceptedCode *int
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return 0, "", err
		}
		key := token.(string) // object keys are strings after a successful Token call
		if seen[key] {
			return 0, "", fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = true
		switch key {
		case "code":
			if err := dec.Decode(&acceptedCode); err != nil {
				return 0, "", err
			}
		case "text":
			if err := dec.Decode(&text); err != nil {
				return 0, "", err
			}
		default:
			var ignored json.RawMessage
			if err := dec.Decode(&ignored); err != nil {
				return 0, "", err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return 0, "", err
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return 0, "", fmt.Errorf("expected the end of the acknowledgement")
	}
	if acceptedCode == nil {
		return 0, "", fmt.Errorf("missing or null code")
	}
	return *acceptedCode, text, nil
}

func (c *Client) http() *http.Client {
	shared := http.DefaultClient
	if c.HTTP != nil {
		shared = c.HTTP
	}
	client := *shared
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}
