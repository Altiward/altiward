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
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("splunk: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var ack struct {
		Code int    `json:"code"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(respBody, &ack); err == nil && ack.Code != 0 {
		return fmt.Errorf("splunk: code %d: %s", ack.Code, ack.Text)
	}
	return nil
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}
