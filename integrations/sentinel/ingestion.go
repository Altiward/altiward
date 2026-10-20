// Package sentinel uploads records to Microsoft Sentinel through the Azure Monitor
// Logs Ingestion API: a Data Collection Rule (DCR) routes a custom stream into a Log
// Analytics table. See README.md for the table schema, and deploy/sentinel/setup.sh in the main repository, which creates it.
package sentinel

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const apiVersion = "2023-01-01"

// TokenSource returns a bearer token for https://monitor.azure.com.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Client uploads to POST {Endpoint}/dataCollectionRules/{RuleID}/streams/{Stream}.
type Client struct {
	// Endpoint is the DCR's own logs ingestion URL, or a Data Collection Endpoint's with
	// private link, e.g. https://dcr-altiward-abcd.uksouth-1.ingest.monitor.azure.com.
	Endpoint string
	RuleID   string // DCR immutable ID, dcr-…
	Stream   string // e.g. Custom-AltiwardOCSF
	Tokens   TokenSource
	HTTP     *http.Client
	// MaxBatchBytes caps uncompressed JSON per call; the API limit is 1 MB per call.
	MaxBatchBytes int
}

// Upload sends records as JSON arrays, gzip-compressed, split to respect the size cap.
func (c *Client) Upload(ctx context.Context, records []any) error {
	limit := c.MaxBatchBytes
	if limit <= 0 {
		limit = 900 << 10
	}
	var batch []json.RawMessage
	size := 2
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("sentinel: encode record: %w", err)
		}
		if len(batch) > 0 && size+len(b)+1 > limit {
			if err := c.post(ctx, batch); err != nil {
				return err
			}
			batch, size = nil, 2
		}
		batch = append(batch, b)
		size += len(b) + 1
	}
	if len(batch) == 0 {
		return nil
	}
	return c.post(ctx, batch)
}

func (c *Client) post(ctx context.Context, batch []json.RawMessage) error {
	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(payload); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	token, err := c.Tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("sentinel: token: %w", err)
	}
	u := fmt.Sprintf("%s/dataCollectionRules/%s/streams/%s?api-version=%s",
		strings.TrimRight(c.Endpoint, "/"), url.PathEscape(c.RuleID), url.PathEscape(c.Stream), apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &gz)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := httpClient(c.HTTP).Do(req)
	if err != nil {
		return fmt.Errorf("sentinel: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("sentinel: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// ClientCredentials gets Entra ID tokens with the OAuth 2.0 client-credentials grant
// and caches them until shortly before expiry.
type ClientCredentials struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	// AuthorityHost defaults to https://login.microsoftonline.com (override for sovereign clouds).
	AuthorityHost string
	HTTP          *http.Client
	Now           func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Scope for the Logs Ingestion API (the double slash is part of the documented value).
const monitorScope = "https://monitor.azure.com//.default"

func (cc *ClientCredentials) Token(ctx context.Context) (string, error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	now := time.Now
	if cc.Now != nil {
		now = cc.Now
	}
	if cc.token != "" && now().Before(cc.expires) {
		return cc.token, nil
	}
	host := cc.AuthorityHost
	if host == "" {
		host = "https://login.microsoftonline.com"
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cc.ClientID},
		"client_secret": {cc.ClientSecret},
		"scope":         {monitorScope},
	}
	u := fmt.Sprintf("%s/%s/oauth2/v2.0/token", strings.TrimRight(host, "/"), url.PathEscape(cc.TenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient(cc.HTTP).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned no access_token")
	}
	cc.token = tr.AccessToken
	// Refresh five minutes early so a token never expires mid-request.
	cc.expires = now().Add(time.Duration(tr.ExpiresIn)*time.Second - 5*time.Minute)
	return cc.token, nil
}

func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return http.DefaultClient
}
