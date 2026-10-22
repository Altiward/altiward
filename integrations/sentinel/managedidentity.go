package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ManagedIdentity gets tokens from an Azure managed identity, so the server holds no
// secret: a VM's through the Instance Metadata Service (IMDS), or a Container App's
// through the identity endpoint the platform gives it. It caches each token until
// shortly before expiry, and retries the errors Microsoft documents as transient.
type ManagedIdentity struct {
	// ClientID picks a user-assigned identity; empty means the system-assigned one.
	ClientID string
	// Endpoint and Header are a Container App's IDENTITY_ENDPOINT and IDENTITY_HEADER.
	// Empty means IMDS.
	Endpoint string
	Header   string
	// Host defaults to http://169.254.169.254 (override for tests). IMDS only.
	Host string
	// HTTP defaults to a client that never uses a proxy: neither IMDS nor the identity
	// endpoint is supported behind one. One you set mustn't use a proxy either.
	HTTP *http.Client
	Now  func() time.Time
	// RetryDelay is the wait before the first retry, doubling for the next; default 1s.
	RetryDelay time.Duration

	mu      sync.Mutex
	token   string
	expires time.Time
}

// The Logs Ingestion API's resource: monitorScope without "/.default", as the Azure SDKs
// turn a scope into an IMDS resource.
const monitorResource = "https://monitor.azure.com/"

const imdsAttempts = 3

// noProxy is the default client. The timeout is short: off Azure, nothing answers.
var noProxy = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}

func (mi *ManagedIdentity) client() *http.Client {
	if mi.HTTP != nil {
		return mi.HTTP
	}
	return noProxy
}

func (mi *ManagedIdentity) Token(ctx context.Context) (string, error) {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	now := time.Now
	if mi.Now != nil {
		now = mi.Now
	}
	if mi.token != "" && now().Before(mi.expires) {
		return mi.token, nil
	}
	delay := mi.RetryDelay
	if delay <= 0 {
		delay = time.Second
	}
	for attempt := 1; ; attempt++ {
		tok, lifetime, retry, err := mi.fetch(ctx, now)
		if err == nil {
			mi.token = tok
			// Refresh five minutes early so a token never expires mid-request.
			mi.expires = now().Add(lifetime - 5*time.Minute)
			return tok, nil
		}
		if !retry || attempt == imdsAttempts {
			return "", fmt.Errorf("managed identity: %w", err)
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("managed identity: %w", ctx.Err())
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// fetch makes one token request. retry says whether the error is one Microsoft documents
// as transient: 404 and 410 while IMDS updates, 429 when throttled, and 5xx.
func (mi *ManagedIdentity) fetch(ctx context.Context, now func() time.Time) (token string, lifetime time.Duration, retry bool, err error) {
	req, source, hint, err := mi.request(ctx)
	if err != nil {
		return "", 0, false, err
	}
	resp, err := mi.client().Do(req)
	if err != nil {
		if mi.Endpoint != "" {
			return "", 0, false, err
		}
		return "", 0, false, fmt.Errorf("%w (is the server on an Azure VM, and can its container reach 169.254.169.254?)", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch s := resp.StatusCode; {
	case s == http.StatusOK:
	case s == http.StatusBadRequest:
		return "", 0, false, fmt.Errorf("%s HTTP 400: %s (%s)", source, strings.TrimSpace(string(body)), hint)
	default:
		transient := s == http.StatusNotFound || s == http.StatusGone || s == http.StatusTooManyRequests || s >= 500
		return "", 0, transient, fmt.Errorf("%s HTTP %d: %s", source, s, strings.TrimSpace(string(body)))
	}
	var tr struct {
		AccessToken string     `json:"access_token"`
		ExpiresIn   flexNumber `json:"expires_in"`
		ExpiresOn   flexNumber `json:"expires_on"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", 0, false, fmt.Errorf("%s returned no access_token", source)
	}
	lifetime = time.Duration(tr.ExpiresIn) * time.Second
	if tr.ExpiresIn == 0 && tr.ExpiresOn > 0 {
		lifetime = time.Unix(int64(tr.ExpiresOn), 0).Sub(now())
	}
	return tr.AccessToken, lifetime, false, nil
}

// request builds one token request, naming its source and how to fix a 400 for errors.
func (mi *ManagedIdentity) request(ctx context.Context) (req *http.Request, source, hint string, err error) {
	q := url.Values{"resource": {monitorResource}}
	if mi.ClientID != "" {
		q.Set("client_id", mi.ClientID)
	}
	if mi.Endpoint != "" {
		// A Container App's identity endpoint (the App Service protocol).
		q.Set("api-version", "2019-08-01")
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, mi.Endpoint+"?"+q.Encode(), nil)
		if err != nil {
			return nil, "", "", err
		}
		req.Header.Set("X-IDENTITY-HEADER", mi.Header)
		return req, "identity endpoint", "give the container app a managed identity, grant it Monitoring Metrics " +
			"Publisher on the DCR, and for a user-assigned identity set ALTIWARD_SENTINEL_CLIENT_ID to its client ID", nil
	}
	host := mi.Host
	if host == "" {
		host = "http://169.254.169.254"
	}
	q.Set("api-version", "2018-02-01")
	req, err = http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(host, "/")+"/metadata/identity/oauth2/token?"+q.Encode(), nil)
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("Metadata", "true")
	return req, "IMDS", "give the VM a managed identity with az vm identity assign, grant it Monitoring Metrics " +
		"Publisher on the DCR, and for a user-assigned identity set ALTIWARD_SENTINEL_CLIENT_ID to its client ID", nil
}

// flexNumber reads a JSON number or a string holding one: IMDS sends "3599".
type flexNumber int64

func (n *flexNumber) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	*n = flexNumber(v)
	return err
}
