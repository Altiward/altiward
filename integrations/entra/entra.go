// Package entra gets Microsoft Entra ID access tokens for a service: the OAuth 2.0
// client-credentials grant with a secret or a certificate, or an Azure managed identity.
// The caller names the scope or resource, so one sign-in serves the Logs Ingestion API,
// Microsoft Graph or any other Microsoft API.
package entra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenSource returns a bearer token for one API.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// ClientCredentials gets Entra ID tokens with the OAuth 2.0 client-credentials grant
// and caches them until shortly before expiry. It signs in with Certificate when set, and
// with ClientSecret otherwise.
type ClientCredentials struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Certificate  *Certificate
	// Scope is the API's, ending in /.default, e.g. https://graph.microsoft.com/.default.
	// Required.
	Scope string
	// AuthorityHost defaults to https://login.microsoftonline.com (override for sovereign clouds).
	AuthorityHost string
	HTTP          *http.Client
	Now           func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func (cc *ClientCredentials) Token(ctx context.Context) (string, error) {
	if cc.Scope == "" {
		return "", errors.New("entra: Scope is empty")
	}
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
	u := fmt.Sprintf("%s/%s/oauth2/v2.0/token", strings.TrimRight(host, "/"), url.PathEscape(cc.TenantID))
	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {cc.ClientID},
		"scope":      {cc.Scope},
	}
	if cc.Certificate != nil {
		assertion, err := cc.Certificate.assertion(cc.ClientID, u, now())
		if err != nil {
			return "", fmt.Errorf("sign client assertion: %w", err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	} else {
		form.Set("client_secret", cc.ClientSecret)
	}
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
