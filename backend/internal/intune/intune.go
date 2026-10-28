// Package intune reads managed Macs from Microsoft Intune through Microsoft Graph. It only
// reads: the app registration needs the DeviceManagementManagedDevices.Read.All application
// permission and nothing else.
package intune

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Altiward/altiward/integrations/entra"
)

const (
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
	maxBody        = 8 << 20 // bytes read from any one response
	maxTries       = 3
	maxWait        = time.Minute
	permission     = "DeviceManagementManagedDevices.Read.All"
	managedDevices = "/deviceManagement/managedDevices"
	listSelect     = "id,serialNumber,azureADDeviceId,userPrincipalName,deviceName,lastSyncDateTime,operatingSystem"
	deviceSelect   = "id,serialNumber,udid,azureADDeviceId,userPrincipalName,deviceName,lastSyncDateTime,operatingSystem"
)

// ErrNotFound means Intune has no managed device with that ID.
var ErrNotFound = errors.New("intune: no such managed device")

var (
	deviceIDRE = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	serialRE   = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)
)

// Device is one Intune managed device.
type Device struct {
	ID            string // Intune's managed device ID
	Serial        string
	EntraDeviceID string
	UDID          string // set only by Device
	PrimaryUPN    string
	Name          string
	LastCheckIn   time.Time // UTC; zero when the device has never checked in
	// OperatingSystem is Intune's name for the platform, "macOS" for a Mac. Macs lists only
	// those; Device and DevicesBySerial give any platform's.
	OperatingSystem string
}

// Client is a read-only Microsoft Graph client for Intune managed devices.
type Client struct {
	Tokens entra.TokenSource
	HTTP   *http.Client
	// BaseURL defaults to https://graph.microsoft.com/v1.0 (override for sovereign clouds).
	BaseURL string
	// Sleep waits between retries and must return early with the context's error when it is
	// cancelled. It defaults to a timer that does.
	Sleep func(context.Context, time.Duration) error
}

// ValidDeviceID reports whether s, ignoring surrounding spaces, is a GUID without braces.
// It catches a placeholder such as {{deviceid}} that an MDM left unexpanded.
func ValidDeviceID(s string) bool { return deviceIDRE.MatchString(strings.TrimSpace(s)) }

// ValidSerial reports whether s is a serial DevicesBySerial accepts: letters and digits, at
// most 32 of them, with nothing around them.
func ValidSerial(s string) bool { return serialRE.MatchString(s) }

// Macs lists every managed device whose operating system is macOS.
func (c *Client) Macs(ctx context.Context) ([]Device, error) {
	next := c.listURL("operatingSystem eq 'macOS'")
	base, err := url.Parse(c.baseURL())
	if err != nil {
		return nil, fmt.Errorf("intune: bad base URL: %w", err)
	}
	var out []Device
	for next != "" {
		page, err := c.list(ctx, next)
		if err != nil {
			return nil, err
		}
		for _, d := range page.Value {
			if strings.EqualFold(d.OperatingSystem, "macOS") {
				out = append(out, d.device())
			}
		}
		next = page.NextLink
		if next == "" {
			break
		}
		// The next page comes with the bearer token, so only the Graph host we were
		// configured for may be asked for it.
		u, err := url.Parse(next)
		if err != nil || u.Scheme != base.Scheme || u.Host != base.Host {
			return nil, errors.New("intune: refusing to follow an @odata.nextLink to another host")
		}
	}
	return out, nil
}

// Device returns one managed device by its Intune ID, including its UDID, on any platform.
func (c *Client) Device(ctx context.Context, id string) (Device, error) {
	id = strings.TrimSpace(id)
	if !ValidDeviceID(id) {
		return Device{}, errors.New("intune: not a managed device ID")
	}
	q := url.Values{"$select": {deviceSelect}}
	body, err := c.get(ctx, c.baseURL()+managedDevices+"/"+url.PathEscape(id)+"?"+encodeQuery(q))
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && se.status == http.StatusNotFound {
			return Device{}, ErrNotFound
		}
		return Device{}, err
	}
	var d graphDevice
	if err := json.Unmarshal(body, &d); err != nil {
		return Device{}, fmt.Errorf("intune: decode device: %w", err)
	}
	return d.device(), nil
}

// DevicesBySerial lists the managed devices with that serial number, on any platform. The
// serial must be letters and digits, at most 32 of them (ValidSerial).
func (c *Client) DevicesBySerial(ctx context.Context, serial string) ([]Device, error) {
	if !ValidSerial(serial) {
		return nil, errors.New("intune: not a serial number")
	}
	page, err := c.list(ctx, c.listURL("serialNumber eq '"+strings.ReplaceAll(serial, "'", "''")+"'"))
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(page.Value))
	for _, d := range page.Value {
		out = append(out, d.device())
	}
	return out, nil
}

type graphDevice struct {
	ID              string `json:"id"`
	SerialNumber    string `json:"serialNumber"`
	AzureADDeviceID string `json:"azureADDeviceId"`
	UDID            string `json:"udid"`
	UPN             string `json:"userPrincipalName"`
	DeviceName      string `json:"deviceName"`
	LastSync        string `json:"lastSyncDateTime"`
	OperatingSystem string `json:"operatingSystem"`
}

func (g graphDevice) device() Device {
	d := Device{
		ID: g.ID, Serial: g.SerialNumber, EntraDeviceID: g.AzureADDeviceID, UDID: g.UDID,
		PrimaryUPN: g.UPN, Name: g.DeviceName, OperatingSystem: g.OperatingSystem,
	}
	// Intune writes 0001-01-01T00:00:00Z for "never", which parses to Go's zero time. A
	// timestamp it doesn't recognise counts as never too, rather than failing the sync.
	if t, err := time.Parse(time.RFC3339, g.LastSync); err == nil && !t.IsZero() {
		d.LastCheckIn = t.UTC()
	}
	return d
}

type listPage struct {
	Value    []graphDevice `json:"value"`
	NextLink string        `json:"@odata.nextLink"`
}

func (c *Client) list(ctx context.Context, u string) (listPage, error) {
	body, err := c.get(ctx, u)
	if err != nil {
		return listPage{}, err
	}
	var p listPage
	if err := json.Unmarshal(body, &p); err != nil {
		return listPage{}, fmt.Errorf("intune: decode device list: %w", err)
	}
	return p, nil
}

func (c *Client) baseURL() string {
	if c.BaseURL == "" {
		return defaultBaseURL
	}
	return strings.TrimRight(c.BaseURL, "/")
}

func (c *Client) listURL(filter string) string {
	q := url.Values{"$filter": {filter}, "$select": {listSelect}}
	return c.baseURL() + managedDevices + "?" + encodeQuery(q)
}

// encodeQuery writes spaces as %20: OData servers don't all read + as a space.
func encodeQuery(q url.Values) string {
	return strings.ReplaceAll(q.Encode(), "+", "%20")
}

// statusError is a non-2xx answer from Graph.
type statusError struct {
	status  int
	code    string
	message string
}

func (e *statusError) Error() string {
	s := fmt.Sprintf("intune: HTTP %d %s: %s", e.status, e.code, e.message)
	if e.status == http.StatusForbidden {
		s += " (the app registration needs the " + permission + " application permission, with admin consent)"
	}
	return s
}

// requestError is a request that failed before Graph answered, without its URL: the URL
// holds a device ID in Device's path, and from page 2 on Graph's $skiptoken, which can name
// the last device read. The error reaches the console and the logs. It keeps the cause, so
// errors.Is still finds a deadline.
type requestError struct{ err error }

func (e *requestError) Error() string { return "intune: GET managedDevices: " + e.err.Error() }
func (e *requestError) Unwrap() error { return e.err }

// withoutURL drops the URL a *url.Error quotes, keeping its cause.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return &requestError{err: err}
}

// get makes one GET with the bearer token, retrying as Graph asks, and returns the body of
// a 2xx answer.
func (c *Client) get(ctx context.Context, u string) ([]byte, error) {
	for try := 1; ; try++ {
		token, err := c.Tokens.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("intune: get token: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, withoutURL(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		resp, err := c.httpClient().Do(req)
		if err != nil {
			return nil, withoutURL(err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("intune: read response: %w", err)
		}
		if len(body) > maxBody {
			return nil, fmt.Errorf("intune: response over %d MiB", maxBody>>20)
		}
		if resp.StatusCode/100 == 2 {
			return body, nil
		}
		se := graphError(resp.StatusCode, body, token)
		if try >= maxTries || !(resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) {
			return nil, se
		}
		wait := time.Duration(1<<try) * time.Second // 2 s, then 4 s
		if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && secs >= 0 {
			wait = time.Duration(secs) * time.Second
		}
		if err := c.sleep(ctx, min(wait, maxWait)); err != nil {
			return nil, err
		}
	}
}

// graphError reads Graph's {"error":{"code","message"}}. It never repeats the response body
// as is, and strips the token in case a gateway echoed the Authorization header.
func graphError(status int, body []byte, token string) *statusError {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	se := &statusError{status: status, code: e.Error.Code, message: e.Error.Message}
	if se.code == "" {
		se.code = "Unknown"
	}
	if se.message == "" {
		se.message = http.StatusText(status)
	}
	if len(se.message) > 500 {
		se.message = se.message[:500] + "..."
	}
	if token != "" {
		se.message = strings.ReplaceAll(se.message, token, "[redacted]")
		se.code = strings.ReplaceAll(se.code, token, "[redacted]")
	}
	return se
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
