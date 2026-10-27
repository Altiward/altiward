package sentinel

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/Altiward/altiward/integrations/entra"
)

// ManagedIdentity gets tokens for the Logs Ingestion API from an Azure managed identity,
// so the server holds no secret: a VM's through the Instance Metadata Service (IMDS), or
// a Container App's through the identity endpoint the platform gives it. It caches each
// token until shortly before expiry, and retries the errors Microsoft documents as
// transient. Set the fields before the first Token call.
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

	once  sync.Once
	entra *entra.ManagedIdentity
}

// The Logs Ingestion API's resource: monitorScope without "/.default", as the Azure SDKs
// turn a scope into an IMDS resource.
const monitorResource = "https://monitor.azure.com/"

func (mi *ManagedIdentity) client() *http.Client {
	if mi.HTTP != nil {
		return mi.HTTP
	}
	return entra.NoProxyClient()
}

func (mi *ManagedIdentity) Token(ctx context.Context) (string, error) {
	mi.once.Do(func() {
		mi.entra = &entra.ManagedIdentity{
			ClientID: mi.ClientID,
			Endpoint: mi.Endpoint,
			Header:   mi.Header,
			Host:     mi.Host,
			Resource: monitorResource,
			IMDSHint: "give the VM a managed identity with az vm identity assign, grant it Monitoring Metrics " +
				"Publisher on the DCR, and for a user-assigned identity set ALTIWARD_SENTINEL_CLIENT_ID to its client ID",
			EndpointHint: "give the container app a managed identity, grant it Monitoring Metrics " +
				"Publisher on the DCR, and for a user-assigned identity set ALTIWARD_SENTINEL_CLIENT_ID to its client ID",
			HTTP:       mi.client(),
			Now:        mi.Now,
			RetryDelay: mi.RetryDelay,
		}
	})
	return mi.entra.Token(ctx)
}
