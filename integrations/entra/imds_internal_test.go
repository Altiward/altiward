package entra

import (
	"net/http"
	"testing"
)

// IMDS must never go through HTTP_PROXY: Microsoft doesn't support it behind a proxy, and
// a proxy would answer for 169.254.169.254 itself.
func TestManagedIdentityNeverUsesAProxy(t *testing.T) {
	tr, ok := (&ManagedIdentity{}).client().Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatalf("transport = %#v", tr)
	}
}
