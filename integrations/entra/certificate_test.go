package entra_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/integrations/entra"
)

// selfSigned makes a certificate for key, as `openssl req -x509` would for the app.
func selfSigned(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Altiward SIEM export"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func pkcs8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestClientCertificateSignsInWithAnAssertion(t *testing.T) {
	key := rsaKey(t)
	certPEM := selfSigned(t, key)
	path := filepath.Join(t.TempDir(), "entra.pem")
	if err := os.WriteFile(path, append(certPEM, pkcs8(t, key)...), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := entra.LoadCertificate(path)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	var assertion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path != "/tenant-1/oauth2/v2.0/token" || r.Form.Get("grant_type") != "client_credentials" ||
			r.Form.Get("client_id") != "app" || r.Form.Has("client_secret") ||
			r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			http.Error(w, "bad request: "+r.Form.Encode(), 400)
			return
		}
		assertion = r.Form.Get("client_assertion")
		w.Write([]byte(`{"access_token":"cert-token","expires_in":3600}`))
	}))
	defer srv.Close()

	cc := &entra.ClientCredentials{Scope: "https://example.test/.default", TenantID: "tenant-1", ClientID: "app", Certificate: cert, AuthorityHost: srv.URL, Now: func() time.Time { return now }}
	if tok, err := cc.Token(context.Background()); err != nil || tok != "cert-token" {
		t.Fatalf("token = %q, %v", tok, err)
	}

	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion isn't a JWT: %q", assertion)
	}
	var header map[string]string
	var claims map[string]any
	decode(t, parts[0], &header)
	decode(t, parts[1], &claims)
	block, _ := pem.Decode(certPEM)
	thumbprint := sha256.Sum256(block.Bytes)
	if header["alg"] != "PS256" || header["typ"] != "JWT" || header["x5t#S256"] != base64.RawURLEncoding.EncodeToString(thumbprint[:]) {
		t.Errorf("header = %v", header)
	}
	if claims["aud"] != srv.URL+"/tenant-1/oauth2/v2.0/token" || claims["iss"] != "app" || claims["sub"] != "app" ||
		claims["jti"] == "" || claims["nbf"] != float64(now.Unix()) || claims["exp"] != float64(now.Add(10*time.Minute).Unix()) {
		t.Errorf("claims = %v", claims)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Errorf("signature: %v", err)
	}
}

func decode(t *testing.T, part string, v any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func TestParseCertificate(t *testing.T) {
	key := rsaKey(t)
	cert := selfSigned(t, key)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	for name, tc := range map[string]struct {
		pem  []byte
		want string // error substring; empty for success
	}{
		"PKCS #8 key after the certificate":  {join(cert, pkcs8(t, key)), ""},
		"PKCS #1 key before the certificate": {join(pkcs1, cert), ""},
		"a chain after the certificate":      {join(cert, pkcs8(t, key), selfSigned(t, rsaKey(t))), ""},
		"no key":                             {cert, "no private key"},
		"no certificate":                     {pkcs8(t, key), "no CERTIFICATE"},
		"someone else's key":                 {join(cert, pkcs8(t, rsaKey(t))), "doesn't belong to the certificate"},
		"an EC key":                          {join(selfSigned(t, ec), pkcs8(t, ec)), "needs an RSA key"},
		"an encrypted key":                   {join(cert, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}})), "encrypted"},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := entra.ParseCertificate(tc.pem)
			if tc.want == "" {
				if err != nil || c.Leaf == nil || c.Key == nil {
					t.Fatalf("got %+v, %v", c, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
