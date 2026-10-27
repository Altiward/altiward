package auth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func TestCanonicalStringMatchesContract(t *testing.T) {
	v := testfixture.Signature(t)
	if got := auth.CanonicalString(v.Method, v.Path, v.Timestamp, []byte(v.Body)); got != v.Canonical {
		t.Fatalf("canonical =\n%s\nwant\n%s", got, v.Canonical)
	}
}

func TestVerifiesContractSignature(t *testing.T) {
	v := testfixture.Signature(t)
	key, err := auth.ParsePublicKey(v.PublicKeySPKI)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.Verify(key, v.Canonical, v.Signature); err != nil {
		t.Fatalf("contract signature rejected: %v", err)
	}
	tampered := strings.Replace(v.Canonical, "POST", "GET", 1)
	if err := auth.Verify(key, tampered, v.Signature); err == nil {
		t.Fatal("signature verified over a different request")
	}
}

func TestParsePublicKeyAcceptsOnlyP256(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := auth.ParsePublicKey(der); err == nil {
		t.Fatal("accepted a P-384 key")
	}
	if _, err := auth.ParsePublicKey([]byte("not a key")); err == nil {
		t.Fatal("accepted garbage")
	}
}

func TestParseSignedRequestHeaders(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/agent/events", nil)
	if _, ok := auth.ParseSignedRequest(r); ok {
		t.Fatal("parsed a request without signature headers")
	}
	r.Header.Set("Authorization", "AltiwardDevice 3f6c2a9e-7b4d-4e1a-9c8f-5d2b1a0e9f47")
	r.Header.Set("X-Altiward-Timestamp", "1792152000")
	r.Header.Set("X-Altiward-Signature", "c2ln")
	got, ok := auth.ParseSignedRequest(r)
	if !ok || got.DeviceID != "3f6c2a9e-7b4d-4e1a-9c8f-5d2b1a0e9f47" || got.Timestamp != 1792152000 || string(got.Signature) != "sig" {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	for header, bad := range map[string]string{
		"X-Altiward-Timestamp": "soon",
		"X-Altiward-Signature": "%%%",
		"Authorization":        "Bearer 3f6c2a9e-7b4d-4e1a-9c8f-5d2b1a0e9f47",
	} {
		r2 := r.Clone(r.Context())
		r2.Header.Set(header, bad)
		if _, ok := auth.ParseSignedRequest(r2); ok {
			t.Errorf("accepted bad %s %q", header, bad)
		}
	}
}

func TestRotationStatementMatchesContract(t *testing.T) {
	v := testfixture.Rotation(t)
	if got := auth.RotationStatement(v.DeviceID, v.NewPublicKey); got != v.Statement {
		t.Fatalf("statement =\n%s\nwant\n%s", got, v.Statement)
	}
}

func TestVerifiesContractRotationProof(t *testing.T) {
	v := testfixture.Rotation(t)
	if err := auth.VerifyRotationProof(v.DeviceID, v.NewPublicKey, v.Proof); err != nil {
		t.Fatalf("contract proof rejected: %v", err)
	}
	otherID := "4" + v.DeviceID[1:]
	if otherID == v.DeviceID {
		otherID = "5" + v.DeviceID[1:]
	}
	if err := auth.VerifyRotationProof(otherID, v.NewPublicKey, v.Proof); err == nil {
		t.Fatal("accepted a proof for another device_id")
	}
	flipped := append([]byte(nil), v.NewPublicKey...)
	flipped[len(flipped)-1] ^= 1
	if err := auth.VerifyRotationProof(v.DeviceID, flipped, v.Proof); err == nil {
		t.Fatal("accepted a proof for a changed key")
	}
	// A request signature must not stand in for a rotation proof.
	sig := testfixture.Signature(t)
	if err := auth.VerifyRotationProof(v.DeviceID, v.NewPublicKey, sig.Signature); err == nil {
		t.Fatal("accepted a request signature as a proof")
	}
	if err := auth.VerifyRotationProof(v.DeviceID, []byte("not a key"), v.Proof); err == nil {
		t.Fatal("accepted a proof for an unparseable key")
	}
}
