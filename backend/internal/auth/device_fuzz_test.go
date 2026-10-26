package auth_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func FuzzSignedRequestHeaders(f *testing.F) {
	v := testfixture.Signature(f)
	f.Add(auth.DeviceScheme+" "+v.DeviceID, strconv.FormatInt(v.Timestamp, 10), base64.StdEncoding.EncodeToString(v.Signature))
	f.Add("", "", "")
	f.Add("Bearer token", "9223372036854775808", "%%%")
	f.Add(auth.DeviceScheme+" device", "-1", "AA==")
	f.Fuzz(func(t *testing.T, authorisation, timestamp, signature string) {
		if len(authorisation)+len(timestamp)+len(signature) > 16<<10 {
			t.Skip()
		}
		r := &http.Request{Header: make(http.Header)}
		r.Header.Set("Authorization", authorisation)
		r.Header.Set("X-Altiward-Timestamp", timestamp)
		r.Header.Set("X-Altiward-Signature", signature)
		got, ok := auth.ParseSignedRequest(r)
		if !ok {
			return
		}
		if got.DeviceID == "" || len(got.Signature) == 0 {
			t.Fatal("accepted missing device ID or signature")
		}
		// An accepted header tuple must preserve its claims when encoded normally.
		r.Header.Set("Authorization", auth.DeviceScheme+" "+got.DeviceID)
		r.Header.Set("X-Altiward-Timestamp", strconv.FormatInt(got.Timestamp, 10))
		r.Header.Set("X-Altiward-Signature", base64.StdEncoding.EncodeToString(got.Signature))
		round, ok := auth.ParseSignedRequest(r)
		if !ok || !reflect.DeepEqual(got, round) {
			t.Fatal("signature header claims changed on round-trip")
		}
		r.Header.Set("Authorization", "Bearer "+got.DeviceID)
		if _, ok := auth.ParseSignedRequest(r); ok {
			t.Fatal("accepted a different authorisation scheme")
		}
	})
}

func FuzzPublicKey(f *testing.F) {
	v := testfixture.Signature(f)
	f.Add(v.PublicKeySPKI)
	f.Add([]byte{})
	f.Add([]byte("not a key"))
	f.Add(append(bytes.Clone(v.PublicKeySPKI), 0))
	p384 := elliptic.P384()
	otherCurve, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: p384, X: p384.Params().Gx, Y: p384.Params().Gy})
	if err != nil {
		f.Fatal(err)
	}
	if _, err := auth.ParsePublicKey(otherCurve); err == nil {
		f.Fatal("accepted the P-384 seed")
	}
	f.Add(otherCurve)
	f.Fuzz(func(t *testing.T, der []byte) {
		if len(der) > 16<<10 {
			t.Skip()
		}
		key, err := auth.ParsePublicKey(der)
		if err != nil {
			return
		}
		if key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) {
			t.Fatal("accepted a key outside P-256")
		}
		encoded, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		round, err := auth.ParsePublicKey(encoded)
		if err != nil || !key.Equal(round) {
			t.Fatalf("accepted public key changed on round-trip: %v", err)
		}
		if _, err := auth.ParsePublicKey(append(bytes.Clone(encoded), 0)); err == nil {
			t.Fatal("accepted trailing data after a public key")
		}
	})
}

func FuzzRequestSignature(f *testing.F) {
	v := testfixture.Signature(f)
	key, err := auth.ParsePublicKey(v.PublicKeySPKI)
	if err != nil || auth.Verify(key, v.Canonical, v.Signature) != nil {
		f.Fatal("invalid request-signing contract vector")
	}
	if auth.CanonicalString(v.Method, v.Path, v.Timestamp, []byte(v.Body)) != v.Canonical {
		f.Fatal("request-signing canonical vector changed")
	}
	f.Add(v.Method, v.Path, v.Timestamp, []byte(v.Body), v.Signature)
	f.Add("GET", v.Path+"?wait=0", int64(-1), []byte{}, []byte("bad DER"))
	f.Fuzz(func(t *testing.T, method, path string, timestamp int64, body, signature []byte) {
		if len(method)+len(path)+len(body)+len(signature) > 128<<10 {
			t.Skip()
		}
		canonical := auth.CanonicalString(method, path, timestamp, body)
		if canonical != auth.CanonicalString(method, path, timestamp, body) {
			t.Fatal("canonicalisation is not deterministic")
		}
		// A fixed, valid signature must authenticate exactly its canonical request.
		if err := auth.Verify(key, canonical, v.Signature); (err == nil) != (canonical == v.Canonical) {
			t.Fatal("contract signature accepted a changed canonical request or rejected its vector")
		}
		// Independently mutate DER as well as signed inputs; malformed signatures must not panic.
		err := auth.Verify(key, canonical, signature)
		if canonical == v.Canonical && bytes.Equal(signature, v.Signature) && err != nil {
			t.Fatal("contract signature rejected")
		}
		if err == nil && auth.Verify(key, canonical+"\x00", signature) == nil {
			t.Fatal("accepted signature did not bind its canonical request")
		}
		if err := auth.Verify(key, canonical+"\x00", v.Signature); err == nil {
			t.Fatal("signature accepted an appended canonical byte")
		}
	})
}
