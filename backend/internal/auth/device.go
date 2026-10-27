package auth

// Per-device request signatures. The agent signs every request after
// enrollment with its P-256 key; the API looks the device up by ID and verifies.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// DeviceScheme is the Authorization scheme of a signed agent request.
	DeviceScheme = "AltiwardDevice"
	// MaxClockSkew is how far a request's timestamp may be from server time.
	MaxClockSkew = 5 * time.Minute

	signatureVersion = "ALTIWARD-SIG-V1"
	rotationVersion  = "ALTIWARD-ROTATE-V1"
)

// SignedRequest is what a signed request's headers claim; Verify proves it.
type SignedRequest struct {
	DeviceID  string
	Timestamp int64
	Signature []byte
}

// CanonicalString is the text the agent signs: version, method, path and query,
// Unix timestamp and the body's SHA-256, one per line.
func CanonicalString(method, pathAndQuery string, timestamp int64, body []byte) string {
	digest := sha256.Sum256(body)
	return strings.Join([]string{
		signatureVersion, method, pathAndQuery, strconv.FormatInt(timestamp, 10), hex.EncodeToString(digest[:]),
	}, "\n")
}

// ParseSignedRequest reads the signature headers. ok is false when any is missing or malformed.
func ParseSignedRequest(r *http.Request) (SignedRequest, bool) {
	scheme, id, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || scheme != DeviceScheme || id == "" {
		return SignedRequest{}, false
	}
	ts, err := strconv.ParseInt(r.Header.Get("X-Altiward-Timestamp"), 10, 64)
	if err != nil {
		return SignedRequest{}, false
	}
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Altiward-Signature"))
	if err != nil || len(sig) == 0 {
		return SignedRequest{}, false
	}
	return SignedRequest{DeviceID: id, Timestamp: ts, Signature: sig}, true
}

// ParsePublicKey decodes a SubjectPublicKeyInfo DER key and requires P-256.
func ParsePublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("public key must be ECDSA P-256")
	}
	return ec, nil
}

// Verify checks an ASN.1 DER ECDSA signature over SHA-256(canonical).
func Verify(key *ecdsa.PublicKey, canonical string, signature []byte) error {
	digest := sha256.Sum256([]byte(canonical))
	if !ecdsa.VerifyASN1(key, digest[:], signature) {
		return errors.New("signature does not verify")
	}
	return nil
}

// RotationStatement is the text a new device key signs to prove it is held by the Mac
// that is rotating: version, the device_id it succeeds and the lowercase hex SHA-256 of
// its own SubjectPublicKeyInfo DER, one per line, with no trailing newline. Its first
// line keeps it apart from CanonicalString, so neither can stand in for the other.
func RotationStatement(deviceID string, newPublicKey []byte) string {
	digest := sha256.Sum256(newPublicKey)
	return strings.Join([]string{rotationVersion, deviceID, hex.EncodeToString(digest[:])}, "\n")
}

// VerifyRotationProof checks that proof, an ASN.1 DER ECDSA signature, was made by the
// P-256 key newPublicKey (SubjectPublicKeyInfo DER) over RotationStatement for deviceID.
func VerifyRotationProof(deviceID string, newPublicKey, proof []byte) error {
	key, err := ParsePublicKey(newPublicKey)
	if err != nil {
		return err
	}
	return Verify(key, RotationStatement(deviceID, newPublicKey), proof)
}
