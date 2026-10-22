package sentinel

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// Certificate is an Entra app registration's certificate credential. Instead of sending a
// secret, ClientCredentials signs a short-lived client assertion with the private key, and
// Entra ID checks it against the certificate uploaded to the app.
type Certificate struct {
	Leaf *x509.Certificate
	Key  *rsa.PrivateKey
}

// LoadCertificate reads a PEM file holding the certificate and its unencrypted RSA private
// key, in either order.
func LoadCertificate(path string) (*Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertificate(data)
}

// ParseCertificate reads the certificate and private key from PEM. The first certificate is
// the app's; any after it are its chain, which Entra ID doesn't need.
func ParseCertificate(data []byte) (*Certificate, error) {
	var c Certificate
	for {
		var block *pem.Block
		if block, data = pem.Decode(data); block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if c.Leaf != nil {
				continue
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("certificate: %w", err)
			}
			c.Leaf = leaf
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("private key: %w", err)
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key: Entra ID needs an RSA key, got %T", key)
			}
			c.Key = rsaKey
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("private key: %w", err)
			}
			c.Key = key
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("the private key is encrypted: export it without a passphrase")
		}
	}
	if c.Leaf == nil {
		return nil, errors.New("no CERTIFICATE in the file")
	}
	if c.Key == nil {
		return nil, errors.New("no private key in the file: put the certificate and its key in one PEM file")
	}
	if pub, ok := c.Leaf.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&c.Key.PublicKey) {
		return nil, errors.New("the private key doesn't belong to the certificate")
	}
	return &c, nil
}

// assertion is a client assertion for the token endpoint aud: a JWT signed with PS256 that
// names the certificate by its SHA-256 thumbprint, as Entra ID documents for certificate
// credentials. It is valid for 10 minutes.
func (c *Certificate) assertion(clientID, aud string, now time.Time) (string, error) {
	thumbprint := sha256.Sum256(c.Leaf.Raw)
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": b64(thumbprint[:])})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"aud": aud, "iss": clientID, "sub": clientID, "jti": hex.EncodeToString(jti),
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	signed := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPSS(rand.Reader, c.Key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return signed + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
