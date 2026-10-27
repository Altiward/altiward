package sentinel

import "github.com/Altiward/altiward/integrations/entra"

// Certificate is an Entra app registration's certificate credential. Instead of sending a
// secret, ClientCredentials signs a short-lived client assertion with the private key, and
// Entra ID checks it against the certificate uploaded to the app.
type Certificate = entra.Certificate

// LoadCertificate reads a PEM file holding the certificate and its unencrypted RSA private
// key, in either order.
func LoadCertificate(path string) (*Certificate, error) { return entra.LoadCertificate(path) }

// ParseCertificate reads the certificate and private key from PEM. The first certificate is
// the app's; any after it are its chain, which Entra ID doesn't need.
func ParseCertificate(data []byte) (*Certificate, error) { return entra.ParseCertificate(data) }
