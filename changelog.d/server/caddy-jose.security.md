- Rebuild the Caddy proxy with go-jose v4.1.6 to fix the RSA JWK parsing denial of
  service in that dependency. Caddy's PKI modules still compile the unpatched go-jose
  v3 dependency; it remains visible to dependency scanning while an upstream fix is
  unavailable.
