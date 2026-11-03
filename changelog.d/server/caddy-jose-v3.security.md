- The Caddy proxy is rebuilt with a backport of the go-jose fixes for GHSA-4w3g-jfj2-cw2q,
  GHSA-vvm8-gf78-28g4 and GHSA-mgcc-cww5-fp2q into its go-jose v3 dependency, which has
  no fixed release. The proxy rejects empty CBC-HMAC ciphertext, excessively nested JSON,
  and malformed or oversized RSA keys before costly validation. CI and releases test the
  backport before building the proxy. The new image is
  `ghcr.io/altiward/caddy:2.11.7-altiward.4`.
