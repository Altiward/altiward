# Temporary Go JOSE v3 security backport

Caddy 2.11.7's Smallstep PKI dependencies still import Go JOSE v3. Upstream v3.0.5
has no released fix for the three advisories below. The proxy's `go.mod` replaces
that dependency with this copy, retaining its v3 API and the standard Caddy modules.
The server uses the separate upstream v4.1.6 module.

Base: `github.com/go-jose/go-jose/v3` v3.0.5, upstream commit
`be2f6548701d4ba561cd61c7d4a2f1289b66c273`. The upstream module checksum is
`h1:BLLJWbC4nMZOfuPVxoZIxeYsn6Nl2r1fITaJ78UQlVQ=`. Go sources, tests, the JSON
test fixture and both licences are retained. Formatting follows the build's Go
version, and two upstream comments differ only in punctuation.
Module dependencies use the patched versions selected by the proxy.

| Advisory | Upstream fix | Backport |
| --- | --- | --- |
| [GHSA-4w3g-jfj2-cw2q](https://github.com/go-jose/go-jose/security/advisories/GHSA-4w3g-jfj2-cw2q) | [35883f7999e87cbd1b1f4cda07fdad8cd71c3dd6](https://github.com/go-jose/go-jose/commit/35883f7999e87cbd1b1f4cda07fdad8cd71c3dd6) | Reject empty CBC-HMAC ciphertext before unpadding. Includes upstream authenticated-empty-ciphertext tests. |
| [GHSA-vvm8-gf78-28g4](https://github.com/go-jose/go-jose/security/advisories/GHSA-vvm8-gf78-28g4) | [a31af25836222f4c45d366d6e8f9b1049dd9935a](https://github.com/go-jose/go-jose/commit/a31af25836222f4c45d366d6e8f9b1049dd9935a) | Limit JSON nesting to 10,000 containers. Tests cover arrays and objects through unmarshalling and the streaming decoder, at and above the limit. |
| [GHSA-mgcc-cww5-fp2q](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q) | [a0111f82742fa92bceec9ede40845e73319e6230](https://github.com/go-jose/go-jose/commit/a0111f82742fa92bceec9ede40845e73319e6230) | Bound RSA moduli, reject inconsistent or oversized primes before private-key validation, and reject private parameters in embedded `jwk` and `epk` headers. Includes upstream key-boundary and embedded-key tests. |

The RSA patch's JWS header assignment is moved before sanitising general signatures.
Its algorithm-allowlist changes target the v4 API and are not part of this v3
backport. `getJWK` moves to a test helper as upstream does. Private key import via
`JSONWebKey.UnmarshalJSON` remains available for trusted key material.

Run `scripts/test-caddy-jose.sh` from the repository root. CI and the release workflow
run the complete retained upstream suite and the security regressions before building
the proxy, all with the race detector except upstream's `TestOpaqueKeyRoundtripJWE`: it
starts no goroutines and takes more than five minutes under the detector. The final amd64 and arm64 binaries are still
scanned independently. Version-only scanners cannot identify these source backports;
any advisory exception must remain scoped to this replacement and its regression tests.

Remove the backport when a supported upstream dependency chain no longer needs it. Take
out, together:

- this directory, and the `replace` in `deploy/caddy/go.mod`
- the `third_party` lines in `deploy/caddy/Dockerfile` and `deploy/caddy/.dockerignore`
- `scripts/test-caddy-jose.sh`, and the steps that run it in `.github/workflows/ci.yml`
  (the backend job) and `.github/workflows/release-server.yml`
- the go-jose annotations in `REUSE.toml`, and `LICENSES/BSD-3-Clause.txt` if nothing
  else uses it
- the backport label in `scripts/third-party-notices.mjs`
- any scanner exceptions for these advisories

Then regenerate licence notices, rebuild the image and verify both architectures before
updating deployment pins. Preserve `LICENSE` (Apache 2.0) and `json/LICENSE`
(BSD 3-Clause); the generated image notices include both.
