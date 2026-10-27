# The deployment proxy

Compose and Azure use the same digest-pinned Caddy image from `image.txt`. It is Caddy
2.11.7, rebuilt with Go 1.27.3 and `golang.org/x/net` 0.62.0. The upstream image still
contains older vulnerable dependencies, so copying its tag alone does not fix them.
This image includes the standard Caddy modules and the upstream image's
`nomysql,nopgx,nobadger` tags. Its runtime contains the binary, trusted CA certificates
and licence notices, with no shell or package manager.

Build and verify it locally from the repository root:

```sh
make notices
scripts/build-caddy.sh /tmp/altiward-caddy
for arch in amd64 arm64; do
  go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -mode=binary "/tmp/altiward-caddy/caddy-$arch"
done
docker load -i /tmp/altiward-caddy/caddy.oci.tar
CADDY_IMAGE=altiward-caddy:build scripts/test-azure-proxy.sh altiward-api:ci
```

`osv-scanner.toml` lists advisories for modules in `go.mod` that never reach the binary,
with the reason for each, so dependency scanners such as OpenSSF Scorecard skip them.
Remove an entry when its module is upgraded past the fix.

The build supports amd64 and arm64 without running the target binaries under emulation.
Pinned builder, Dockerfile frontend, compiler and certificate images, module checksums,
a fixed source date, stripped build IDs and normalised layer timestamps make the final
image reproducible. Both platforms take the CA bundle from the amd64 certificate image:
the two platforms' bundles are identical but carry different timestamps, and BuildKit
may reuse either copy for both, which would make the digest vary between builds. Each invocation creates a fresh builder and removes it afterwards.
Attached
build attestations are omitted from this image's index because their varying timestamps
would change its digest. The server image retains its usual provenance and SBOM.

When updating the proxy, change the source/dependency pins and regenerate notices. Build
the archive, review its reported digest, then put the new image reference in `image.txt`,
`deploy/compose/compose.yaml` and `deploy/azure/main.bicep`. Run `make azure-template`,
rebuild from a clean cache to confirm the same digest, scan both extracted final binaries,
and rerun the proxy checks. The build helper fails until all deployment pins match.

The server release workflow builds and scans the archive, then copies those exact OCI
blobs to GHCR and verifies the published digest. A newly introduced digest becomes
available there when that server release is published. Local builds do not publish it.
Keep using the previous server release's complete deployment bundle until upgrading.

`make notices` also generates this directory's `THIRD_PARTY_NOTICES.md` from the linked
proxy modules with the same build tags. The proxy keeps Caddy's existing CC0-1.0 licence
for blake3; that exception does not change the server or console dependency policy.
