#!/bin/bash
# Build locally, check the pinned image, and extract both final binaries for scanning.
# Does not publish. The release workflow copies this exact archive after scanning.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:?usage: scripts/build-caddy.sh OUTPUT_DIRECTORY}"
mkdir -p "$out"
out=$(cd "$out" && pwd)
# An isolated, pinned builder makes runner upgrades and existing caches irrelevant.
builder="altiward-caddy-$$"
docker buildx create --name "$builder" --driver docker-container \
  --driver-opt image=moby/buildkit:v0.33.1@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea >/dev/null
trap 'docker buildx rm --force "$builder" >/dev/null 2>&1 || true' EXIT
docker buildx build --builder "$builder" --platform linux/amd64,linux/arm64 \
  --provenance=false --sbom=false --build-arg SOURCE_DATE_EPOCH=1792886400 \
  --tag altiward-caddy:build \
  --output "type=oci,dest=$out/caddy.oci.tar,rewrite-timestamp=true" \
  --metadata-file "$out/metadata.json" deploy/caddy
python3 scripts/check-caddy-image.py "$out"
