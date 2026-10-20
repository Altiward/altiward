#!/bin/bash
# Builds AppIcon.icns from the brand's macOS app icon SVG, the Installer backgrounds from
# the brand mark, the square avatar and this repository's GitHub social preview image
# (`make app-icon`). The SVGs in assets/brand are the source; the outputs are
# committed so packaging needs no renderer.
#
#   scripts/brand/generate.sh [source.svg]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BRAND="$ROOT/assets/brand"
SVG="${1:-$BRAND/altiward-app-icon.svg}"
"$HERE/export.sh" console "$ROOT/console"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ICONSET="$WORK/AppIcon.iconset"
mkdir -p "$ICONSET"
# Each point size at 1x and 2x, as iconutil expects.
swift "$HERE/render-icon.swift" "$SVG" "$ICONSET" 16 32 128 256 512
iconutil -c icns "$ICONSET" -o "$ROOT/agent/packaging/AppIcon.icns"
echo "wrote $ROOT/agent/packaging/AppIcon.icns from $SVG"

# The mark in the corner under Installer's list of steps: dark ink in light mode, light
# ink in dark mode. One TIFF per appearance holds both scales.
mkdir -p "$ROOT/agent/packaging/installer"
for variant in "background:altiward-mark.svg" "background-dark:altiward-mark-on-dark.svg"; do
  name="${variant%%:*}"
  swift "$HERE/render-background.swift" "$BRAND/${variant#*:}" "$WORK/$name" 112 80 12
  tiffutil -cathidpicheck "$WORK/$name.png" "$WORK/$name@2x.png" -out "$ROOT/agent/packaging/installer/$name.tiff" 2>/dev/null
  echo "wrote $ROOT/agent/packaging/installer/$name.tiff"
done

# The square profile picture (the GitHub organisation's), full bleed because the sites
# round or circle-crop it themselves. 1024 px, beside its SVG.
swift "$HERE/render-icon.swift" "$BRAND/altiward-avatar.svg" "$WORK" 512
mv "$WORK/icon_512x512@2x.png" "$BRAND/altiward-avatar.png"
echo "wrote $BRAND/altiward-avatar.png"

# This repository's GitHub social preview, 1280x640, uploaded in the repository's
# Settings. render-social.swift's header says how to render the other repositories' ones.
mkdir -p "$ROOT/docs/brand"
swift "$HERE/render-social.swift" "$ROOT/docs/brand/social-altiward.png" altiward
echo "wrote $ROOT/docs/brand/social-altiward.png"
