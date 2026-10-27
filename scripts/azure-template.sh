#!/bin/bash
# Moves the Deploy to Azure template to a server release: sets the version in
# deploy/azure/main.bicep and rebuilds azuredeploy.json (and intune-read.json, which has no
# version, so it only follows the tag through its button). For a release, not a candidate,
# it also points every Deploy to Azure button at the release's tag, so the buttons only
# ever deploy a release. Run it for the release commit (docs/releasing.md); the release
# workflow refuses a tag the template doesn't match.
#
#   scripts/azure-template.sh <version>     e.g. 0.2.0, or 0.2.0-rc.1
set -euo pipefail

v="${1:?the server version, such as 0.2.0}"
[[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || { echo "want X.Y.Z or X.Y.Z-rc.N, got $v" >&2; exit 1; }
cd "$(dirname "$0")/.."

# in_place FILE SED-ARGS...: sed -i, on macOS and Linux alike.
in_place() {
  local f="$1"
  shift
  sed "$@" "$f" >"$f.new" && mv "$f.new" "$f"
}

in_place deploy/azure/main.bicep -e "s/^var version = '.*'\$/var version = '$v'/"
grep -q "^var version = '$v'\$" deploy/azure/main.bicep || { echo "no version line in deploy/azure/main.bicep" >&2; exit 1; }
make -s azure-template
echo "deploy/azure runs $v."

if [[ "$v" != *-rc.* ]]; then
  # The buttons link to the template on raw.githubusercontent.com at a server-v tag,
  # URL-encoded; the CLI instructions link to it plainly.
  tag='server-v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?'
  for f in README.md docs/install.md deploy/azure/README.md; do
    in_place "$f" -E -e "s/(Altiward%2Faltiward%2F)$tag(%2Fdeploy%2Fazure%2F)/\1server-v$v\3/g" \
      -e "s#(Altiward/altiward/)$tag(/deploy/azure/)#\1server-v$v\3#g"
  done
  echo "The Deploy to Azure links point at server-v$v."
fi
