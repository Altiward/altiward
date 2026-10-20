#!/bin/bash
# Prints one release's section of CHANGELOG.md, the notes published with the release.
# Fails if the section is missing, still unreleased, or lacks one of the four headings.
# A server release candidate (X.Y.Z-rc.N) takes the coming release's section,
# which may still be unreleased.
#
#   scripts/release-notes.sh server 0.1.0
#   scripts/release-notes.sh server 0.1.0-rc.1
#   scripts/release-notes.sh agent 0.1.0
set -euo pipefail

PRODUCT="${1:?server or agent}"
VERSION="${2:?version, e.g. 0.1.0}"
case "$PRODUCT" in
  server) TITLE="Server" ;;
  agent) TITLE="Agent" ;;
  *) echo "product must be server or agent, got $PRODUCT" >&2; exit 1 ;;
esac
RELEASE="$VERSION"
CANDIDATE=""
if [[ "$VERSION" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-rc\.[0-9]+$ ]]; then
  [ "$PRODUCT" = server ] || { echo "only the server has release candidates" >&2; exit 1; }
  RELEASE="${BASH_REMATCH[1]}"
  CANDIDATE="$VERSION"
elif ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "version must be X.Y.Z, or X.Y.Z-rc.N for a server release candidate, got $VERSION" >&2
  exit 1
fi
cd "$(dirname "$0")/.."

# The section runs from its heading to the next release heading.
SECTION="$(awk -v head="## $TITLE $RELEASE - " '
  index($0, head) == 1 { found = 1; print; next }
  found && /^## / { exit }
  found { print }
' CHANGELOG.md)"

if [ -z "$SECTION" ]; then
  echo "CHANGELOG.md has no \"## $TITLE $RELEASE - <date>\" section" >&2
  exit 1
fi
DATE="$(head -1 <<<"$SECTION" | sed "s/^## $TITLE $RELEASE - //")"
if [ -n "$CANDIDATE" ]; then
  SECTION="## $TITLE $CANDIDATE - $(date -u +%F), release candidate for $RELEASE
$(tail -n +2 <<<"$SECTION")"
elif ! [[ "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "CHANGELOG.md: $TITLE $RELEASE is dated \"$DATE\"; put the release date (YYYY-MM-DD) before releasing" >&2
  exit 1
fi
for heading in "Upgrade order" "Breaking changes" "Security" "Changes"; do
  grep -qx "### $heading" <<<"$SECTION" || { echo "CHANGELOG.md: $TITLE $RELEASE has no \"### $heading\"" >&2; exit 1; }
done
printf '%s\n' "$SECTION"
