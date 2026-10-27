#!/bin/bash
# Builds altiward-server-<version>.tar.gz: what a site needs besides the image and the
# agent package. Its layout matches the paths docs/install.md names.
#
#   scripts/server-bundle.sh <version> <image reference> <output directory> [release notes]
#
# The image reference should be pinned by digest, e.g. ghcr.io/owner/altiward-api@sha256:…
# The release notes, from scripts/release-notes.sh, go in as RELEASE_NOTES.md.
set -euo pipefail

VERSION="${1:?version, e.g. 0.1.0 or 0.1.0-rc.1}"
IMAGE="${2:?image reference}"
OUT="${3:?output directory}"
NOTES="${4:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || { echo "version must be X.Y.Z or X.Y.Z-rc.N, got $VERSION" >&2; exit 1; }

cd "$(dirname "$0")/.."
NAME="altiward-server-$VERSION"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
D="$STAGE/$NAME"

mkdir -p "$D/deploy" "$D/docs" "$D/integrations" "$D/profiles"
cp -R deploy/compose "$D/deploy/compose"
rm -f "$D/deploy/compose/.env"
# The example starts on this release.
sed -e "s/^ALTIWARD_VERSION=.*/ALTIWARD_VERSION=$VERSION/" deploy/compose/env.example > "$D/deploy/compose/env.example"
chmod 755 "$D/deploy/compose/upgrade.sh"
# upgrade.sh compares each deployment file with the copy the release shipped, to tell
# whether the admin changed it.
(cd "$D/deploy/compose" && find . -type f ! -path './.altiward/*' | while read -r f; do
  mkdir -p ".altiward/shipped/$(dirname "$f")"
  cp "$f" ".altiward/shipped/$f"
done)
cp docs/install.md docs/data-handling.md "$D/docs/"
# The install guide's pictures, at the paths it uses.
mkdir -p "$D/docs/images"
cp -R docs/images/install "$D/docs/images/"
for siem in splunk sentinel syslog; do
  mkdir -p "$D/integrations/$siem"
  cp "integrations/$siem/README.md" "$D/integrations/$siem/README.md"
done
# Sentinel's setup script, to upload to Cloud Shell.
cp deploy/sentinel/setup.sh "$D/integrations/sentinel/setup.sh"
chmod 755 "$D/integrations/sentinel/setup.sh"
# The script that lets the server read Intune, to upload to Cloud Shell.
mkdir -p "$D/integrations/intune"
cp deploy/intune/setup.sh "$D/integrations/intune/setup.sh"
chmod 755 "$D/integrations/intune/setup.sh"
# The Altiward overview dashboard for Splunk.
cp integrations/splunk/altiward_overview.xml "$D/integrations/splunk/"
# The Altiward overview workbook, as a template to deploy and as JSON to paste.
cp integrations/sentinel/workbook.json integrations/sentinel/workbook.arm.json "$D/integrations/sentinel/"
# The agent's Mac profiles. Not the Privileges plist or profile: their checksum is a
# placeholder until the agent build fills it in, and Privileges won't run a hook whose
# checksum doesn't match, so admins take those files from the agent release.
cp deploy/mdm/com.altiward.agent.plist deploy/mdm/com.altiward.agent.mobileconfig \
  deploy/mdm/altiward-login-items.mobileconfig "$D/profiles/"
cp LICENSE NOTICE THIRD_PARTY_NOTICES.md "$D/"
[ -z "$NOTES" ] || cp "$NOTES" "$D/RELEASE_NOTES.md"
cat > "$D/README.md" <<README
# Altiward server $VERSION

Start with docs/install.md (upgrading: its "Releases and updates" section, and
RELEASE_NOTES.md). The deployment files are in deploy/compose, the agent's example Mac
profiles in profiles, and SIEM setup in integrations. The SAP Privileges keys come with
each agent release, pinned to that release's hook. For a security review,
docs/data-handling.md lists what Altiward stores and where data goes.

Image: $IMAGE
README

mkdir -p "$OUT"
# Without macOS's extended attributes, which Linux tar warns about.
COPYFILE_DISABLE=1 tar --no-xattrs -C "$STAGE" -czf "$OUT/$NAME.tar.gz" "$NAME"
echo "$OUT/$NAME.tar.gz"
