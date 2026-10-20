#!/bin/bash
# End-to-end test of deploy/compose/upgrade.sh, in Docker: installs a release the way
# docs/install.md does, then upgrades it as an admin would, including a file they
# changed, a release candidate, a refused downgrade and a corrupted download. Caddy is
# left out.
#
#   scripts/test-upgrade.sh <image>     e.g. altiward-api:ci, as `make image` builds it
set -euo pipefail

SOURCE_IMAGE="${1:?image to make the test releases from}"
cd "$(dirname "$0")/.."
REPO=ghcr.io/altiward/altiward-api # compose.yaml's default image name
export COMPOSE_PROJECT_NAME=altiward-upgrade-test
T="$(mktemp -d)"
SITE="$T/site"
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; *) arch=arm64 ;; esac
if command -v sha256sum >/dev/null; then sha=(sha256sum); else sha=(shasum -a 256); fi

cleanup() {
  if [ -d "$SITE" ]; then (cd "$SITE" && docker compose down -v --timeout 5 >/dev/null 2>&1) || true; fi
  for v in 0.0.1 0.0.2 0.0.3-rc.1 0.0.3; do docker rmi "$REPO:$v" >/dev/null 2>&1 || true; done
  rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok - $*"; }

# release VERSION [COMPOSE_LINE] [SCRIPT_LINE]: writes the files of a server release to
# $T/rel-VERSION, appending a comment to the bundle's compose.yaml and upgrade.sh when
# given, as a later release would change them.
release() {
  local v="$1" out="$T/rel-$1"
  mkdir -p "$out"
  docker tag "$SOURCE_IMAGE" "$REPO:$v"
  docker save "$REPO:$v" | gzip >"$out/altiward-api-$v-linux-$arch.tar.gz"
  docker rmi "$REPO:$v" >/dev/null
  printf '## Server %s - 2026-01-01\n\n### Upgrade order\n\nServer first.\n\n### Breaking changes\n\nNone.\n\n### Security\n\nNone.\n\n### Changes\n\n- A test release.\n' \
    "$v" >"$out/RELEASE_NOTES.md"
  scripts/server-bundle.sh "$v" "$REPO:$v" "$out" "$out/RELEASE_NOTES.md" >/dev/null
  if [ -n "${2:-}${3:-}" ]; then
    local x="$T/unpack-$v" d
    mkdir -p "$x"
    tar -xzf "$out/altiward-server-$v.tar.gz" -C "$x"
    d="$x/altiward-server-$v/deploy/compose"
    [ -z "${2:-}" ] || echo "# $2" >>"$d/compose.yaml"
    [ -z "${3:-}" ] || echo "# $3" >>"$d/upgrade.sh"
    COPYFILE_DISABLE=1 tar --no-xattrs -C "$x" -czf "$out/altiward-server-$v.tar.gz" "altiward-server-$v"
  fi
  (cd "$out" && "${sha[@]}" ./*.tar.gz RELEASE_NOTES.md | sed 's| \./| |' >SHA256SUMS)
}

env_version() { sed -n 's/^ALTIWARD_VERSION=//p' "$SITE/.env"; }
upgrade() { "$SITE/upgrade.sh" --yes --skip-signature "$@"; }

# Version ordering: each pair is lower, then higher.
for pair in "0.3.0-rc.1 0.3.0" "0.3.0-rc.1 0.3.0-rc.2" "0.3.0-rc.2 0.3.0-rc.10" "0.9.9 0.10.0" \
  "0.3.0-lab.8ce2772 0.3.0-rc.1" "0.3.0-lab.8ce2772 0.3.0" "dev 0.0.1" "0.3.0 0.3.1-rc.1"; do
  read -r lo hi <<<"$pair"
  [ "$(deploy/compose/upgrade.sh --compare "$lo" "$hi")" = -1 ] || fail "$lo should sort before $hi"
  [ "$(deploy/compose/upgrade.sh --compare "$hi" "$lo")" = 1 ] || fail "$hi should sort after $lo"
done
[ "$(deploy/compose/upgrade.sh --compare 1.0.0 1.0.0)" = 0 ] || fail "1.0.0 should equal itself"
ok "versions sort as semantic versioning does, release candidates before their release"

echo "Making releases 0.0.1, 0.0.2, 0.0.3-rc.1 and 0.0.3"
release 0.0.1
release 0.0.2 "changed in 0.0.2"
release 0.0.3-rc.1
release 0.0.3 "changed in 0.0.3" "upgrade.sh from 0.0.3"

echo "Installing 0.0.1 as the install guide does"
tar -xzf "$T/rel-0.0.1/altiward-server-0.0.1.tar.gz" -C "$T"
mv "$T/altiward-server-0.0.1/deploy/compose" "$SITE"
cat >"$SITE/.env" <<EOF
ALTIWARD_VERSION=0.0.1
ALTIWARD_AGENT_HOST=agents.example.com
ALTIWARD_CONSOLE_HOST=console.example.com
ALTIWARD_CONSOLE_ALLOW=10.0.0.0/8
POSTGRES_PASSWORD=$(openssl rand -hex 12)
ALTIWARD_AGENT_TOKENS=test=$(openssl rand -hex 12)
ALTIWARD_CONSOLE_TOKENS=test=$(openssl rand -hex 12)
EOF
chmod 600 "$SITE/.env"
printf 'services:\n  caddy:\n    profiles: ["off"]\n' >"$SITE/compose.override.yaml"
docker load -i "$T/rel-0.0.1/altiward-api-0.0.1-linux-$arch.tar.gz" >/dev/null
(cd "$SITE" && docker compose up -d --wait --wait-timeout 180 >/dev/null 2>&1) || fail "0.0.1 didn't start"
ok "0.0.1 installed and healthy"

# Untouched files are replaced; a file the admin changed that the release doesn't
# change stays theirs.
echo "# my Caddyfile change" >>"$SITE/Caddyfile"
upgrade "$T/rel-0.0.2" >"$T/out" 2>&1 || { cat "$T/out"; fail "upgrade to 0.0.2 failed"; }
[ "$(env_version)" = 0.0.2 ] || fail ".env says $(env_version), not 0.0.2"
grep -q "changed in 0.0.2" "$SITE/compose.yaml" || fail "compose.yaml wasn't replaced"
grep -q "my Caddyfile change" "$SITE/Caddyfile" || fail "the admin's Caddyfile was replaced"
[ ! -e "$SITE/Caddyfile.new" ] || fail "Caddyfile.new left for a file the release doesn't change"
ls "$SITE"/backups/*-from-0.0.1/altiward.dump >/dev/null 2>&1 || fail "no database backup"
[ -s "$(ls "$SITE"/backups/*-from-0.0.1/altiward.dump)" ] || fail "the database backup is empty"
[ "$(stat -c %a "$SITE/.env" 2>/dev/null || stat -f %Lp "$SITE/.env")" = 600 ] || fail ".env lost its permissions"
ok "upgraded to 0.0.2: files replaced, the changed Caddyfile kept, the database backed up"

upgrade "$T/rel-0.0.2" >"$T/out" 2>&1 || fail "rerunning the same release failed"
grep -q "Already running 0.0.2" "$T/out" || fail "rerunning the same release didn't say so"
if upgrade "$T/rel-0.0.1" >"$T/out" 2>&1; then fail "a downgrade went ahead"; fi
grep -q "Going back isn't supported" "$T/out" || { cat "$T/out"; fail "the downgrade wasn't refused for the right reason"; }
ok "the same release is a no-op, and a downgrade is refused"

cp -R "$T/rel-0.0.3" "$T/rel-bad"
echo "tampered" >>"$T/rel-bad/RELEASE_NOTES.md"
if upgrade "$T/rel-bad" >"$T/out" 2>&1; then fail "a corrupted release was installed"; fi
grep -q "doesn't match SHA256SUMS" "$T/out" || { cat "$T/out"; fail "the corruption wasn't reported"; }
if ! command -v cosign >/dev/null; then
  if "$SITE/upgrade.sh" --yes "$T/rel-0.0.3" >"$T/out" 2>&1; then fail "went ahead without a signature check"; fi
  grep -q "cosign isn't installed" "$T/out" || fail "didn't explain the missing cosign"
fi
[ "$(env_version)" = 0.0.2 ] || fail "a refused upgrade changed .env"
ok "a corrupted release, and one whose signature can't be checked, are refused"

upgrade "$T/rel-0.0.3-rc.1" >"$T/out" 2>&1 || { cat "$T/out"; fail "upgrade to 0.0.3-rc.1 failed"; }
[ "$(env_version)" = 0.0.3-rc.1 ] || fail ".env says $(env_version), not 0.0.3-rc.1"
grep -q "is a release candidate" "$T/out" || fail "didn't say 0.0.3-rc.1 is a release candidate"
ok "upgraded to the release candidate 0.0.3-rc.1"

# A file both the admin and the release changed stops the upgrade with a .new copy,
# after the new release's upgrade.sh has taken over.
echo "# my compose change" >>"$SITE/compose.yaml"
status=0
upgrade "$T/rel-0.0.3" >"$T/out" 2>&1 || status=$?
[ "$status" = 3 ] || { cat "$T/out"; fail "a conflicting compose.yaml should stop with 3, got $status"; }
grep -q "Updated upgrade.sh from 0.0.3" "$T/out" || fail "upgrade.sh didn't hand over to 0.0.3's"
grep -q "upgrade.sh from 0.0.3" "$SITE/upgrade.sh" || fail "upgrade.sh wasn't replaced"
grep -q "changed in 0.0.3" "$SITE/compose.yaml.new" || fail "no compose.yaml.new from 0.0.3"
grep -q "my compose change" "$SITE/backups/before-0.0.3/compose.yaml" || fail "the admin's compose.yaml wasn't saved"
[ "$(env_version)" = 0.0.3-rc.1 ] || fail "a stopped upgrade changed .env"
ok "a compose.yaml changed on both sides stops the upgrade with compose.yaml.new"

upgrade --merged "$T/rel-0.0.3" >"$T/out" 2>&1 || { cat "$T/out"; fail "the --merged upgrade failed"; }
[ "$(env_version)" = 0.0.3 ] || fail ".env says $(env_version), not 0.0.3"
grep -q "my compose change" "$SITE/compose.yaml" || fail "the admin's compose.yaml was replaced"
[ ! -e "$SITE/compose.yaml.new" ] || fail "compose.yaml.new was left behind"
grep -q "is running and healthy" "$T/out" || fail "didn't report healthy"
ok "after merging, the upgrade from the candidate to 0.0.3 keeps the admin's compose.yaml"
sed 's/^/    | /' "$T/out" # what an admin sees

if upgrade "$T/rel-0.0.3-rc.1" >"$T/out" 2>&1; then fail "a release candidate replaced its release"; fi
ok "a release candidate doesn't replace its release"

echo "All upgrade tests passed."
