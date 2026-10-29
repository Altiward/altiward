#!/bin/bash
# End-to-end test of deploy/compose/upgrade.sh, in Docker: installs a release the way
# docs/install.md does, then upgrades it as an admin would, including a file they
# changed, a release candidate, a refused downgrade and a corrupted download. Releases
# given by version are downloaded from a local file server standing in for GitHub,
# including one with a file missing and one that doesn't match its checksums. Caddy is
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
WWW="$T/www" # served as GitHub serves releases: server-v<version>/<file>
http_pid=""
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; *) arch=arm64 ;; esac
if command -v sha256sum >/dev/null; then sha=(sha256sum); else sha=(shasum -a 256); fi

cleanup() {
  [ -z "$http_pid" ] || kill "$http_pid" 2>/dev/null || true
  if [ -d "$SITE" ]; then (cd "$SITE" && docker compose down -v --timeout 5 >/dev/null 2>&1) || true; fi
  for v in 0.0.1 0.0.2 0.0.3-rc.1 0.0.3; do docker rmi "$REPO:$v" >/dev/null 2>&1 || true; done
  rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok - $*"; }

# release VERSION [COMPOSE_LINE] [SCRIPT_LINE]: writes the files of a server release to
# $T/rel-VERSION and publishes them on the file server, appending a comment to the
# bundle's compose.yaml and upgrade.sh when given, as a later release would change them.
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
  # Unsigned: the tests run with --skip-signature, but a download needs the file.
  echo '{}' >"$out/SHA256SUMS.sigstore.json"
  ln -sfn "$out" "$WWW/server-v$v"
}

env_version() { sed -n 's/^ALTIWARD_VERSION=//p' "$SITE/.env"; }
# As an admin runs it, with a stand-in cosign (below) first on PATH, so a cosign installed
# here doesn't check the test releases' empty signatures. upgrade.sh checks the signature
# whenever cosign can, even with --skip-signature.
upgrade() { PATH="$T/cosign:$PATH" "$SITE/upgrade.sh" --yes --skip-signature "$@"; }

# The stand-in cosign reports FAKE_COSIGN_VERSION, 3.1.4 unless set, and accepts a
# signature only when asked as that version must be asked. Cosign 2.4 reads the release's
# Sigstore bundle only with --new-bundle-format, which later 2.x accept, and cosign 3
# deprecates the flag, so it's refused there as a later cosign may. FAKE_COSIGN_REJECT
# makes it reject anyway.
mkdir -p "$T/cosign"
cat >"$T/cosign/cosign" <<'EOF'
#!/bin/bash
FAKE_COSIGN_VERSION="${FAKE_COSIGN_VERSION:-3.1.4}"
if [ "$1" = version ]; then printf 'GitVersion:    v%s\n' "$FAKE_COSIGN_VERSION"; exit 0; fi
[ "$1" = verify-blob ] || { echo "Error: unexpected cosign $1" >&2; exit 2; }
args=" $* "
case "$args" in
  *" --certificate-identity https://github.com/Altiward/altiward/.github/workflows/release-server.yml@refs/tags/server-v"*) ;;
  *) echo "Error: not asked for the release workflow's identity" >&2; exit 1 ;;
esac
[[ "$args" == *" --certificate-oidc-issuer https://token.actions.githubusercontent.com "* ]] \
  || { echo "Error: not asked for GitHub's issuer" >&2; exit 1; }
[[ "$args" == *" --bundle "* ]] || { echo "Error: no bundle" >&2; exit 1; }
if [[ "$FAKE_COSIGN_VERSION" == 2.* ]]; then
  [[ "$args" == *" --new-bundle-format "* ]] \
    || { echo "Error: bundle does not contain cert for verification, please provide public key" >&2; exit 1; }
elif [[ "$args" == *" --new-bundle-format "* ]]; then
  echo "Error: unknown flag: --new-bundle-format" >&2; exit 1
fi
[ -z "${FAKE_COSIGN_REJECT:-}" ] \
  || { echo "Error: none of the expected identities matched what was in the certificate" >&2; exit 1; }
echo "Verified OK"
EOF
chmod +x "$T/cosign/cosign"

# Version ordering: each pair is lower, then higher.
for pair in "0.3.0-rc.1 0.3.0" "0.3.0-rc.1 0.3.0-rc.2" "0.3.0-rc.2 0.3.0-rc.10" "0.9.9 0.10.0" \
  "0.3.0-lab.8ce2772 0.3.0-rc.1" "0.3.0-lab.8ce2772 0.3.0" "dev 0.0.1" "0.3.0 0.3.1-rc.1"; do
  read -r lo hi <<<"$pair"
  [ "$(deploy/compose/upgrade.sh --compare "$lo" "$hi")" = -1 ] || fail "$lo should sort before $hi"
  [ "$(deploy/compose/upgrade.sh --compare "$hi" "$lo")" = 1 ] || fail "$hi should sort after $lo"
done
[ "$(deploy/compose/upgrade.sh --compare 1.0.0 1.0.0)" = 0 ] || fail "1.0.0 should equal itself"
ok "versions sort as semantic versioning does, release candidates before their release"

mkdir -p "$WWW"
python3 -u -m http.server 0 --bind 127.0.0.1 --directory "$WWW" >"$T/http.log" 2>&1 &
http_pid=$!
port=""
for _ in $(seq 1 50); do
  port="$(sed -n 's/^Serving HTTP on .* port \([0-9][0-9]*\) .*/\1/p' "$T/http.log")"
  [ -n "$port" ] && break
  sleep 0.2
done
[ -n "$port" ] || { cat "$T/http.log"; fail "the local file server didn't start"; }
export ALTIWARD_RELEASES_URL="http://127.0.0.1:$port"

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
upgrade 0.0.2 >"$T/out" 2>&1 || fail "rerunning the same version failed"
grep -q "Already running 0.0.2" "$T/out" || fail "rerunning the same version didn't say so"
if upgrade "$T/rel-0.0.1" >"$T/out" 2>&1; then fail "a downgrade went ahead"; fi
grep -q "Going back isn't supported" "$T/out" || { cat "$T/out"; fail "the downgrade wasn't refused for the right reason"; }
if upgrade 0.0.1 >"$T/out" 2>&1; then fail "a downgrade by version went ahead"; fi
grep -q "Going back isn't supported" "$T/out" || { cat "$T/out"; fail "the downgrade by version wasn't refused for the right reason"; }
[ ! -e "$SITE/releases" ] || fail "downloaded a release it doesn't need"
ok "the same release is a no-op, and a downgrade is refused, without downloading either"

cp -R "$T/rel-0.0.3" "$T/rel-bad"
echo "tampered" >>"$T/rel-bad/RELEASE_NOTES.md"
if upgrade "$T/rel-bad" >"$T/out" 2>&1; then fail "a corrupted release was installed"; fi
grep -q "doesn't match SHA256SUMS" "$T/out" || { cat "$T/out"; fail "the corruption wasn't reported"; }
if ! command -v cosign >/dev/null; then
  if "$SITE/upgrade.sh" --yes "$T/rel-0.0.3" >"$T/out" 2>&1; then fail "went ahead without a signature check"; fi
  grep -q "cosign isn't installed" "$T/out" || fail "didn't explain the missing cosign"
fi
if PATH="$T/cosign:$PATH" FAKE_COSIGN_VERSION=2.2.4 "$SITE/upgrade.sh" --yes 0.0.3 >"$T/out" 2>&1; then
  fail "went ahead with a cosign too old to check the signature"
fi
grep -q "cosign 2.2.4 is too old to check this release's signature: install cosign 2.4 or later" "$T/out" \
  || { cat "$T/out"; fail "didn't say cosign 2.2.4 is too old"; }
! grep -q "don't install it" "$T/out" || fail "called a release unsigned because cosign is too old"
[ ! -e "$SITE/releases" ] || fail "downloaded a release it can't check"
for v in 2.4.1 3.1.4; do
  if FAKE_COSIGN_VERSION=$v FAKE_COSIGN_REJECT=1 upgrade "$T/rel-0.0.3" >"$T/out" 2>&1; then
    fail "a release cosign $v rejected was installed"
  fi
  grep -q "cosign $v says: Error: none of the expected identities matched" "$T/out" \
    || { cat "$T/out"; fail "didn't pass on cosign $v's error"; }
  grep -q "SHA256SUMS isn't signed by Altiward's release workflow for 0.0.3: don't install it" "$T/out" \
    || { cat "$T/out"; fail "cosign $v's rejection wasn't reported as unsigned"; }
done
[ "$(env_version)" = 0.0.2 ] || fail "a refused upgrade changed .env"
ok "a corrupted release, one whose signature can't be checked, and one cosign rejects, are refused"

# 0.0.4 is published without its image, so the download stops partway.
mkdir "$WWW/server-v0.0.4"
cp "$T/rel-0.0.3/RELEASE_NOTES.md" "$WWW/server-v0.0.4/"
echo "not a bundle" >"$WWW/server-v0.0.4/altiward-server-0.0.4.tar.gz"
if upgrade 0.0.4 >"$T/out" 2>&1; then fail "a release missing a file was installed"; fi
grep -q "couldn't download altiward-api-0.0.4-linux-$arch.tar.gz" "$T/out" || { cat "$T/out"; fail "didn't name the missing file"; }
[ ! -e "$SITE/releases/0.0.4" ] || fail "left a partial download behind"
# A download that doesn't match its checksums, as if changed on the way.
ln -sfn "$T/rel-bad" "$WWW/server-v0.0.3"
if upgrade 0.0.3 >"$T/out" 2>&1; then fail "a corrupted download was installed"; fi
grep -q "RELEASE_NOTES.md doesn't match SHA256SUMS" "$T/out" || { cat "$T/out"; fail "the corrupted download wasn't reported"; }
ln -sfn "$T/rel-0.0.3" "$WWW/server-v0.0.3"
[ "$(env_version)" = 0.0.2 ] || fail "a failed download changed .env"
ok "a download with a file missing, and one that doesn't match its checksums, are refused"

FAKE_COSIGN_VERSION=2.4.1 upgrade 0.0.3-rc.1 >"$T/out" 2>&1 \
  || { cat "$T/out"; fail "upgrade to 0.0.3-rc.1 by version, checked with cosign 2.4.1, failed"; }
[ "$(env_version)" = 0.0.3-rc.1 ] || fail ".env says $(env_version), not 0.0.3-rc.1"
grep -q "signed by Altiward's release workflow for 0.0.3-rc.1" "$T/out" || fail "cosign 2.4.1 didn't check the signature"
grep -q "Downloading 0.0.3-rc.1" "$T/out" || fail "didn't download 0.0.3-rc.1"
[ -f "$SITE/releases/0.0.3-rc.1/altiward-server-0.0.3-rc.1.tar.gz" ] || fail "the download isn't in releases/0.0.3-rc.1"
grep -q "is a release candidate" "$T/out" || fail "didn't say 0.0.3-rc.1 is a release candidate"
ok "upgraded to the release candidate 0.0.3-rc.1, downloaded by version and checked with cosign 2.4.1"

# A file both the admin and the release changed stops the upgrade with a .new copy,
# after the new release's upgrade.sh has taken over with the files already downloaded.
echo "# my compose change" >>"$SITE/compose.yaml"
status=0
upgrade 0.0.3 >"$T/out" 2>&1 || status=$?
[ "$status" = 3 ] || { cat "$T/out"; fail "a conflicting compose.yaml should stop with 3, got $status"; }
[ "$(grep -c "signed by Altiward's release workflow for 0.0.3$" "$T/out")" = 2 ] \
  || { cat "$T/out"; fail "cosign 3 didn't check the signature, before and after the handover"; }
grep -q "Updated upgrade.sh from 0.0.3" "$T/out" || fail "upgrade.sh didn't hand over to 0.0.3's"
[ "$(grep -c "^Downloading 0.0.3 " "$T/out")" = 1 ] || { cat "$T/out"; fail "0.0.3 wasn't downloaded exactly once"; }
grep -q "upgrade.sh from 0.0.3" "$SITE/upgrade.sh" || fail "upgrade.sh wasn't replaced"
grep -q "changed in 0.0.3" "$SITE/compose.yaml.new" || fail "no compose.yaml.new from 0.0.3"
grep -q "my compose change" "$SITE/backups/before-0.0.3/compose.yaml" || fail "the admin's compose.yaml wasn't saved"
grep -q -- "--merged .*/releases/0.0.3$" "$T/out" || { cat "$T/out"; fail "didn't say to carry on from the downloaded release"; }
[ "$(env_version)" = 0.0.3-rc.1 ] || fail "a stopped upgrade changed .env"
ok "a compose.yaml changed on both sides stops the upgrade with compose.yaml.new"

FAKE_COSIGN_VERSION=2.2.4 upgrade --merged "$SITE/releases/0.0.3" >"$T/out" 2>&1 \
  || { cat "$T/out"; fail "the --merged upgrade failed"; }
grep -q "cosign 2.2.4 is too old to check this release's signature: install cosign 2.4 or later. Only the checksums were checked" "$T/out" \
  || { cat "$T/out"; fail "--skip-signature with a cosign too old didn't say what it skipped"; }
[ "$(env_version)" = 0.0.3 ] || fail ".env says $(env_version), not 0.0.3"
grep -q "my compose change" "$SITE/compose.yaml" || fail "the admin's compose.yaml was replaced"
[ ! -e "$SITE/compose.yaml.new" ] || fail "compose.yaml.new was left behind"
grep -q "is running and healthy" "$T/out" || fail "didn't report healthy"
ok "after merging, the upgrade from the candidate to 0.0.3 keeps the admin's compose.yaml"
sed 's/^/    | /' "$T/out" # what an admin sees

if upgrade "$T/rel-0.0.3-rc.1" >"$T/out" 2>&1; then fail "a release candidate replaced its release"; fi
ok "a release candidate doesn't replace its release"

echo "All upgrade tests passed."
