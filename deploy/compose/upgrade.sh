#!/usr/bin/env bash
# Upgrades this Altiward server to a new release (docs/install.md, "Releases and
# updates"). Run it from anywhere; it works on the deployment directory it sits in.
#
#   ./upgrade.sh [options] <version>
#   ./upgrade.sh [options] <directory holding the release files>
#
# Given a version, such as 1.0.1 or 1.1.0-rc.1, it downloads the release from GitHub into
# releases/<version>/ in the deployment directory, with curl, which uses HTTPS_PROXY if
# it's set. On a server without internet access, give a directory holding the release
# files instead: altiward-server-<version>.tar.gz, the image for this machine
# (altiward-api-<version>-linux-amd64.tar.gz or …-arm64), RELEASE_NOTES.md, SHA256SUMS
# and SHA256SUMS.sigstore.json.
#
#   --yes             don't ask before upgrading
#   --skip-signature  carry on without cosign, or with one older than 2.4, which can't
#                     check the signature; the checksums are still checked
#   --skip-backup     don't back up the database, for when you back up your own Postgres
#   --merged          you've merged the deployment files left as *.new; carry on
#
# It checks the files, refuses to go back a version, backs up the database, .env and the
# files it replaces into backups/, loads the image, updates the deployment files you
# haven't changed, sets ALTIWARD_VERSION and restarts, then waits for the server to report
# healthy. If a release changes a file you changed, it leaves the new one beside yours as
# <file>.new and stops before changing anything.
set -euo pipefail

# The release workflow that signs SHA256SUMS; the certificate must name this release's tag.
SIGNER_WORKFLOW=https://github.com/Altiward/altiward/.github/workflows/release-server.yml
SIGNER_ISSUER=https://token.actions.githubusercontent.com
# Deployment files an upgrade may replace. You may change the first two (an existing
# Postgres, your own certificates); the rest are Altiward's.
CONFIG_FILES=(compose.yaml Caddyfile)
OWN_FILES=(env.example README.md certs/README.md)
HEALTH_TIMEOUT=180
RELEASE_VERSION='^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'
# A version's files are at $RELEASES_URL/server-v<version>/. scripts/test-upgrade.sh
# points it at a local server.
RELEASES_URL="${ALTIWARD_RELEASES_URL:-https://github.com/Altiward/altiward/releases/download}"

say() { printf '%s\n' "$*"; }
warn() { printf 'upgrade: %s\n' "$*" >&2; }
die() { warn "$*"; exit 1; }

# Orders two versions as semantic versioning does, printing -1, 0 or 1: X.Y.Z by number,
# and a pre-release before its release (0.3.0-rc.1 < 0.3.0-rc.2 < 0.3.0). A
# version that isn't X.Y.Z, such as dev, counts as 0.0.0.
compare() {
  local a="${1%%+*}" b="${2%%+*}" ca cb pa="" pb="" x y i p q
  ca="${a%%-*}" cb="${b%%-*}"
  [[ "$a" == *-* ]] && pa="${a#*-}"
  [[ "$b" == *-* ]] && pb="${b#*-}"
  [[ "$ca" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] || { ca=0 pa=""; }
  [[ "$cb" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] || { cb=0 pb=""; }
  IFS=. read -r -a x <<<"$ca"
  IFS=. read -r -a y <<<"$cb"
  for i in 0 1 2; do
    if (( 10#${x[i]:-0} < 10#${y[i]:-0} )); then echo -1; return; fi
    if (( 10#${x[i]:-0} > 10#${y[i]:-0} )); then echo 1; return; fi
  done
  if [ "$pa" = "$pb" ]; then echo 0; return; fi
  if [ -z "$pa" ]; then echo 1; return; fi
  if [ -z "$pb" ]; then echo -1; return; fi
  IFS=. read -r -a x <<<"$pa"
  IFS=. read -r -a y <<<"$pb"
  for ((i = 0; ; i++)); do
    if (( i >= ${#x[@]} && i >= ${#y[@]} )); then echo 0; return; fi
    if (( i >= ${#x[@]} )); then echo -1; return; fi # fewer parts sorts first
    if (( i >= ${#y[@]} )); then echo 1; return; fi
    p="${x[i]}" q="${y[i]}"
    if [[ "$p" =~ ^[0-9]+$ && "$q" =~ ^[0-9]+$ ]]; then
      if (( 10#$p < 10#$q )); then echo -1; return; fi
      if (( 10#$p > 10#$q )); then echo 1; return; fi
    elif [[ "$p" =~ ^[0-9]+$ ]]; then echo -1; return # numbers sort before words
    elif [[ "$q" =~ ^[0-9]+$ ]]; then echo 1; return
    elif [[ "$p" < "$q" ]]; then echo -1; return
    elif [[ "$p" > "$q" ]]; then echo 1; return
    fi
  done
}
if [ "${1:-}" = --compare ]; then compare "$2" "$3"; exit 0; fi # for scripts/test-upgrade.sh


yes=false skip_signature=false skip_backup=false merged=false target="" opts=()
for arg in "$@"; do
  case "$arg" in
    --yes) yes=true ;;
    --skip-signature) skip_signature=true ;;
    --skip-backup) skip_backup=true ;;
    --merged) merged=true ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $arg (see --help)" ;;
    *) [ -z "$target" ] || die "give one version or release directory"; target="$arg"; continue ;;
  esac
  opts+=("$arg") # passed on to the new release's script
done
[ -n "$target" ] || die "give the version to upgrade to, or the directory holding the release files (see --help)"
version="" release=""
if [[ "$target" =~ $RELEASE_VERSION ]]; then
  version="$target"
else
  [ -d "$target" ] || die "$target is neither a version, such as 1.0.1, nor a directory"
  release="$(cd "$target" && pwd)"
fi

DEPLOY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="$DEPLOY/$(basename "${BASH_SOURCE[0]}")"
cd "$DEPLOY"
if [ ! -f compose.yaml ] || [ ! -f .env ]; then
  die "$DEPLOY has no compose.yaml and .env: keep this script in your deployment directory"
fi
docker compose version >/dev/null 2>&1 || die "needs Docker with the Compose plugin"

# Values from .env, as written there (no shell expansion).
env_value() { sed -n "s/^$1=//p" .env | tail -n 1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"; }

## The release files

if [ -n "$release" ]; then
  shopt -s nullglob
  bundles=("$release"/altiward-server-*.tar.gz)
  shopt -u nullglob
  [ "${#bundles[@]}" -eq 1 ] || die "expected one altiward-server-<version>.tar.gz in $release, found ${#bundles[@]}"
  version="$(basename "${bundles[0]}")"
  version="${version#altiward-server-}"
  version="${version%.tar.gz}"
  [[ "$version" =~ $RELEASE_VERSION ]] || die "can't read a version from $(basename "${bundles[0]}")"
fi
bundle="altiward-server-$version.tar.gz"

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "no Altiward image for $(uname -m)" ;;
esac
image_file="altiward-api-$version-linux-$arch.tar.gz"

## Versions

current="$(env_value ALTIWARD_VERSION)"
if [ -n "$current" ]; then
  if [ "$current" = "$version" ]; then say "Already running $version."; exit 0; fi
  if [ "$(compare "$version" "$current")" != 1 ]; then
    die "this server runs $current, which is newer than $version. Going back isn't supported: restore a backup instead"
  fi
fi

# Checked before anything is downloaded. The release workflow signs SHA256SUMS in Sigstore's
# bundle format v0.3. Cosign 3 reads it by default and deprecates --new-bundle-format;
# cosign 2.4 reads it only with that flag, which later 2.x accept. Older ones can't.
cosign_ok=false cosign_args=() cosign_version=""
if command -v cosign >/dev/null; then
  cosign_version="$(cosign version 2>&1 | sed -n 's/^GitVersion:[[:space:]]*v\{0,1\}//p' | head -n 1 || true)"
  cosign_problem="cosign $cosign_version is too old to check this release's signature: install cosign 2.4 or later"
  if [[ "$cosign_version" =~ ^([0-9]+)\.([0-9]+)\. ]]; then
    if (( 10#${BASH_REMATCH[1]} >= 3 )); then
      cosign_ok=true
    elif (( 10#${BASH_REMATCH[1]} == 2 && 10#${BASH_REMATCH[2]} >= 4 )); then
      cosign_ok=true cosign_args=(--new-bundle-format)
    fi
  else
    cosign_problem="can't tell which version cosign is (\`cosign version\` reports no GitVersion), so it can't check this release's signature: install cosign 2.4 or later"
  fi
  if ! $cosign_ok; then
    $skip_signature || die "$cosign_problem (docs/install.md, \"Checking a release\"), check the files on another machine, or run again with --skip-signature"
  fi
elif ! $skip_signature; then
  die "cosign isn't installed, so the signature can't be checked. Install cosign 2.4 or later (docs/install.md, \"Checking a release\"), check the files on another machine, or run again with --skip-signature"
fi

## Download

if [ -z "$release" ]; then
  command -v curl >/dev/null || die "needs curl to download $version, or give a directory holding the release files (see --help)"
  release="$DEPLOY/releases/$version"
  url="$RELEASES_URL/server-v$version"
  say "Downloading $version from $url"
  rm -rf "$release"
  mkdir -p "$release"
  # A failed download leaves nothing behind, so a partial release is never used.
  trap 'rm -rf "$release"' EXIT
  for f in "$bundle" "$image_file" RELEASE_NOTES.md SHA256SUMS SHA256SUMS.sigstore.json; do
    curl -fsSL --connect-timeout 30 --retry 2 -o "$release/$f" "$url/$f" \
      || die "couldn't download $f from $url, so nothing has changed. Check the version, and that this server can reach GitHub (set HTTPS_PROXY for a proxy), or give a directory holding the release files instead"
  done
  trap - EXIT
fi

for f in "$bundle" "$image_file" RELEASE_NOTES.md SHA256SUMS; do
  [ -f "$release/$f" ] || die "$release has no $f"
done

say "Checking the release files"
if command -v sha256sum >/dev/null; then sha=(sha256sum); else sha=(shasum -a 256); fi
# Every file used must be listed, so check each by name rather than whatever is listed.
for f in "$bundle" "$image_file" RELEASE_NOTES.md; do
  line="$(awk -v f="$f" '$2 == f || $2 == "*" f' "$release/SHA256SUMS")"
  [ -n "$line" ] || die "SHA256SUMS doesn't list $f"
  (cd "$release" && printf '%s\n' "$line" | "${sha[@]}" -c --quiet -) || die "$f doesn't match SHA256SUMS: get the release again"
done
if $cosign_ok; then
  [ -f "$release/SHA256SUMS.sigstore.json" ] || die "$release has no SHA256SUMS.sigstore.json"
  if ! cosign_out="$(cosign verify-blob "$release/SHA256SUMS" --bundle "$release/SHA256SUMS.sigstore.json" \
    ${cosign_args[@]+"${cosign_args[@]}"} \
    --certificate-identity "$SIGNER_WORKFLOW@refs/tags/server-v$version" \
    --certificate-oidc-issuer "$SIGNER_ISSUER" 2>&1)"; then
    why="$(printf '%s\n' "$cosign_out" | grep -m 1 '^Error:' || true)"
    [ -n "$why" ] || why="$(printf '%s\n' "$cosign_out" | sed '/^[[:space:]]*$/d' | tail -n 1)"
    warn "cosign $cosign_version says: ${why:-nothing}"
    die "SHA256SUMS isn't signed by Altiward's release workflow for $version: don't install it, and report it at https://github.com/Altiward/altiward/security"
  fi
  say "  checksums match, signed by Altiward's release workflow for $version"
elif command -v cosign >/dev/null; then
  warn "$cosign_problem. Only the checksums were checked, not who made them"
else
  warn "cosign isn't installed, so only the checksums were checked, not who made them"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tar -xzf "$release/$bundle" -C "$work"
new="$work/altiward-server-$version/deploy/compose"
[ -f "$new/compose.yaml" ] || die "$bundle has no deploy/compose: is it an Altiward server release?"

# The new release's script does the rest, so its fixes apply to its own upgrade. It
# replaces this one by rename, which leaves the copy bash is running intact. It gets the
# release's directory, so a downloaded release isn't downloaded again.
if [ -z "${ALTIWARD_UPGRADE_HANDOFF:-}" ] && [ -f "$new/upgrade.sh" ] && ! cmp -s "$new/upgrade.sh" "$SELF"; then
  cp "$new/upgrade.sh" "$SELF.tmp"
  chmod 755 "$SELF.tmp"
  mv "$SELF.tmp" "$SELF"
  say "Updated upgrade.sh from $version; it carries on"
  ALTIWARD_UPGRADE_HANDOFF=1 exec "$SELF" ${opts[@]+"${opts[@]}"} "$release"
fi

## Deployment files

# Each file as the release you run shipped it: the bundle carries them, and each upgrade
# records the new ones.
shipped="$DEPLOY/.altiward/shipped"
replace=() keep=() conflicts=()
for f in "${CONFIG_FILES[@]}"; do
  [ -f "$new/$f" ] || continue
  if [ ! -f "$f" ] || cmp -s "$f" "$new/$f"; then
    replace+=("$f")
  elif [ -f "$shipped/$f" ] && cmp -s "$f" "$shipped/$f"; then
    replace+=("$f") # you haven't changed it
  elif [ -f "$shipped/$f" ] && cmp -s "$shipped/$f" "$new/$f"; then
    keep+=("$f") # the release doesn't change it, so yours stays as it is
  elif $merged; then
    keep+=("$f")
    rm -f "$f.new"
  else
    conflicts+=("$f")
  fi
done
for f in "${OWN_FILES[@]}"; do
  [ -f "$new/$f" ] && replace+=("$f")
done

if [ "${#conflicts[@]}" -gt 0 ]; then
  kept="$DEPLOY/backups/before-$version"
  mkdir -p "$kept"
  chmod 700 "$DEPLOY/backups" "$kept"
  for f in "${conflicts[@]}"; do
    cp "$new/$f" "$f.new"
    mkdir -p "$kept/$(dirname "$f")"
    cp -p "$f" "$kept/$f"
    say ""
    if [ -f "$shipped/$f" ]; then
      say "You changed $f, and $version changes it too. What $version changes:"
      diff -u "$shipped/$f" "$new/$f" | sed '1,2d' || true
    else
      say "$f differs from $version's. Yours against $version's:"
      diff -u "$f" "$new/$f" | sed '1,2d' || true
    fi
  done
  say ""
  say "Nothing has changed yet. Bring the changes into your files from:"
  printf '  %s.new\n' "${conflicts[@]}"
  say "or replace yours with them and move your settings into .env. Yours, as they are now,"
  say "are saved in $kept. Then run:"
  say "  $SELF --merged $release"
  exit 3
fi

## Ask

notes_section() { awk -v h="### $1" '$0 == h {on=1; next} on && /^##/ {exit} on' "$release/RELEASE_NOTES.md" | sed '/^$/d'; }
say ""
say "Upgrading Altiward from ${current:-an unknown version} to $version."
[[ "$version" == *-rc.* ]] && say "$version is a release candidate, for testing; ${version%-rc.*} will replace it."
for h in "Upgrade order" "Breaking changes" "Security"; do
  text="$(notes_section "$h")"
  [ -n "$text" ] && [ "$text" != "None." ] && { say ""; say "$h:"; printf '%s\n' "$text" | sed 's/^/  /'; }
done
say ""
say "The rest is in $release/RELEASE_NOTES.md."
if ! $yes; then
  [ -t 0 ] || die "run with --yes to upgrade without being asked"
  read -r -p "Upgrade now? [y/N] " answer
  [[ "$answer" =~ ^[Yy] ]] || { say "Nothing changed."; exit 0; }
fi

## Back up

# compose.yaml requires ALTIWARD_VERSION, and .env names the new one only once the image
# is loaded. Until then Compose runs with the version this server runs, so a blank value
# in .env can't stop the backup; the environment wins over .env.
was="${current:-$version}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="$DEPLOY/backups/$stamp-from-${current:-unknown}"
mkdir -p "$backup"
chmod 700 "$DEPLOY/backups" "$backup"
cp -p .env "$backup/.env"
for f in ${replace[@]+"${replace[@]}"}; do
  [ -f "$f" ] && { mkdir -p "$backup/$(dirname "$f")"; cp -p "$f" "$backup/$f"; }
done
if $skip_backup; then
  warn "not backing up the database (--skip-backup)"
elif ALTIWARD_VERSION="$was" docker compose ps --status running --services 2>/dev/null | grep -qx postgres; then
  say "Backing up the database to $backup/altiward.dump"
  (umask 077; ALTIWARD_VERSION="$was" docker compose exec -T postgres pg_dump -U altiward -Fc altiward >"$backup/altiward.dump") \
    || die "the database backup failed, so nothing was upgraded"
  [ -s "$backup/altiward.dump" ] || die "the database backup is empty, so nothing was upgraded"
else
  die "the bundled Postgres isn't running, so this can't back it up. Back up your database, then run again with --skip-backup"
fi

## Upgrade

image="$(env_value ALTIWARD_IMAGE)"
[ -n "$image" ] || image="$(sed -n 's/.*\${ALTIWARD_IMAGE:-\([^}]*\)}.*/\1/p' "$new/compose.yaml" | head -n 1)"
[ -n "$image" ] || die "can't tell which image name compose.yaml uses"
say "Loading the image"
loaded="$(docker load -i "$release/$image_file" | sed -n 's/^Loaded image: //p' | tail -n 1)"
[ -n "$loaded" ] || die "docker load didn't report an image"
[ "$loaded" = "$image:$version" ] || docker tag "$loaded" "$image:$version"

old_settings="$( [ -f "$shipped/env.example" ] && grep -oE '^#? ?ALTIWARD_[A-Z0-9_]+=' "$shipped/env.example" | tr -d '#= ' | sort -u || true)"
for f in ${replace[@]+"${replace[@]}"}; do
  mkdir -p "$(dirname "$f")" "$shipped/$(dirname "$f")"
  cmp -s "$new/$f" "$f" 2>/dev/null || cp "$new/$f" "$f"
  cp "$new/$f" "$shipped/$f"
done
for f in ${keep[@]+"${keep[@]}"} upgrade.sh; do
  [ -f "$new/$f" ] && cp "$new/$f" "$shipped/$f"
done
mkdir -p certs

# Rewrite .env in place, so it keeps its owner and permissions.
if grep -q '^ALTIWARD_VERSION=' .env; then
  sed "s/^ALTIWARD_VERSION=.*/ALTIWARD_VERSION=$version/" .env >"$work/env"
else
  { cat .env; printf 'ALTIWARD_VERSION=%s\n' "$version"; } >"$work/env"
fi
cat "$work/env" >.env

say "Starting $version"
docker compose up -d
id="$(docker compose ps -q altiward)"
status=starting
for _ in $(seq 1 $((HEALTH_TIMEOUT / 3))); do
  status="$(docker inspect -f '{{.State.Health.Status}}' "$id" 2>/dev/null || echo missing)"
  [ "$status" = healthy ] && break
  sleep 3
done
if [ "$status" != healthy ]; then
  docker compose logs --tail 30 altiward >&2 || true
  warn "$version didn't report healthy within ${HEALTH_TIMEOUT}s (it's $status). The logs are above."
  warn "To go back to ${current:-the previous version}, restore what was saved in $backup:"
  warn "  cp -p $backup/.env .env   # and any other files there"
  warn "  ALTIWARD_VERSION=$was docker compose up -d postgres"
  warn "  ALTIWARD_VERSION=$was docker compose exec -T postgres pg_restore -U altiward -d altiward --clean --if-exists < $backup/altiward.dump"
  warn "  ALTIWARD_VERSION=$was docker compose up -d"
  exit 1
fi

running="$(docker compose exec -T altiward /usr/local/bin/altiward-api version 2>/dev/null || echo unknown)"
say ""
say "Altiward $version is running and healthy (the server reports version $running)."
say "Saved in $backup: the database, .env and the replaced files."
if [ -n "$old_settings" ]; then
  added="$(comm -13 <(printf '%s\n' "$old_settings") <(grep -oE '^#? ?ALTIWARD_[A-Z0-9_]+=' env.example | tr -d '#= ' | sort -u))"
  [ -z "$added" ] || { say "New settings in this release, described in env.example:"; printf '%s\n' "$added" | sed 's/^/  /'; }
fi
say "If the release notes say so, roll out the new agent through your MDM next."
