#!/bin/bash
# Release notes wait in changelog.d/ as one file per change, so pull requests never edit
# the same lines of CHANGELOG.md. A release folds them into its dated section.
#
#   scripts/changelog.sh check                       check every fragment, and CHANGELOG.md
#   scripts/changelog.sh show server 1.0.1           print the section the fragments make
#   scripts/changelog.sh release server 1.0.1        add that section to CHANGELOG.md, dated
#   scripts/changelog.sh release agent 1.0.1 DATE    today or DATE, and delete the fragments
#
# A fragment is changelog.d/<server|agent>/<name>.<heading>.md, where <heading> is
# upgrade-order, breaking, security or changes. Under upgrade-order it holds paragraphs;
# under the others, "- " bullets whose lines continue indented by two spaces.
set -euo pipefail
shopt -s nullglob
cd "$(dirname "$0")/.."

HEADINGS="upgrade-order:Upgrade order
breaking:Breaking changes
security:Security
changes:Changes"

die() { echo "$*" >&2; exit 1; }

# Prints a file without its trailing blank lines.
trimmed() {
  awk '{ line[NR] = $0 } NF { last = NR } END { for (i = 1; i <= last; i++) print line[i] }' "$1"
}

check() {
  local bad=0 f kind body
  # Unreleased changes live in fragments, so every section here is a dated release.
  if grep -nE '^## (Server|Agent) ' CHANGELOG.md | grep -vE ' - [0-9]{4}-[0-9]{2}-[0-9]{2}$' >&2; then
    echo "CHANGELOG.md: only released, dated sections belong here; add a fragment to changelog.d/ instead (changelog.d/README.md)" >&2
    bad=1
  fi
  while IFS= read -r f; do
    if ! [[ "$f" =~ ^changelog\.d/(server|agent)/[a-z0-9][a-z0-9-]*\.(upgrade-order|breaking|security|changes)\.md$ ]]; then
      echo "$f: name it changelog.d/<server|agent>/<name>.<upgrade-order|breaking|security|changes>.md" >&2
      bad=1
      continue
    fi
    kind="${BASH_REMATCH[2]}"
    body="$(trimmed "$f")"
    if [ -z "$body" ] || [ -z "$(head -1 <<<"$body" | tr -d '[:space:]')" ]; then
      echo "$f: start with the text itself, on the first line" >&2
      bad=1
    elif grep -q '^#' <<<"$body"; then
      echo "$f: leave out headings; the release adds them" >&2
      bad=1
    elif [ "$kind" != upgrade-order ] && { [[ "$body" != "- "* ]] || grep -vqE '^(- |  )' <<<"$body"; }; then
      echo "$f: write \"- \" bullets, with no blank lines, continuing each line indented by two spaces" >&2
      bad=1
    fi
  done < <(find changelog.d -type f ! -name '.*' ! -path changelog.d/README.md | sort)
  return "$bad"
}

# Prints the section the fragments make for a product, version and date.
section() {
  local product="$1" title="$2" version="$3" date="$4" pair kind files f sep
  printf '## %s %s - %s\n' "$title" "$version" "$date"
  while IFS= read -r pair; do
    kind="${pair%%:*}"
    printf '\n### %s\n\n' "${pair#*:}"
    files=(changelog.d/"$product"/*."$kind".md)
    if [ "${#files[@]}" -eq 0 ]; then
      echo "None."
      continue
    fi
    sep=""
    for f in "${files[@]}"; do
      # Paragraphs need a blank line between them; bullets join into one list.
      [ "$kind" = upgrade-order ] && printf '%s' "$sep"
      trimmed "$f"
      sep=$'\n'
    done
  done <<<"$HEADINGS"
}

COMMAND="${1:?check, show or release}"
if [ "$COMMAND" = check ]; then
  check
  exit
fi
[ "$COMMAND" = show ] || [ "$COMMAND" = release ] || die "command must be check, show or release, got $COMMAND"
PRODUCT="${2:?server or agent}"
VERSION="${3:?version, e.g. 1.0.1}"
DATE="${4:-$(date +%F)}"
case "$PRODUCT" in
  server) TITLE="Server" ;;
  agent) TITLE="Agent" ;;
  *) die "product must be server or agent, got $PRODUCT" ;;
esac
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be X.Y.Z, got $VERSION"
[[ "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "date must be YYYY-MM-DD, got $DATE"
check || die "fix the above first"

if [ "$COMMAND" = show ]; then
  section "$PRODUCT" "$TITLE" "$VERSION" unreleased
  exit
fi

! grep -q "^## $TITLE $VERSION - " CHANGELOG.md || die "CHANGELOG.md already has $TITLE $VERSION"
new="$(mktemp)"
trap 'rm -f "$new"' EXIT
# The new section goes above the newest release, after the introduction.
section "$PRODUCT" "$TITLE" "$VERSION" "$DATE" | awk -v notes=CHANGELOG.md '
  { section = section $0 "\n" }
  END {
    while ((getline line < notes) > 0) {
      if (!done && line ~ /^## (Server|Agent) /) { printf "%s\n", section; done = 1 }
      print line
    }
    if (!done) printf "\n%s", section
  }
' >"$new"
cat "$new" >CHANGELOG.md
rm -f changelog.d/"$PRODUCT"/*.md
echo "Added $TITLE $VERSION to CHANGELOG.md and deleted its fragments: read the section, then commit both." >&2
