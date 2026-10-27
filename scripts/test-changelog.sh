#!/bin/bash
# Tests scripts/changelog.sh, and release-notes.sh on what it writes, in a scratch copy
# of the scripts with a made-up CHANGELOG.md and fragments.
#
#   scripts/test-changelog.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/scripts" "$T/changelog.d/server" "$T/changelog.d/agent"
cp "$ROOT/scripts/changelog.sh" "$ROOT/scripts/release-notes.sh" "$T/scripts/"
cp "$ROOT/changelog.d/README.md" "$T/changelog.d/"
cd "$T"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok - $*"; }
same() { diff -u "$2" - || fail "$1"; ok "$1"; }

cat >CHANGELOG.md <<'EOF'
# Changelog

Introduction.

## Server 1.0.0 - 2026-10-27

### Upgrade order

None.

### Breaking changes

None.

### Security

None.

### Changes

- First release.
EOF
cp CHANGELOG.md before.md
printf 'Upgrade the server first.\n\n' >changelog.d/server/rotate.upgrade-order.md
printf 'Then the agents.\n' >changelog.d/server/zeta.upgrade-order.md
printf -- '- One change, on a line that wraps\n  onto a second.\n\n\n' >changelog.d/server/one.changes.md
printf -- '- Another change.\n' >changelog.d/server/two.changes.md
printf -- '- An agent change.\n' >changelog.d/agent/agent.changes.md

scripts/changelog.sh check || fail "good fragments pass the check"
ok "good fragments pass the check"

cat >want.md <<'EOF'
## Server 1.0.1 - unreleased

### Upgrade order

Upgrade the server first.

Then the agents.

### Breaking changes

None.

### Security

None.

### Changes

- One change, on a line that wraps
  onto a second.
- Another change.
EOF
scripts/changelog.sh show server 1.0.1 | same "show joins paragraphs and bullets, and fills empty headings" want.md

scripts/release-notes.sh server 1.0.1-rc.1 | sed -n 1p | grep -q '^## Server 1.0.1-rc.1 - .*, release candidate for 1.0.1$' ||
  fail "a release candidate takes its notes from the fragments"
ok "a release candidate takes its notes from the fragments"

scripts/changelog.sh release server 1.0.1 2026-11-02 2>/dev/null
{ sed -n 1,4p before.md; sed 's/unreleased/2026-11-02/' want.md; echo; sed -n '5,$p' before.md; } >want-changelog.md
same "release adds the dated section above the newest release" want-changelog.md <CHANGELOG.md
[ -z "$(ls changelog.d/server)" ] || fail "release deletes the product's fragments"
[ -f changelog.d/agent/agent.changes.md ] || fail "release keeps the other product's fragments"
ok "release deletes only the product's fragments"
scripts/release-notes.sh server 1.0.1 | same "release-notes.sh prints the new section" <(sed 's/unreleased/2026-11-02/' want.md)

! scripts/changelog.sh release server 1.0.1 2>/dev/null || fail "a version can't be released twice"
ok "a version can't be released twice"

rejects() {
  local what="$1" name="$2" text="$3"
  mkdir -p "$(dirname "changelog.d/$name")"
  printf '%b' "$text" >"changelog.d/$name"
  ! scripts/changelog.sh check 2>/dev/null || fail "the check rejects $what"
  rm "changelog.d/$name"
  ok "the check rejects $what"
}
rejects "an unknown heading" server/x.fixes.md '- A fix.\n'
rejects "a product other than server or agent" console/x.changes.md '- A fix.\n'
rejects "a fragment outside a product" x.changes.md '- A fix.\n'
rejects "capital letters in the name" server/Fix.changes.md '- A fix.\n'
rejects "an empty fragment" server/x.changes.md '\n'
rejects "a leading blank line" server/x.changes.md '\n- A fix.\n'
rejects "a paragraph under a list heading" server/x.changes.md 'A fix.\n'
rejects "a continuation line not indented" server/x.security.md '- A fix\nthat wraps.\n'
rejects "a blank line inside a list" server/x.changes.md '- A fix.\n\n- Another.\n'
rejects "a heading" server/x.upgrade-order.md '### Upgrade order\n\nText.\n'
rmdir changelog.d/console

printf '\n## Agent 1.0.1 - unreleased\n' >>CHANGELOG.md
! scripts/changelog.sh check 2>/dev/null || fail "the check rejects an unreleased section in CHANGELOG.md"
ok "the check rejects an unreleased section in CHANGELOG.md"
