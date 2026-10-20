#!/bin/bash
# Copy canonical assets into a consumer checkout, or check its copies without writing.
#   scripts/brand/export.sh <console|github|website> <destination> [--check]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="${1:?target: console, github or website}"
DEST="${2:?destination directory}"
MODE="${3:-}"
[ "$#" -le 3 ] && { [ -z "$MODE" ] || [ "$MODE" = --check ]; } || {
  echo 'usage: export.sh <console|github|website> <destination> [--check]' >&2; exit 1;
}
[ -d "$DEST" ] || { echo "destination directory does not exist: $DEST" >&2; exit 1; }
case "$TARGET" in
  console) files=(
    'assets/brand/altiward-mark.svg:public/brand/altiward-mark.svg'
    'assets/brand/altiward-mark-on-dark.svg:public/brand/altiward-mark-on-dark.svg'
  ) ;;
  github) files=(
    'assets/brand/altiward-mark.svg:profile/images/altiward-mark.svg'
    'assets/brand/altiward-mark-on-dark.svg:profile/images/altiward-mark-on-dark.svg'
    'docs/images/console-overview.png:profile/images/console-overview.png'
  ) ;;
  website) files=('assets/brand/altiward-mark.svg:mark.svg') ;;
  *) echo "unknown export target: $TARGET" >&2; exit 1 ;;
esac
for pair in "${files[@]}"; do
  source_file="$ROOT/${pair%%:*}"
  destination_file="$DEST/${pair#*:}"
  if [ "$MODE" = --check ]; then
    cmp -s "$source_file" "$destination_file" || {
      echo "asset is missing or out of date: $destination_file" >&2; exit 1;
    }
  else
    mkdir -p "$(dirname "$destination_file")"
    cp "$source_file" "$destination_file"
  fi
done
