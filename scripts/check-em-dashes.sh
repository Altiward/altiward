#!/bin/bash
# Fails if any tracked text file contains an em dash (U+2014). The project's writing rules
# allow none in docs, UI text, comments or anything else published: use a full stop, colon,
# comma or brackets instead. A missing value in the console is a word (Missing in
# console/src/components/Chrome.tsx), not a dash. If a file ever has to quote one, from a
# log line or third-party text, exclude that file here by name.
set -euo pipefail
cd "$(dirname "$0")/.."

dash=$(printf '\xe2\x80\x94')
if git ls-files -z | xargs -0 grep -nI -- "$dash"; then
  echo "Em dashes above: use a full stop, colon, comma or brackets instead." >&2
  exit 1
fi
