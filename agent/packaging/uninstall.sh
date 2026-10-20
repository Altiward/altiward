#!/bin/bash
# Removes the Altiward agent. Keeps /Library/Application Support/Altiward, which holds
# events not yet delivered, unless run with --purge.
#   sudo "/Library/Application Support/Altiward/Altiward.app/Contents/Resources/uninstall.sh" [--purge]
set -euo pipefail
LABEL=com.altiward.agent
DIR="/Library/Application Support/Altiward"
if [ "$(id -u)" != 0 ]; then echo "Run with sudo." >&2; exit 1; fi

queued="$("$DIR/Altiward.app/Contents/MacOS/altiward-agent" status 2>/dev/null | sed -n 's/^queued events: //p' || true)"
launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist"
rm -rf "$DIR/Altiward.app"
pkgutil --forget com.altiward.agent.pkg >/dev/null 2>&1 || true

if [ "${1:-}" = "--purge" ]; then
  rm -rf "$DIR"
  echo "Removed the Altiward agent and its data${queued:+ ($queued undelivered events deleted)}."
else
  echo "Removed the Altiward agent. Kept $DIR${queued:+ ($queued events not yet delivered)}; run with --purge to delete it."
fi
