#!/bin/bash
# Checks a build from build.sh: bundle layout, architectures, signatures, the hook's
# identity, the package payload and scripts, and the generated Privileges checksum.
# Also runs postinstall against a scratch target volume (no launchctl, nothing installed).
#
#   agent/packaging/verify.sh [OUT_DIR]        default ~/Library/Caches/altiward/package
#   RELEASE=1 also requires Developer ID signatures, notarization and stapling.
set -euo pipefail

OUT="${1:-$HOME/Library/Caches/altiward/package}"
APP="$OUT/Altiward.app"
INSTALL_DIR="/Library/Application Support/Altiward"
failures=0
check() { # description, command...
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "ok   $what"; else echo "FAIL $what"; failures=$((failures + 1)); fi
}
plist() { [ -f "$1" ] && /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }

VERSION="$(plist "$APP/Contents/Info.plist" CFBundleShortVersionString || true)"
PKG="$OUT/Altiward-$VERSION.pkg"

check "bundle exists" test -d "$APP"
check "bundle identifier is com.altiward.agent" test "$(plist "$APP/Contents/Info.plist" CFBundleIdentifier)" = com.altiward.agent
check "version matches AgentVersion.current" grep -q "current = \"$VERSION\"" "$(dirname "$0")/../Sources/AltiwardCore/DeviceIdentity.swift"
for bin in altiward-agent Altiward; do  # Altiward is the hook
  f="$APP/Contents/MacOS/$bin"
  check "$bin is universal" bash -c "lipo -archs '$f' | grep -q arm64 && lipo -archs '$f' | grep -q x86_64"
  check "$bin runs on macOS 13" bash -c "vtool -arch arm64 -show-build '$f' | grep -q 'minos 13.0'"
done
check "Altiward.app has its icon" bash -c "[ \"\$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIconFile' '$APP/Contents/Info.plist')\" = AppIcon ] && [ -s '$APP/Contents/Resources/AppIcon.icns' ]"
check "bundle has no nested login items" test ! -e "$APP/Contents/Library/LoginItems"
check "bundle signature verifies (strict)" codesign --verify --strict --verbose=2 "$APP"
check "hook is signed as com.altiward.hook" bash -c "codesign -d --verbose=2 '$APP/Contents/MacOS/Altiward' 2>&1 | grep -q '^Identifier=com.altiward.hook$'"
check "agent is signed as com.altiward.agent" bash -c "codesign -d --verbose=2 '$APP/Contents/MacOS/altiward-agent' 2>&1 | grep -q '^Identifier=com.altiward.agent$'"
check "hardened runtime on the hook" bash -c "codesign -d --verbose=2 '$APP/Contents/MacOS/Altiward' 2>&1 | grep -q 'flags=.*runtime'"

LD="$APP/Contents/Resources/com.altiward.agent.plist"
check "LaunchDaemon plist is valid" plutil -lint "$LD"
check "LaunchDaemon label" test "$(plist "$LD" Label)" = com.altiward.agent
check "LaunchDaemon runs the installed agent" test "$(plist "$LD" Program)" = "$INSTALL_DIR/Altiward.app/Contents/MacOS/altiward-agent"
check "LaunchDaemon advertises the XPC service" test "$(plist "$LD" MachServices:com.altiward.agent.xpc)" = true
check "uninstaller is executable" test -x "$APP/Contents/Resources/uninstall.sh"
check "bundle carries LICENSE and NOTICE" test -s "$APP/Contents/Resources/LICENSE" -a -s "$APP/Contents/Resources/NOTICE"

PROFILE="$OUT/corp.sap.privileges.plist"
check "Privileges profile is valid" plutil -lint "$PROFILE"
check "Privileges profile pins the built hook" test "$(plist "$PROFILE" PostChangeExecutableChecksum)" = "$(shasum -a 256 "$APP/Contents/MacOS/Altiward" | cut -d' ' -f1)"
check "Privileges profile points at the installed hook" test "$(plist "$PROFILE" PostChangeExecutablePath)" = "$INSTALL_DIR/Altiward.app/Contents/MacOS/Altiward"
check "Privileges profile turns on tamper protection" test "$(plist "$PROFILE" EnableSystemExtension)" = true

check "package exists" test -f "$PKG"
check "bundle is not relocatable" bash -c "pkgutil --expand '$PKG' '$OUT/.check' >/dev/null && grep -q 'relocatable=\"false\"' \$(find '$OUT/.check' -name PackageInfo); rc=\$?; rm -rf '$OUT/.check'; exit \$rc"
check "package installs over any version, so MDM can roll back" bash -c "pkgutil --expand '$PKG' '$OUT/.check' >/dev/null && grep -q '<bundle-version/>' \$(find '$OUT/.check' -name PackageInfo); rc=\$?; rm -rf '$OUT/.check'; exit \$rc"
check "package installs the hook" bash -c "pkgutil --payload-files '$PKG' | grep -qx './Library/Application Support/Altiward/Altiward.app/Contents/MacOS/Altiward'"
check "package installs no login items" bash -c "files=\$(pkgutil --payload-files '$PKG') && ! grep -q '/Contents/Library/LoginItems' <<<\"\$files\""

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pkgutil --expand "$PKG" "$WORK/expanded" >/dev/null 2>&1 || true
SCRIPTS="$(find "$WORK/expanded" -type d -name Scripts 2>/dev/null | head -1)"
SCRIPTS="${SCRIPTS:-$WORK/missing}"
check "package has executable preinstall and postinstall" test -x "$SCRIPTS/preinstall" -a -x "$SCRIPTS/postinstall"
check "Installer shows the title Altiward" grep -q '<title>Altiward</title>' "$WORK/expanded/Distribution"
for bg in background background-dark; do
  check "Installer shows the brand mark ($bg)" bash -c "grep -q 'file=\"$bg.tiff\"' '$WORK/expanded/Distribution' && [ -s '$WORK/expanded/Resources/$bg.tiff' ]"
done
check "package installs only on the system volume" grep -q 'enable_localSystem="true"' "$WORK/expanded/Distribution"

# postinstall against a scratch volume: it must place the plist, install no LaunchAgent and
# not touch launchd.
TARGET="$WORK/volume"
mkdir -p "$TARGET$INSTALL_DIR"
cp -R "$APP" "$TARGET$INSTALL_DIR/"
check "postinstall succeeds on another volume" "$SCRIPTS/postinstall" "$PKG" "/" "$TARGET" "/"
check "postinstall installs the LaunchDaemon plist" cmp "$LD" "$TARGET/Library/LaunchDaemons/com.altiward.agent.plist"
check "LaunchDaemon plist is mode 644" test "$(stat -f %Lp "$TARGET/Library/LaunchDaemons/com.altiward.agent.plist")" = 644
check "postinstall installs no LaunchAgent" test ! -e "$TARGET/Library/LaunchAgents"
check "preinstall succeeds on another volume" "$SCRIPTS/preinstall" "$PKG" "/" "$TARGET" "/"

if [ "${RELEASE:-0}" = 1 ]; then
  check "bundle signed with Developer ID" bash -c "codesign -d --verbose=2 '$APP' 2>&1 | grep -q 'Authority=Developer ID Application'"
  check "package signed with Developer ID Installer" bash -c "pkgutil --check-signature '$PKG' | grep -q 'Developer ID Installer'"
  check "Gatekeeper accepts the package" spctl --assess --type install "$PKG"
  check "notarization ticket stapled" xcrun stapler validate "$PKG"
fi

if [ "$failures" -gt 0 ]; then echo "$failures check(s) failed"; exit 1; fi
echo "all checks passed"
