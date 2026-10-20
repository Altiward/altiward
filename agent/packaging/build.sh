#!/bin/bash
# Builds Altiward.app and Altiward-<version>.pkg.
#
#   agent/packaging/build.sh
#
# Environment (all optional; the defaults give a local, ad-hoc-signed build):
#   OUT                  output folder (default ~/Library/Caches/altiward/package; never
#                        inside iCloud-synced ~/Documents, where codesign refuses products)
#   APP_IDENTITY         codesign identity for the bundle and binaries (default "-", ad hoc)
#   INSTALLER_IDENTITY   productbuild signing identity ("Developer ID Installer: …")
#   KEYCHAIN             keychain holding those identities
#   NOTARY_KEY_PATH, NOTARY_KEY_ID, NOTARY_ISSUER
#                        App Store Connect API key: when set, notarize and staple the package
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
AGENT="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$AGENT/.." && pwd)"
OUT="${OUT:-$HOME/Library/Caches/altiward/package}"
SCRATCH="${SCRATCH:-$HOME/Library/Caches/altiward/agent-release}"
APP_IDENTITY="${APP_IDENTITY:--}"
INSTALL_DIR="/Library/Application Support/Altiward"
VERSION="$(sed -n 's/.*public static let current = "\(.*\)".*/\1/p' "$AGENT/Sources/AltiwardCore/DeviceIdentity.swift")"
[ -n "$VERSION" ] || { echo "could not read AgentVersion.current" >&2; exit 1; }

case "$OUT" in "$HOME/Documents"*|"$HOME/Library/Mobile Documents"*)
  echo "OUT must be outside iCloud-synced folders: $OUT" >&2; exit 1;; esac

echo "== building $VERSION (universal, release)"
swift build --package-path "$AGENT" --scratch-path "$SCRATCH" -c release --arch arm64 --arch x86_64 \
  2> >(grep -v "x86_64 architecture is deprecated" >&2)
BIN="$(swift build --package-path "$AGENT" --scratch-path "$SCRATCH" -c release --arch arm64 --arch x86_64 --show-bin-path)"

echo "== assembling Altiward.app"
rm -rf "$OUT" && mkdir -p "$OUT"
APP="$OUT/Altiward.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
# The hook is installed as "Altiward": Privileges shows the file's name in its settings
# ("Run after privilege change"), where admins see it.
cp "$BIN/altiward-agent" "$APP/Contents/MacOS/"
cp "$BIN/altiward-hook" "$APP/Contents/MacOS/Altiward"
cp "$HERE/LaunchDaemons/com.altiward.agent.plist" "$APP/Contents/Resources/"
# The brand's app icon, built by `make app-icon` from assets/brand.
cp "$HERE/AppIcon.icns" "$APP/Contents/Resources/"
install -m 0755 "$HERE/uninstall.sh" "$APP/Contents/Resources/uninstall.sh"
# Apache 2.0 travels with the binaries: the licence and the notice.
cp "$REPO/LICENSE" "$REPO/NOTICE" "$APP/Contents/Resources/"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>com.altiward.agent</string>
    <key>CFBundleName</key><string>Altiward</string>
    <key>CFBundleExecutable</key><string>altiward-agent</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSUIElement</key><true/>
    <key>NSHumanReadableCopyright</key><string>Works with SAP Privileges.</string>
</dict>
</plist>
PLIST

echo "== signing ($([ "$APP_IDENTITY" = "-" ] && echo "ad hoc" || echo "$APP_IDENTITY"))"
SIGN=(codesign --force --options runtime)
if [ "$APP_IDENTITY" = "-" ]; then SIGN+=(--timestamp=none); else SIGN+=(--timestamp); fi
[ -n "${KEYCHAIN:-}" ] && SIGN+=(--keychain "$KEYCHAIN")
# Inside out: each binary with the identifier its code requirement names, then the bundle.
"${SIGN[@]}" --sign "$APP_IDENTITY" --identifier com.altiward.hook "$APP/Contents/MacOS/Altiward"
"${SIGN[@]}" --sign "$APP_IDENTITY" --identifier com.altiward.agent "$APP/Contents/MacOS/altiward-agent"
"${SIGN[@]}" --sign "$APP_IDENTITY" "$APP"
codesign --verify --strict "$APP"

echo "== Privileges profile pinned to this hook"
HOOK_SHA="$(shasum -a 256 "$APP/Contents/MacOS/Altiward" | cut -d' ' -f1)"
sed "s/REPLACE_WITH_SHA256_OF_SIGNED_HOOK/$HOOK_SHA/" "$REPO/deploy/mdm/corp.sap.privileges.plist" > "$OUT/corp.sap.privileges.plist"
plutil -lint "$OUT/corp.sap.privileges.plist" >/dev/null
codesign -d -r- "$APP/Contents/MacOS/Altiward" 2>/dev/null | sed -n 's/^\(# \)\{0,1\}designated => /hook requirement (HookCodeRequirement): /p'

echo "== packaging"
ROOT="$OUT/pkgroot"
mkdir -p "$ROOT$INSTALL_DIR"
ditto "$APP" "$ROOT$INSTALL_DIR/Altiward.app"
pkgbuild --analyze --root "$ROOT" "$OUT/component.plist" >/dev/null
# Install exactly where we say, never over a same-ID bundle found elsewhere on disk.
/usr/libexec/PlistBuddy -c "Delete :0:BundleIsRelocatable" "$OUT/component.plist" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :0:BundleIsRelocatable bool false" "$OUT/component.plist"
# Install this version whatever is there, even a newer one: downgrades are allowed so MDM
# can roll back, and the agent reports a downgrade as an agent-version tamper event.
/usr/libexec/PlistBuddy -c "Delete :0:BundleIsVersionChecked" "$OUT/component.plist" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :0:BundleIsVersionChecked bool false" "$OUT/component.plist"
pkgbuild --root "$ROOT" --component-plist "$OUT/component.plist" --scripts "$HERE/scripts" \
  --identifier com.altiward.agent.pkg --version "$VERSION" --install-location / "$OUT/component.pkg" >/dev/null
PKG="$OUT/Altiward-$VERSION.pkg"
# A distribution file gives Installer its title ("Install Altiward" rather than empty
# quotes) and the brand mark behind its steps (built by `make app-icon`), installs only on
# the system volume, and refuses macOS older than the binaries.
productbuild --synthesize --package "$OUT/component.pkg" "$OUT/distribution.xml" >/dev/null
awk '{ print } /<installer-gui-script/ {
  print "    <title>Altiward</title>"
  print "    <background file=\"background.tiff\" mime-type=\"image/tiff\" alignment=\"bottomleft\" scaling=\"none\"/>"
  print "    <background-darkAqua file=\"background-dark.tiff\" mime-type=\"image/tiff\" alignment=\"bottomleft\" scaling=\"none\"/>"
  print "    <domains enable_anywhere=\"false\" enable_currentUserHome=\"false\" enable_localSystem=\"true\"/>"
  print "    <allowed-os-versions><os-version min=\"13.0\"/></allowed-os-versions>"
}' "$OUT/distribution.xml" > "$OUT/distribution.tmp" && mv "$OUT/distribution.tmp" "$OUT/distribution.xml"
PB=(productbuild --distribution "$OUT/distribution.xml" --resources "$HERE/installer" --package-path "$OUT")
if [ -n "${INSTALLER_IDENTITY:-}" ]; then
  PB+=(--sign "$INSTALLER_IDENTITY"); [ -n "${KEYCHAIN:-}" ] && PB+=(--keychain "$KEYCHAIN")
fi
"${PB[@]}" "$PKG" >/dev/null
rm -rf "$ROOT" "$OUT/component.pkg" "$OUT/component.plist" "$OUT/distribution.xml"

if [ -n "${NOTARY_KEY_PATH:-}" ]; then
  echo "== notarizing"
  xcrun notarytool submit "$PKG" --key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" --wait
  xcrun stapler staple "$PKG"
fi

echo "== done"
echo "  $APP"
echo "  $PKG"
echo "  $OUT/corp.sap.privileges.plist (PostChangeExecutableChecksum $HOOK_SHA)"
