#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Builds apps/macos/build/Avarok.app with swiftc (no Xcode project): tray-ffi as a static
# library, then TrayKit, the bridge and the host compiled as one module and linked against it.
# Unsigned: signing and notarising are the release lane's job.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$root/apps/macos/build"
target="${CARGO_TARGET_DIR:-$root/target}"
# The one minimum macOS: Info.plist's LSMinimumSystemVersion, read so it is never restated.
min_macos="$(plutil -extract LSMinimumSystemVersion raw "$root/apps/macos/Info.plist")"

MACOSX_DEPLOYMENT_TARGET="$min_macos" cargo build --manifest-path "$root/Cargo.toml" -p tray-ffi --release --locked

rm -rf "$out/Avarok.app"
mkdir -p "$out/Avarok.app/Contents/MacOS"
cp "$root/apps/macos/Info.plist" "$out/Avarok.app/Contents/Info.plist"

swiftc -O -module-name Avarok \
  -target "$(uname -m)-apple-macos$min_macos" \
  -I "$root/TrayKit/Sources/CTrayCore/include" \
  -L "$target/release" -ltray_ffi \
  -framework AppKit -framework SwiftUI -framework WebKit -framework Security -framework ServiceManagement \
  "$root"/TrayKit/Sources/TrayKit/*.swift \
  "$root"/TrayKit/Sources/TrayCoreBridge/*.swift \
  "$root"/apps/macos/Sources/*.swift \
  -o "$out/Avarok.app/Contents/MacOS/Avarok"

plutil -lint "$out/Avarok.app/Contents/Info.plist"
echo "built $out/Avarok.app"
