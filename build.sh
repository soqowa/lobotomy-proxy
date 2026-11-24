#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
dest="${1:-$(pwd)/../Deliverables/Lobotomy Proxy.app}"
mkdir -p "$(dirname "$dest")"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
app="$temp/Lobotomy Proxy.app"
mkdir -p "$app/Contents"/{MacOS,Helpers,Resources} "$temp/Icon.iconset"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>LobotomyProxy</string>
<key>CFBundleIdentifier</key><string>local.proxyguard.app</string>
<key>CFBundleName</key><string>Lobotomy Proxy</string>
<key>CFBundleDisplayName</key><string>Lobotomy Proxy</string>
<key>CFBundleVersion</key><string>9</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
plutil -insert CFBundleShortVersionString -string "$(cat VERSION)" "$app/Contents/Info.plist"
cp Brand/lobotomy-proxy.svg "$app/Contents/Resources/"
swiftc App/BrandArtwork.swift App/Icon.swift -o "$temp/icon-maker"
"$temp/icon-maker" Brand/lobotomy-proxy.svg "$temp/Icon.iconset"
iconutil -c icns "$temp/Icon.iconset" -o "$app/Contents/Resources/AppIcon.icns"
for arch in arm64 amd64; do
    swarch="$arch"
    if [[ "$arch" = amd64 ]]; then swarch=x86_64; fi
    (cd engine && CGO_ENABLED=1 MACOSX_DEPLOYMENT_TARGET=14.0 CC="clang -arch $swarch" GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "$temp/core-$arch" .)
    swiftc -O -parse-as-library -target "$swarch-apple-macos14.0" App/Model.swift App/Window.swift App/BrandArtwork.swift App/ZoneLaunch.swift App/FilterPolicy.swift App/FilterView.swift App/ProfileStatus.swift App/BackgroundRelay.swift App/DomainSelection.swift -o "$temp/ui-$arch"
done
lipo -create "$temp/core-arm64" "$temp/core-amd64" -output "$app/Contents/Helpers/lobotomy-proxy"
lipo -create "$temp/ui-arm64" "$temp/ui-amd64" -output "$app/Contents/MacOS/LobotomyProxy"
cp engine/catalog.json "$app/Contents/Resources/catalog.json"
identity="${PROXYGUARD_SIGNING_IDENTITY:--}"
codesign --force --sign "$identity" --timestamp=none --options runtime --identifier local.proxyguard.engine "$app/Contents/Helpers/lobotomy-proxy"
relay="$app/Contents/Library/LoginItems/Lobotomy Proxy Relay.app"
mkdir -p "$relay/Contents/MacOS"
cp "$app/Contents/MacOS/LobotomyProxy" "$relay/Contents/MacOS/LobotomyProxyRelay"
cat > "$relay/Contents/Info.plist" <<'RELAY'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>LobotomyProxyRelay</string>
<key>CFBundleIdentifier</key><string>local.proxyguard.relay-agent</string>
<key>CFBundleName</key><string>Lobotomy Proxy Relay</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>9</string>
<key>LSBackgroundOnly</key><true/>
</dict></plist>
RELAY
codesign --force --sign "$identity" --timestamp=none --options runtime "$relay"
digest="$(shasum -a 256 "$app/Contents/Helpers/lobotomy-proxy" | cut -d" " -f1)"
plutil -insert LobotomyProxyHelperSHA256 -string "$digest" "$app/Contents/Info.plist"
# Pin verified, wire-compatible system helpers when packaging an upgrade.
compatible="${PROXYGUARD_COMPATIBLE_HELPER_SHA256:-}"
if [[ -n "$compatible" ]]; then
    read -r -a hashes <<< "$compatible"
    plutil -insert LobotomyProxyCompatibleHelperHashes -json '[]' "$app/Contents/Info.plist"
    for index in "${!hashes[@]}"; do
        [[ "${hashes[$index]}" =~ ^[0-9a-f]{64}$ ]]
        plutil -insert "LobotomyProxyCompatibleHelperHashes.$index" -string "${hashes[$index]}" "$app/Contents/Info.plist"
    done
fi
codesign --force --sign "$identity" --timestamp=none --options runtime "$app"
codesign --verify --deep --strict "$app"
stage="$(mktemp -d "$(dirname "$dest")/.pg-build-XXXXXX")"
ditto "$app" "$stage/new.app"
if [[ -e "$dest" ]]; then
    test "$(plutil -extract CFBundleIdentifier raw "$dest/Contents/Info.plist")" = local.proxyguard.app
    mv "$dest" "$stage/previous.app"
fi
if ! mv "$stage/new.app" "$dest"; then
    [[ ! -e "$stage/previous.app" ]] || mv "$stage/previous.app" "$dest"
    exit 1
fi
python3 -c 'import shutil,sys;shutil.rmtree(sys.argv[1])' "$stage"
