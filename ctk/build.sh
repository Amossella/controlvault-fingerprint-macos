#!/bin/bash
# Build del POC token CryptoTokenKit: app contenitore + estensione .appex,
# firma AD-HOC con entitlement com.apple.token. Nessun Xcode: clang + codesign.
set -e
cd "$(dirname "$0")"
ROOT="$PWD"
# Identità di firma: 1° argomento, o variabile SIGN_ID, altrimenti ad-hoc ("-").
SIGN_ID="${1:-${SIGN_ID:--}}"
echo "Firma con identità: $SIGN_ID"
BUILD="$ROOT/build"
APP="$BUILD/FPTokenApp.app"
EXT="$APP/Contents/PlugIns/FPToken.appex"
SDK="$(xcrun --sdk macosx --show-sdk-path)"

rm -rf "$BUILD"
mkdir -p "$APP/Contents/MacOS" "$EXT/Contents/MacOS"

echo "== compilo l'app contenitore =="
clang -fobjc-arc -isysroot "$SDK" -framework Foundation -framework CryptoTokenKit \
    src/main.m -o "$APP/Contents/MacOS/FPTokenApp"
cp app-Info.plist "$APP/Contents/Info.plist"

echo "== compilo l'estensione CTK =="
# Le app-extension usano NSExtensionMain come entry point (niente main()).
clang -fobjc-arc -fapplication-extension -isysroot "$SDK" \
    -framework Foundation -framework CryptoTokenKit \
    -Wl,-e,_NSExtensionMain \
    src/TokenDriver.m -o "$EXT/Contents/MacOS/FPToken"
cp ext-Info.plist "$EXT/Contents/Info.plist"

echo "== firma (prima l'estensione, poi l'app) =="
codesign --force --sign "$SIGN_ID" --entitlements token.entitlements --timestamp=none "$EXT"
codesign --force --sign "$SIGN_ID" --entitlements token.entitlements --timestamp=none "$APP"

echo "== verifica firma + entitlement estensione =="
codesign -dv "$EXT" 2>&1 | sed 's/^/   /'
echo "   --- entitlements ---"
codesign -d --entitlements - "$EXT" 2>&1 | sed 's/^/   /'

echo
echo "OK. Bundle in: $APP"
