#!/bin/bash
set -e
cd "$(dirname "$0")"
NAME=usbcfgfix
VER=1.0.0
SDK=$(xcrun --show-sdk-path)
KSDK="$PWD/MacKernelSDK"
LILU="$PWD/lilu/Lilu.kext/Contents/Resources"
OUT="build/$NAME.kext"
rm -rf build; mkdir -p "$OUT/Contents/MacOS" build/obj
FLAGS=(-target x86_64-apple-macos10.15 -std=c++17 -fapple-kext -mkernel -fno-builtin -fno-common -fno-exceptions -fno-rtti -fno-stack-protector -ffreestanding -Os -nostdinc -Wno-stdlibcxx-not-found -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -DAPPLE -DNeXT "-DPRODUCT_NAME=$NAME" "-DMODULE_VERSION=$VER" -isystem "$KSDK/Headers" "-I$LILU")
clang++ "${FLAGS[@]}" -c kern_start.cpp -o build/obj/kern_start.o
clang++ "${FLAGS[@]}" -c "$LILU/Library/plugin_start.cpp" -o build/obj/plugin_start.o
clang -target x86_64-apple-macos10.15 -fapple-kext -mkernel -nostdinc -DKERNEL -DKERNEL_PRIVATE -DAPPLE -isystem "$KSDK/Headers" -c ${NAME}_info.c -o build/obj/info.o
clang++ -target x86_64-apple-macos10.15 -nostdlib -Xlinker -kext -o "$OUT/Contents/MacOS/$NAME" build/obj/*.o -L"$KSDK/Library/x86_64" -lkmod -L"$SDK/usr/lib" -lkmodc++
cp Info.plist "$OUT/Contents/Info.plist"
echo "OK: $OUT"
