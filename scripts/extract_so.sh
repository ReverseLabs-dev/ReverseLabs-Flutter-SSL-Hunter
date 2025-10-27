#!/bin/bash
set -e
APK="$1"
OUTDIR="$2"

if [ -z "$APK" ] || [ -z "$OUTDIR" ]; then
    echo "Usage: extract_so.sh <apk_file> <output_dir>"
    exit 1
fi

if [ ! -f "$APK" ]; then
    echo "Error: APK file not found: $APK"
    exit 1
fi

print_status() {
    echo -e "\033[0;34m[*]\033[0m $1"
}

print_success() {
    echo -e "\033[0;32m[+]\033[0m $1"
}

print_error() {
    echo -e "\033[0;31m[-]\033[0m $1"
}

TMP="/tmp/apk_extract_$$"
rm -rf "$TMP"
mkdir -p "$TMP"

print_status "Extracting APK: $APK"
unzip -o "$APK" -d "$TMP" >/dev/null

mkdir -p "$OUTDIR/libs"

print_status "Searching for libflutter.so files..."
# Find all libflutter.so files across different ABIs and copy them
found_libs=0
for so_file in $(find "$TMP/lib" -type f -name "libflutter.so"); do
    ABI=$(basename $(dirname "$so_file"))
    cp "$so_file" "$OUTDIR/libs/${ABI}_libflutter.so"
    print_status "  Found: $ABI/libflutter.so"
    found_libs=$((found_libs+1))
done

if [ "$found_libs" -eq 0 ]; then
    print_error "No libflutter.so files found in APK"
    rm -rf "$TMP"
    exit 1
fi

print_success "Extracted $found_libs libflutter.so files to $OUTDIR/libs/"
rm -rf "$TMP"