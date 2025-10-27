#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Progress indicator
show_progress() {
    local step=$1
    local total=$2
    local desc=$3
    local percentage=$((step * 100 / total))
    printf "\r${CYAN}[${NC}%3d%%${CYAN}]${NC} ${WHITE}${desc}${NC}" $percentage
}

print_banner() {
    echo -e "${CYAN}
╔══════════════════════════════════════════════════════════════╗
║              ReverseLabs Flutter SSL Pinning Memory Address  ║
║                    Finder Automated Analysis Engine          ║
╚══════════════════════════════════════════════════════════════╝
${NC}"
}

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_banner

# Check arguments
if [ $# -lt 1 ]; then
    print_error "Usage: docker run --rm -v \$(pwd)/input:/work/input -v \$(pwd)/output:/work/output image <file.apk|file.so>"
    echo ""
    echo "Docker image includes all necessary tools - no need to mount external tools!"
    exit 1
fi

TARGET_FILE="$1"
OUTDIR=/work/output
INDIR=/work/input

mkdir -p "$OUTDIR" "$INDIR"

print_status "Target file: $TARGET_FILE"

# Determine file type and process
if [[ "$TARGET_FILE" == *.apk ]]; then
    print_status "APK detected: $TARGET_FILE"
    show_progress 1 4 "Extracting libflutter.so from APK for all architectures..."
    echo ""
    /work/scripts/extract_so.sh "/work/input/$TARGET_FILE" "$OUTDIR"

    # Process each libflutter.so found
    SO_FILES=$(find "$OUTDIR/libs" -type f -name "*libflutter.so" 2>/dev/null)
    if [ -z "$SO_FILES" ]; then
        print_error "No libflutter.so files found in APK"
        exit 3
    fi

    print_success "Found libflutter.so files:"
    for so in $SO_FILES; do
        echo "  - $(basename $(dirname $so))/$(basename $so)"
    done

elif [[ "$TARGET_FILE" == *.so ]]; then
    print_status "Shared library detected: $TARGET_FILE"
    show_progress 1 4 "Copying .so file for processing..."
    echo ""
    # Copy the .so file to output directory for processing
    cp "/work/input/$TARGET_FILE" "$OUTDIR/"
    SO_FILES="$OUTDIR/$(basename "$TARGET_FILE")"
else
    print_error "Unsupported file type. Please provide .apk or .so file"
    exit 2
fi

print_status "Starting advanced SSL analysis..."
show_progress 2 4 "Initializing analysis engine..."
echo ""

# Process each .so file
for so in $SO_FILES; do
    print_status "Analyzing: $(basename $so)"
    show_progress 3 4 "Running objdump + grep + strings analysis..."
    echo ""
    /work/scripts/analyze_ssl.sh "$so" "$OUTDIR"
done

show_progress 4 4 "Analysis complete!"
echo ""
print_success "Analysis complete! Check the output above for memory addresses."
print_status "Results saved in: $OUTDIR"