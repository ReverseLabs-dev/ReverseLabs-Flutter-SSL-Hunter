#!/bin/bash
# flutter-ssl-hunter.sh - Flutter SSL Hunter
# Fast and lightweight SSL analysis using strings + Python

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}
╔══════════════════════════════════════════════════════════════╗
║                🎯 ReverseLabs Flutter SSL Hunter 🎯          ║
║              Automated SSL Pin-Analysis Tool for Flutter     ║
║                    Hunt SSL Memory Address                    ║
║                                                              ║
║                        By: carlosadrianosj                    ║
╚══════════════════════════════════════════════════════════════╝
${NC}"
    
    # Show banner for 3 seconds
    echo -e "${YELLOW}Starting analysis in 3 seconds...${NC}"
    sleep 3
}

print_step() {
    echo -e "${MAGENTA}[STEP]${NC} $1"
}

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_banner

# Check arguments
if [ $# -lt 1 ]; then
    print_error "Usage: $0 <file.apk|file.so|path/to/file>"
    echo ""
    echo "Examples:"
    echo "  $0 my_app.apk"
    echo "  $0 path/to/libflutter.so"
    exit 1
fi

TARGET_FILE="$1"
TARGET_BASENAME=$(basename "$TARGET_FILE")
INPUT_DIR="input"
OUTPUT_DIR="output"
IMAGE_NAME="flutter-ssl-hunter"

# Create input and output directories if they don't exist
mkdir -p "$INPUT_DIR" "$OUTPUT_DIR"

print_step "Target file: $TARGET_BASENAME"

# Copy the target file to the input directory
if [ ! -f "$TARGET_FILE" ]; then
    print_error "File not found: $TARGET_FILE"
    exit 1
fi
cp "$TARGET_FILE" "$INPUT_DIR/"
print_status "File copied to input directory"

print_status "Type: $(file -b --mime-type "$INPUT_DIR/$TARGET_BASENAME" | grep -q "zip" && echo "APK (Flutter)" || echo "Shared Library")"
print_status "Size: $(du -h "$INPUT_DIR/$TARGET_BASENAME" | awk '{print $1}')"

# Check if Docker is running
print_step "Checking Docker..."
if ! docker info >/dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi
print_success "Docker is running"

# Build Docker image
print_step "Checking Docker image..."
if ! docker image inspect "$IMAGE_NAME" &> /dev/null; then
    print_status "Building Docker image..."
    if docker build -t "$IMAGE_NAME" . >/dev/null 2>&1; then
        print_success "Docker image built successfully"
    else
        print_error "Failed to build Docker image"
        exit 1
    fi
else
    print_success "Docker image already exists, skipping build..."
fi

# Prepare directories (clean output for fresh analysis)
print_step "Preparing directories..."
rm -rf "$OUTPUT_DIR/*" # Clear previous output

# Run analysis
print_step "Starting automated analysis..."
if docker run --rm \
    -v "$(pwd)/$INPUT_DIR:/work/input" \
    -v "$(pwd)/$OUTPUT_DIR:/work/output" \
    "$IMAGE_NAME" "$TARGET_BASENAME" >/dev/null 2>&1; then
    print_success "✅ $TARGET_BASENAME analyzed successfully"
else
    print_success "✅ $TARGET_BASENAME analysis completed"
fi

print_step "Analysis completed!"

# Collect statistics
SUCCESS_COUNT=0
FAILURE_COUNT=0
TOTAL_FILES=0
GENERATED_FILES=""

for json_file in "$OUTPUT_DIR"/*.ssl_analysis.json; do
    if [ -f "$json_file" ]; then
        TOTAL_FILES=$((TOTAL_FILES+1))
        # Check if file has SSL strings (success) or is empty (failure)
        if grep -q '"ssl_strings": {' "$json_file" && [ -s "$json_file" ]; then
            SUCCESS_COUNT=$((SUCCESS_COUNT+1))
        else
            FAILURE_COUNT=$((FAILURE_COUNT+1))
        fi
        GENERATED_FILES+="  📄 $(basename "$json_file") ($(du -h "$json_file" | awk '{print $1}'))\n"
    fi
done

# Only show failures if there are any
if [ $FAILURE_COUNT -gt 0 ]; then
    print_error "❌ $FAILURE_COUNT analysis failed"
fi

print_status "📄 Generated files in output/:"
if [ -n "$GENERATED_FILES" ]; then
    echo -e "$GENERATED_FILES"
else
    print_error "No JSON files generated"
fi

# Show memory addresses summary
echo ""
print_step "🎯 Memory addresses summary:"

if [ $SUCCESS_COUNT -gt 0 ]; then
    for json_file in "$OUTPUT_DIR"/*.ssl_analysis.json; do
        if [ -f "$json_file" ]; then
            echo ""
            echo -e "${WHITE}📄 $(basename "$json_file")${NC}"
            
            # Parse JSON and show results clearly
            python3 -c "
import json
import sys
with open('$json_file', 'r') as f:
    data = json.load(f)

print('\\033[0;36m🎯 MEMORY ADDRESSES FOUND:\\033[0m')
print('=' * 60)

ssl_strings = data.get('ssl_strings', {})
if ssl_strings:
    print('\\033[0;32m[+] SSL strings found:\\033[0m')
    for s, info in ssl_strings.items():
        if 'addresses' in info and info['addresses']:
            for addr_info in info['addresses']:
                print('  🔍 {}'.format(s))
                print('    📍 RVA     = {}'.format(addr_info['rva']))
                print('    📍 Address = {}'.format(addr_info['address']))
                print('    📍 Base    = {}'.format(addr_info['base_address']))
                print('')

frida_offsets = data.get('frida_offsets', [])
if frida_offsets:
    print('\\033[0;32m[+] Frida offsets:\\033[0m')
    for offset_info in frida_offsets:
        print('  🎯 {}'.format(offset_info['function_name']))
        print('    📍 RVA  = {}'.format(offset_info['rva']))
        print('    📍 Base = {}'.format(offset_info['base_address']))
        print('')

print('\\033[0;36m🚀 FRIDA USAGE:\\033[0m')
print('')
print('\\033[0;33m1. Create ssl_hook.js file:\\033[0m')
print('')
print('const m = Process.findModuleByName(\"libflutter.so\");')
if frida_offsets:
    for offset_info in frida_offsets:
        print('const offset = ptr(\"{}\");'.format(offset_info['rva']))
        print('const addr = m.base.add(offset);')
        print('')
        print('Interceptor.attach(addr, {')
        print('    onEnter: function(args) {')
        print('        console.log(\"[+] SSL verification called!\");')
        print('    },')
        print('    onLeave: function(retval) {')
        print('        console.log(\"[+] Original return:\", retval);')
        print('        retval.replace(1);  // Force success')
        print('        console.log(\"[+] SSL bypassed!\");')
        print('    }')
        print('});')
        break
else:
    print('// Use the RVAs above to create your hooks')
print('')
print('\\033[0;33m2. Run with Frida:\\033[0m')
print('frida -U -f com.app.package -l ssl_hook.js')
print('')
print('')
print('')
print('')
"
        fi
    done
else
    print_warning "No SSL functions identified"
fi

print_success "🎉 ReverseLabs Flutter SSL Hunter - Analysis complete!"
print_status "Check files in output/ for more details"
print_status "Use the RVAs above for Frida SSL bypass"

echo ""
print_status "🔗 ReverseLabs Flutter SSL Hunter - Hunt SSL Memory Addresses"
echo ""
echo -e "${CYAN}By: carlosadrianosj${NC}"