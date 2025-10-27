#!/bin/bash
set -e

SO_PATH="$1"
OUTDIR="$2"
SO_BASENAME=$(basename "$SO_PATH")
OUTFILE="${OUTDIR}/${SO_BASENAME}.ssl_analysis.json"

print_status() {
    echo -e "\033[0;34m[*]\033[0m $1"
}

print_success() {
    echo -e "\033[0;32m[+]\033[0m $1"
}

print_error() {
    echo -e "\033[0;31m[-]\033[0m $1"
}

print_status "Running simple strings analysis for $SO_BASENAME..."

# Create Python script for analysis
cat > /tmp/ssl_analysis_simple.py << 'EOF'
#!/usr/bin/env python3
import json
import sys
import os
import subprocess
import re
import struct

def find_ssl_strings_with_addresses(so_path):
    """Find SSL strings and their memory addresses using objdump + grep"""
    results = {
          "analysis_info": {
              "program_name": os.path.basename(so_path),
              "analysis_method": "objdump + grep + strings + Python"
          },
        "ssl_strings": {},
        "ssl_functions": [],
        "memory_addresses": {},
        "frida_offsets": []
    }
    
    # SSL strings to search for (prioritize ssl_client as per article)
    ssl_strings = [
        "ssl_client",  # Main target from article
        "ssl_server", 
        "ssl_crypto_x509_session_verify_cert_chain",
        "X509_verify_cert",
        "X509_STORE_CTX_init",
        "Invalid certificate verification context",
        "certificate chain too long",
        "self signed certificate in certificate chain",
        "handshake_client",
        "ssl_privkey",
        "ssl_aead_ctx",
        "ssl_cert",
        "ssl_transcript"
    ]
    
    print("🔍 Searching for SSL functions using objdump...")
    
    # Use objdump to find SSL functions and symbols
    ssl_functions_found = {}
    
    try:
        # Get symbol table with objdump -t
        print("📋 Running objdump -t to find SSL symbols...")
        objdump_t_result = subprocess.check_output(['objdump', '-t', so_path], stderr=subprocess.DEVNULL).decode('utf-8')
        
        # Search for SSL-related symbols
        ssl_symbols = [
            'ssl_client', 'ssl_server', 'ssl_crypto', 'x509', 'verify', 'cert',
            'SSL_', 'X509_', 'ssl_', 'tls_', 'crypto_'
        ]
        
        for symbol in ssl_symbols:
            lines = objdump_t_result.split('\n')
            for line in lines:
                if symbol.lower() in line.lower():
                    parts = line.split()
                    if len(parts) >= 6:
                        addr = parts[0]
                        symbol_name = parts[-1]
                        if addr != '00000000' and len(addr) == 8:
                            ssl_functions_found[symbol_name] = addr
                            print(f"✅ Found symbol: {symbol_name} at {addr}")
        
        # Get disassembly with objdump -d to find function calls
        print("🔍 Running objdump -d to find SSL function calls...")
        objdump_d_result = subprocess.check_output(['objdump', '-d', so_path], stderr=subprocess.DEVNULL).decode('utf-8')
        
        # Look for calls to SSL functions
        ssl_call_patterns = [
            r'call.*ssl_client',
            r'call.*ssl_server', 
            r'call.*ssl_crypto',
            r'call.*x509',
            r'call.*verify',
            r'call.*SSL_',
            r'call.*X509_'
        ]
        
        for pattern in ssl_call_patterns:
            matches = re.findall(pattern, objdump_d_result, re.IGNORECASE)
            if matches:
                print(f"🎯 Found SSL calls: {matches}")
        
    except subprocess.CalledProcessError as e:
        print(f"⚠️  objdump failed: {e}")
    except FileNotFoundError:
        print("⚠️  objdump not found, falling back to strings method")
    
    # Fallback to strings method if objdump fails
    print("📝 Using strings method as fallback...")
    
    # Read the binary file
    try:
        with open(so_path, 'rb') as f:
            binary_data = f.read()
    except Exception as e:
        print(f"Error reading binary: {e}")
        return results
    
    # Search for each SSL string and find their addresses
    for ssl_str in ssl_strings:
        str_bytes = ssl_str.encode('utf-8')
        addresses = []
        
        # Find all occurrences of the string
        start = 0
        while True:
            pos = binary_data.find(str_bytes, start)
            if pos == -1:
                break
            
            # Calculate address (assuming base address 0x100000)
            base_addr = 0x100000
            string_addr = base_addr + pos
            rva = pos  # RVA is the offset from base
            
            addresses.append({
                "offset": pos,
                "address": f"0x{string_addr:x}",
                "rva": f"0x{rva:x}",
                "base_address": f"0x{base_addr:x}"
            })
            
            start = pos + 1
        
        if addresses:
            results["ssl_strings"][ssl_str] = {
                "count": len(addresses),
                "addresses": addresses
            }
            print(f"✅ Found '{ssl_str}': {len(addresses)} occurrences")
            for addr_info in addresses:
                print(f"    📍 Offset: 0x{addr_info['offset']:x}, RVA: {addr_info['rva']}")
    
    # Process objdump results
    print("Processing objdump results...")
    
    for func_name, addr in ssl_functions_found.items():
        # Convert address to RVA
        addr_int = int(addr, 16)
        base_addr = 0x100000  # Common base address
        rva = addr_int - base_addr
        
        func_entry = {
            "name": func_name,
            "type": "SSL_FUNCTION",
            "address": addr,
            "rva": f"0x{rva:x}",
            "base_address": f"0x{base_addr:x}",
            "source": "objdump_symbol_table"
        }
        results["ssl_functions"].append(func_entry)
        
        # Add to Frida offsets
        frida_offset = {
            "function_name": func_name,
            "rva": f"0x{rva:x}",
            "base_address": f"0x{base_addr:x}",
            "description": f"SSL function found via objdump: {func_name}"
        }
        results["frida_offsets"].append(frida_offset)
        
        print(f"Added SSL function: {func_name} at {addr} (RVA: 0x{rva:x})")
    
    # Look for function patterns and try to find XREFs (fallback)
    print("Searching for SSL function patterns...")
    
      # Try to find functions that reference ssl_client (main target)
      if "ssl_client" in results["ssl_strings"]:
          ssl_client_addrs = results["ssl_strings"]["ssl_client"]["addresses"]
          
          for addr_info in ssl_client_addrs:
              # This is a simplified approach - in reality you'd need more sophisticated analysis
              # But we can provide the RVA for manual verification
              func_entry = {
                  "name": "ssl_crypto_x509_session_verify_cert_chain",
                  "type": "SSL_VERIFICATION_FUNCTION",
                  "references_ssl_client": True,
                  "ssl_client_rva": addr_info["rva"],
                  "ssl_client_address": addr_info["address"],
                  "base_address": addr_info["base_address"],
                  "source": "strings_analysis"
              }
              results["ssl_functions"].append(func_entry)
              
              # Add to Frida offsets
              frida_offset = {
                  "function_name": "ssl_crypto_x509_session_verify_cert_chain",
                  "rva": addr_info["rva"],
                  "base_address": addr_info["base_address"],
                  "description": "SSL verification function (found via ssl_client reference)"
              }
              results["frida_offsets"].append(frida_offset)
    
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ssl_analysis_simple.py <so_file>")
        sys.exit(1)
    
    so_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else f"{so_path}.ssl_analysis.json"
    
    print(f"Analyzing: {so_path}")
    
    # Perform SSL analysis
    results = find_ssl_strings_with_addresses(so_path)
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to: {output_file}")
    
    # Print summary
    print("\n" + "="*60)
    print("SSL ANALYSIS SUMMARY")
    print("="*60)
    
    if results["ssl_functions"]:
        print(f"Found {len(results['ssl_functions'])} SSL function patterns:")
        for func in results["ssl_functions"]:
            if 'occurrences' in func:
                print(f"  - {func['name']} ({func['occurrences']} occurrences)")
            else:
                print(f"  - {func['name']}")
    else:
        print("No SSL function patterns found")
    
    if results["ssl_strings"]:
        print(f"\nFound {len(results['ssl_strings'])} SSL strings:")
        for ssl_str, count in results["ssl_strings"].items():
            print(f"  - '{ssl_str}': {count} occurrences")
    else:
        print("\nNo SSL strings found")
    
    # Generate Frida script with actual offsets
    if results["frida_offsets"]:
        frida_script = '''// Flutter SSL Bypass - Generated by Flutter SSL Hunter
// Based on ssl_client string analysis (as per article)

const m = Process.findModuleByName("libflutter.so");
console.log("[*] Flutter SSL Hunter - SSL Analysis Results");
console.log("[*] Module:", m.name);
console.log("[*] Base address:", m.base);

'''
        
        # Add Frida hooks for each found offset
        for offset_info in results["frida_offsets"]:
            rva_hex = offset_info["rva"]
            rva_int = int(rva_hex, 16)
            
            frida_script += f'''// {offset_info['description']}
// RVA: {rva_hex}
const offset_{rva_int:x} = ptr("{rva_hex}");
const addr_{rva_int:x} = m.base.add(offset_{rva_int:x});

console.log("[*] SSL function offset: {rva_hex}");
console.log("[*] Target address:", addr_{rva_int:x});

Interceptor.attach(addr_{rva_int:x}, {{
    onEnter: function(args) {{
        console.log("[+] SSL verification called at {rva_hex}");
        console.log("[+] Arguments:", args[0], args[1], args[2]);
    }},
    onLeave: function(retval) {{
        console.log("[+] Original return value:", retval);
        retval.replace(1); // Force return TRUE (success)
        console.log("[+] SSL verification bypassed!");
    }}
}});

'''
        
        frida_script += '''
console.log("[*] SSL bypass hooks installed successfully!");
console.log("[*] Ready to intercept SSL verification!");
'''
        
        script_file = output_file.replace('.ssl_analysis.json', '_frida_script.js')
        with open(script_file, 'w') as f:
            f.write(frida_script)
        
        print(f"\nFrida script generated: {script_file}")
        print("📋 To use with Frida:")
        print(f"   frida -U -f com.app.package --no-pause -l {script_file}")
    
    elif results["ssl_strings"]:
        # Fallback if no offsets found but strings exist
        frida_script = f'''// Flutter SSL Bypass - Generated by Flutter SSL Hunter
// Found SSL strings: {', '.join(results['ssl_strings'].keys())}
// Manual address finding required

const m = Process.findModuleByName("libflutter.so");
console.log("[*] Flutter SSL Hunter - SSL strings found:");
{chr(10).join([f'console.log("[*] {ssl_str}: {data["count"]} occurrences");' for ssl_str, data in results['ssl_strings'].items()])}

// Use the RVAs found above for SSL bypass
// Look for ssl_client string and its XREFs
console.log("[*] Use the RVAs above for Frida SSL bypass");
'''
        
        script_file = output_file.replace('.ssl_analysis.json', '_frida_script.js')
        with open(script_file, 'w') as f:
            f.write(frida_script)
        
        print(f"\nFrida script generated: {script_file}")
        print("⚠️  Manual address finding required - use the RVAs above for Frida SSL bypass")

if __name__ == "__main__":
    main()
EOF

# Run the analysis
python3 /tmp/ssl_analysis_simple.py "$SO_PATH" "$OUTFILE"

if [ -f "$OUTFILE" ]; then
    print_success "Analysis completed: $OUTFILE"
    
    # Parse and display results
    python3 /work/scripts/parse_results.py "$OUTFILE"
else
    print_error "Analysis failed - no output file generated"
    exit 1
fi
