#!/usr/bin/env python3
import json
import sys
import os

def print_colored(text, color):
    """Print colored text"""
    colors = {
        'red': '\033[0;31m',
        'green': '\033[0;32m',
        'yellow': '\033[1;33m',
        'blue': '\033[0;34m',
        'purple': '\033[0;35m',
        'cyan': '\033[0;36m',
        'white': '\033[1;37m',
        'reset': '\033[0m'
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")

def main():
    if len(sys.argv) < 2:
        print("Usage: parse_simple_results.py <analysis_file.json>")
        sys.exit(1)
    
    analysis_file = sys.argv[1]
    
    if not os.path.exists(analysis_file):
        print(f"Error: Analysis file not found: {analysis_file}")
        sys.exit(1)
    
    with open(analysis_file, 'r') as f:
        results = json.load(f)
    
          print_colored("\n" + "="*60, 'white')
          print_colored("🎯 REVERSELABS FLUTTER SSL HUNTER - ANALYSIS RESULTS", 'cyan')
          print_colored("="*60, 'white')
    
    # Display analysis info
    analysis_info = results.get("analysis_info", {})
    print_colored(f"\n📄 Program: {analysis_info.get('program_name', 'Unknown')}", 'blue')
    print_colored(f"🔧 Method: {analysis_info.get('analysis_method', 'strings')}", 'blue')
    
    # Display SSL strings found
    ssl_strings = results.get("ssl_strings", {})
    if ssl_strings:
        print_colored(f"\n🔍 Found {len(ssl_strings)} SSL strings:", 'green')
        for ssl_str, data in ssl_strings.items():
            if isinstance(data, dict) and "addresses" in data:
                print_colored(f"  ✅ '{ssl_str}': {data['count']} occurrences", 'green')
                for addr_info in data["addresses"]:
                    print_colored(f"    📍 RVA: {addr_info['rva']} | Address: {addr_info['address']}", 'blue')
            else:
                print_colored(f"  ✅ '{ssl_str}': {data} occurrences", 'green')
    else:
        print_colored("\n⚠️  No SSL strings found", 'yellow')
    
    # Display SSL functions
    ssl_functions = results.get("ssl_functions", [])
    if ssl_functions:
        print_colored(f"\n🎯 Found {len(ssl_functions)} SSL functions:", 'green')
        for func in ssl_functions:
            if func.get("source") == "objdump_symbol_table":
                print_colored(f"  🔧 {func['name']} (objdump)", 'white')
                print_colored(f"    📍 Address: {func['address']}", 'purple')
                print_colored(f"    📍 RVA: {func['rva']}", 'blue')
                print_colored(f"    📍 Base: {func['base_address']}", 'cyan')
            elif "ssl_client_rva" in func:
                print_colored(f"  📍 {func['name']} - RVA: {func['ssl_client_rva']} (strings)", 'blue')
            else:
                print_colored(f"  📍 {func['name']} ({func.get('occurrences', 0)} occurrences)", 'blue')
    else:
        print_colored("\n⚠️  No SSL function patterns found", 'yellow')
    
    # Display Frida offsets
    frida_offsets = results.get("frida_offsets", [])
    if frida_offsets:
        print_colored(f"\n🚀 Frida Offsets Found:", 'green')
        for offset in frida_offsets:
            print_colored(f"  🎯 {offset['function_name']}", 'white')
            print_colored(f"    📍 RVA: {offset['rva']}", 'purple')
            print_colored(f"    📍 Base: {offset['base_address']}", 'blue')
            print_colored(f"    📝 {offset['description']}", 'cyan')
    else:
        print_colored("\n⚠️  No Frida offsets found", 'yellow')
    
    # Summary
    print_colored("\n" + "="*60, 'white')
    if ssl_strings or ssl_functions:
        print_colored("✅ SSL components found - manual analysis recommended!", 'green')
        print_colored("💡 Use the RVAs above for Frida SSL bypass", 'blue')
    else:
        print_colored("⚠️  No SSL components found - app may use custom SSL", 'yellow')
    print_colored("="*60, 'white')

if __name__ == "__main__":
    main()
