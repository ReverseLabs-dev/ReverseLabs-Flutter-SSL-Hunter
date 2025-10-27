#!/usr/bin/env python3

# Script to fix the output formatting in flutter-ssl-hunter.sh

with open('flutter-ssl-hunter.sh', 'r') as f:
    content = f.read()

# Replace the Frida command section
old_section = '''print('\\033[0;36m🚀 FRIDA USAGE:\\033[0m')
print('const m = Process.findModuleByName("libflutter.so");')
if frida_offsets:
    for offset_info in frida_offsets:
        print('const offset = ptr("{}");'.format(offset_info['rva']))
        print('const addr = m.base.add(offset);')
        print('Interceptor.attach(addr, { onEnter: function(args) { console.log("[+] SSL called!"); }, onLeave: function(retval) { retval.replace(1); } });')
        break
else:
    print('// Use the RVAs above to create your hooks')'''

new_section = '''print('\\033[0;36m🚀 FRIDA USAGE:\\033[0m')
print('')
print('\\033[0;33m1. Create ssl_hook.js file:\\033[0m')
print('')
print('const m = Process.findModuleByName("libflutter.so");')
if frida_offsets:
    for offset_info in frida_offsets:
        print('const offset = ptr("{}");'.format(offset_info['rva']))
        print('const addr = m.base.add(offset);')
        print('')
        print('Interceptor.attach(addr, {')
        print('    onEnter: function(args) {')
        print('        console.log("[+] SSL verification called!");')
        print('    },')
        print('    onLeave: function(retval) {')
        print('        console.log("[+] Original return:", retval);')
        print('        retval.replace(1);  // Force success')
        print('        console.log("[+] SSL bypassed!");')
        print('    }')
        print('});')
        break
else:
    print('// Use the RVAs above to create your hooks')
print('')
print('\\033[0;33m2. Run with Frida:\\033[0m')
print('frida -U -f com.app.package -l ssl_hook.js')'''

content = content.replace(old_section, new_section)

with open('flutter-ssl-hunter.sh', 'w') as f:
    f.write(content)

print("✅ Output formatting fixed!")
