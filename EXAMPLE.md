# 🎯 ReverseLabs Flutter SSL Hunter - Usage Example

## 📋 **Command to Test:**

```bash
# Navigate to the project directory
cd /Users/carlosadrianosj/Documents/mobile-automations/flutter/flutter-ssl-hunter

# Run analysis with example APK
./flutter-ssl-hunter.sh ../apps-test/venue/venue_arm64.apk
```

## 🎯 **What to Expect:**

1. **Extraction**: The tool will extract `libflutter.so` from the APK
2. **Analysis**: Will use objdump + grep + strings to find SSL functions
3. **Results**: Will show calculated RVAs for found SSL strings
4. **Frida Script**: Will generate a ready-to-use Frida script

## 📊 **Example Output:**

```
🎯 FLUTTER SSL HUNTER - ANALYSIS RESULTS
============================================================
📄 Program: arm64-v8a_libflutter.so
🔧 Method: objdump + grep + strings + Python

🔍 Found 10 SSL strings:
  ✅ 'ssl_client': 1 occurrences
    📍 RVA: 0x1b7c25 | Address: 0x2b7c25
  ✅ 'ssl_server': 1 occurrences
    📍 RVA: 0x1c0ea3 | Address: 0x2c0ea3
  ✅ 'Invalid certificate verification context': 1 occurrences
    📍 RVA: 0x1b5ba9 | Address: 0x2b5ba9

🎯 Found 1 SSL functions:
  📍 ssl_crypto_x509_session_verify_cert_chain - RVA: 0x1b7c25

🚀 Frida Offsets Found:
  🎯 ssl_crypto_x509_session_verify_cert_chain
    📍 RVA: 0x1b7c25
    📍 Base: 0x100000
```

## 🚀 **How to Use the Results:**

```javascript
// Use the RVA found by Flutter SSL Hunter
const m = Process.findModuleByName("libflutter.so");
const offset = ptr("0x1b7c25");  // RVA of ssl_client
const addr = m.base.add(offset);

console.log("Target address:", addr);

Interceptor.attach(addr, {
    onEnter: function(args) {
        console.log("[+] SSL verification called!");
    },
    onLeave: function(retval) {
        retval.replace(1); // Force return TRUE (success)
        console.log("[+] SSL verification bypassed!");
    }
});
```

## 📁 **Generated Files:**

- `output/arm64-v8a_libflutter.so.ssl_analysis.json` - Detailed analysis
- `output/arm64-v8a_libflutter.so_frida_script.js` - Ready-to-use Frida script
- `output/libs/arm64-v8a_libflutter.so` - Extracted .so file

## 🎉 **Ready to Use!**

ReverseLabs Flutter SSL Hunter automates all SSL analysis and provides the memory addresses needed for SSL pinning bypass!

**By: carlosadrianosj**