# 🚀 ReverseLabs Flutter SSL Hunter - Quick Execution Guide

This document provides a quick guide on how to run **ReverseLabs Flutter SSL Hunter** to analyze Flutter applications for SSL pinning bypass points.

---

## 🛠️ **Requirements**

-   **Docker** installed and running on your machine.

---

## 🏃 **Steps to Execute**

### **1. Navigate to the project directory:**
```bash
cd /path/to/your/project/flutter-ssl-hunter
```

### **2. Run analysis with your APK or .SO file:**

**Example with an APK:**
```bash
./flutter-ssl-hunter.sh ../apps-test/venue/venue_arm64.apk
```

**Example with a .SO file:**
```bash
./flutter-ssl-hunter.sh /path/to/your/libflutter.so
```

---

## 📊 **What to Expect:**

The script will:
-   ✅ Check and build Docker image (if necessary)
-   ✅ Extract `libflutter.so` from APK (if it's an APK)
-   ✅ Perform SSL analysis using **objdump + grep + strings**
-   ✅ **Calculate and display RVAs (Relative Virtual Addresses)** for found SSL strings
-   ✅ **Generate a Frida script** (`.js`) in the `output/` folder with found offsets
-   ✅ Display formatted results summary in terminal

---

## 🎯 **Example Output:**

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

🎯 Found 1 SSL functions:
  📍 ssl_crypto_x509_session_verify_cert_chain - RVA: 0x1b7c25

🚀 Frida Offsets Found:
  🎯 ssl_crypto_x509_session_verify_cert_chain
    📍 RVA: 0x1b7c25
    📍 Base: 0x100000
```

---

## 💡 **Next Steps (after execution):**

### **1. Use the found RVA in Frida:**
```javascript
const m = Process.findModuleByName("libflutter.so");
const offset = ptr("0x1b7c25");  // RVA found by Flutter SSL Hunter
const addr = m.base.add(offset);

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

### **2. For deeper analysis:**
- Use **the RVAs above** for Frida SSL bypass
- Look for the found strings and their XREFs
- Verify if the RVA is correct for your architecture

---

## 🔧 **Useful Commands:**

### **Check detailed results:**
```bash
python3 scripts/parse_results.py output/arm64-v8a_libflutter.so.ssl_analysis.json
```

### **View generated files:**
```bash
ls -la output/
```

### **View generated Frida script:**
```bash
cat output/arm64-v8a_libflutter.so_frida_script.js
```

---

## 🎉 **Happy SSL Hunting!**

**ReverseLabs Flutter SSL Hunter** automates SSL analysis and provides the memory addresses needed for SSL pinning bypass with Frida.

**By: carlosadrianosj**