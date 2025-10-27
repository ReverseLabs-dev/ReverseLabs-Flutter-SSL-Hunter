# 🎯 ReverseLabs Flutter SSL Hunter

![Tool Demo](https://raw.githubusercontent.com/carlosadrianosj/reverselabs-Flutter-SSL-Hunter/main/tool-action.gif)

## 🚀 Automated SSL Pin-Analysis Tool for Flutter

**ReverseLabs Flutter SSL Hunter** is a powerful Docker-based tool designed to help security researchers and developers identify SSL pinning bypass points in Flutter applications. It automatically extracts `libflutter.so` from APKs, analyzes SSL-related strings using **objdump + grep**, calculates memory addresses (RVAs), and generates ready-to-use Frida scripts.

---

## ✨ **Features**

- **🔍 APK/SO Analysis**: Directly analyze Flutter APKs or standalone `libflutter.so` files
- **📦 Automated Extraction**: Automatically extracts `libflutter.so` from APKs for all architectures
- **🔧 Advanced Analysis**: Uses **objdump + grep + strings** for comprehensive SSL detection
- **📍 RVA Calculation**: Calculates Relative Virtual Addresses (RVAs) for identified strings
- **🎯 Frida Script Generation**: Generates Frida scripts with actual memory offsets
- **🐳 Dockerized**: Runs in a consistent Docker environment
- **🎨 Beautiful Output**: Colored, formatted output with progress bars and clear results

---

## 🛠️ **Requirements**

- [Docker](https://docs.docker.com/get-docker/) installed and running
- No additional dependencies needed!

---

## 🚀 **Quick Start**

### 1. **Clone and Navigate**
```bash
git clone https://github.com/your-repo/ReverseLabs-flutter-ssl-hunter.git
cd ReverseLabs-flutter-ssl-hunter
```

### 2. **Run Analysis**
```bash
# Analyze an APK
./flutter-ssl-hunter.sh /path/to/your/app.apk

# Analyze a .so file
./flutter-ssl-hunter.sh /path/to/libflutter.so
```

### 3. **View Results**
The tool will automatically:
- Extract `libflutter.so` (if APK)
- Analyze SSL strings and functions
- Calculate memory addresses
- Generate Frida scripts
- Display formatted results

---

## 📋 **Usage Examples**

### **Example 1: Analyze Flutter APK**
```bash
./flutter-ssl-hunter.sh ../apps/my_flutter_app.apk
```

**Output:**
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
    📝 SSL verification function (found via ssl_client reference)
```

### **Example 2: Analyze .so File**
```bash
./flutter-ssl-hunter.sh /path/to/libflutter.so
```

---

## 🔧 **How It Works**

### **1. Input Processing**
- Detects file type (APK or .so)
- Extracts `libflutter.so` from APK if needed

### **2. SSL Analysis**
- **objdump -t**: Searches symbol table for SSL functions
- **objdump -d**: Analyzes disassembly for SSL function calls
- **strings + Python**: Finds SSL-related strings and calculates addresses

### **3. Address Calculation**
- Base address: `0x100000` (common for Android libraries)
- RVA = String offset from file start
- Memory address = Base + RVA

### **4. Output Generation**
- JSON file with detailed analysis
- Frida script with calculated offsets
- Formatted console output with progress bars

---

## 📁 **Project Structure**

```
flutter-ssl-hunter/
├── 🐳 Dockerfile              # Docker image definition
├── 🚀 flutter-ssl-hunter.sh   # Main entry point script
├── 📋 requirements.txt        # Python dependencies
├── 📖 README.md              # This file
├── 📝 EXECUTE.md             # Quick execution guide
├── 🎯 EXAMPLE.md              # Usage example
├── 🔧 entrypoint.sh          # Docker entrypoint script
├── .gitignore                # Git ignore file
├── scripts/
│   ├── 🔍 analyze_ssl.sh      # Core SSL analysis script
│   ├── 📦 extract_so.sh       # APK extraction script
│   └── 📊 parse_results.py     # Results parser
├── input/                    # Input files directory
└── output/                   # Analysis results directory
    ├── libs/                 # Extracted .so files
    ├── *.ssl_analysis.json   # Analysis results
    └── *_frida_script.js     # Generated Frida scripts
```

---

## 🎯 **Using Results with Frida**

### **1. Basic SSL Bypass**
```javascript
// Use the RVA found by Flutter SSL Hunter
const m = Process.findModuleByName("libflutter.so");
const offset = ptr("0x1b7c25");  // RVA from analysis
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

### **2. Advanced SSL Bypass**
```javascript
// Multiple SSL functions bypass
const ssl_functions = [
    { name: "ssl_client", rva: "0x1b7c25" },
    { name: "ssl_server", rva: "0x1c0ea3" },
    { name: "verify_cert", rva: "0x1b5ba9" }
];

const m = Process.findModuleByName("libflutter.so");

ssl_functions.forEach(func => {
    const offset = ptr(func.rva);
    const addr = m.base.add(offset);
    
    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log(`[+] ${func.name} called!`);
        },
        onLeave: function(retval) {
            retval.replace(1); // Bypass SSL verification
            console.log(`[+] ${func.name} bypassed!`);
        }
    });
});
```

---

## 🔍 **Understanding the Output**

### **SSL Strings Found**
- **ssl_client**: Main SSL client function (primary target)
- **ssl_server**: SSL server function
- **Invalid certificate verification context**: Error message indicating SSL verification
- **certificate chain too long**: SSL certificate validation error
- **self signed certificate in certificate chain**: SSL certificate validation error

### **Memory Addresses**
- **RVA**: Relative Virtual Address (offset from base)
- **Address**: Full memory address (base + RVA)
- **Base**: Base address of the library (usually 0x100000)

### **Frida Offsets**
- Ready-to-use offsets for Frida hooking
- Calculated from actual string positions in the binary

---

## 🚨 **Important Notes**

### **⚠️ Limitations**
- **Approximate addresses**: Uses heuristic base address (0x100000)
- **String-based analysis**: Finds strings, not exact function addresses
- **Manual verification**: Use the RVAs found for Frida SSL bypass

### **🔒 Legal Considerations**
- Only analyze applications you own or have permission to analyze
- Respect terms of service and applicable laws
- Use responsibly for security research and testing

### **💡 Tips for Success**
- **Target ssl_client**: This is usually the main SSL verification function
- **Use the RVAs**: For Frida SSL bypass hooks
- **Test multiple RVAs**: Different functions may be called in different scenarios
- **Monitor logs**: Check Frida logs for successful hooks

---

## 🛠️ **Troubleshooting**

### **Docker Issues**
```bash
# Check Docker status
docker info

# Rebuild image if needed
docker build -t flutter-ssl-hunter .
```

### **No SSL Strings Found**
- App might not use Flutter SSL
- Try different search patterns
- Use the RVAs for manual analysis

### **Frida Hooks Not Working**
- Verify RVA is correct
- Check if function signature matches
- Use the RVAs above for Frida SSL bypass

---

## 🤝 **Contributing**

Feel free to open issues or pull requests if you have suggestions or improvements!

---

## 📄 **License**

This project is licensed under the MIT License.

---

## 🎉 **Happy Hunting!**

**ReverseLabs Flutter SSL Hunter** makes SSL pinning analysis fast and automated. Use the results responsibly and always verify addresses with the RVAs provided for production use.

**🔗 ReverseLabs Flutter SSL Hunter - Hunt SSL Memory Addresses**

---

**By: carlosadrianosj**