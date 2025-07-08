# 🔥 How to Run Vuln-Scan - Modular Vulnerability Scanner

## 📖 Overview
Vuln-Scan has been successfully refactored from a monolithic application into a modular architecture. You now have multiple ways to run the complete program.

## 🚀 Quick Start Options

### 1️⃣ Main Entry Point (Easiest - Recommended)
```bash
python3 main.py
```
**Features:**
- ✅ Automatically starts the web interface
- ✅ Checks all dependencies
- ✅ User-friendly web interface at http://localhost:5000
- ✅ Real-time scan progress
- ✅ Download JSON/CSV/PDF reports
- ✅ No menu navigation needed

### 2️⃣ Direct Web Interface
```bash
python3 app_modular.py
```
Then visit: **http://localhost:5000**

### 3️⃣ Command Line Interface (Advanced)
```bash
# Basic scan
python3 main_scanner.py scanme.nmap.org

# With wordlist for directory scanning
python3 main_scanner.py example.com -w /path/to/wordlist.txt

# Custom output directory
python3 main_scanner.py target.com -o ./my_scans/
```

**Features:**
- ✅ Full CLI control
- ✅ Scriptable and automatable
- ✅ Batch processing
- ✅ Custom configurations

### 4️⃣ Individual Module Testing
```bash
# Test HTTP analyzer
python3 tools/http_analyzer.py

# Test Nmap scanner
python3 tools/nmap_scanner.py

# Test email crawler
python3 tools/email_crawler.py
```

## 📁 Project Structure
```
vuln-scan/
├── main.py                  # 🚀 Main entry point
├── app_modular.py           # 🌐 Modular web interface
├── main_scanner.py          # 💻 CLI orchestrator
├── tools/                   # 🔧 Individual scanner modules
│   ├── nmap_scanner.py      #   ├── Port scanning
│   ├── subfinder_scanner.py #   ├── Subdomain enumeration
│   ├── gobuster_scanner.py  #   ├── Directory brute-forcing
│   ├── email_crawler.py     #   ├── Email discovery
│   ├── pwned_checker.py     #   ├── Breach checking
│   ├── nuclei_scanner.py    #   ├── CVE/exploit detection
│   ├── http_analyzer.py     #   ├── HTTP security analysis
│   └── vulnerability_scorer.py # └── Security scoring
├── scan_results/            # 📊 Output reports
├── static/                  # 🎨 Web assets
├── templates/               # 📄 HTML templates
├── requirements.txt         # 📦 Dependencies
├── test_modular.py         # 🧪 Test suite
└── app_legacy.py           # 📜 Legacy version (reference only)
```

## 🔧 Setup Requirements

### Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

### Install System Tools
```bash
# Ubuntu/Debian
sudo apt install nmap

# Install these separately:
# - subfinder (Go tool)
# - gobuster (Go tool)  
# - nuclei (Go tool)
```

## 📊 Output Formats

All scans generate multiple report formats:

- **JSON Reports**: `scan_results/scan_target.json` (comprehensive)
- **Simple JSON**: `scan_results/scan_target_simple.json` (summary)
- **CSV Reports**: Available via web interface
- **PDF Reports**: Available via web interface
- **TXT Reports**: Available via web interface

## 🎯 Example Usage

### Main Entry Point (Simplest)
1. `python3 main.py`
2. Web interface automatically opens
3. Enter target: `scanme.nmap.org`
4. Click "Start Scan"
5. Watch real-time progress
6. Download reports when complete

### Web Interface Demo
1. `python3 app_modular.py`
2. Open browser to http://localhost:5000
3. Enter target: `scanme.nmap.org`
4. Click "Start Scan"
5. Watch real-time progress
6. Download reports when complete

### CLI Demo
```bash
# Quick scan
python3 main_scanner.py httpbin.org

# Results summary
📊 Scan Summary:
   🎯 Target: httpbin.org
   🔢 Security Score: 75% (Grade: B)
   🚨 Vulnerabilities: 5
   🔍 Subdomains: 7
   📧 Emails: 1
   💥 Nuclei Findings: 0
```

## 🔍 Sample Testing Targets

- **scanme.nmap.org** - Official Nmap test target
- **testphp.vulnweb.com** - Vulnerable web application
- **httpbin.org** - HTTP testing service
- **example.com** - Simple test target

## 🧪 Testing & Validation

```bash
# Run all tests
python3 test_modular.py
```

## 🆚 Comparison: Old vs New

| Feature | Legacy (`app_legacy.py`) | Modular (`app_modular.py`) |
|---------|-------------------|----------------------------|
| **Architecture** | Monolithic | Modular |
| **Debugging** | Difficult | Easy |
| **Testing** | Hard to test | Module-level testing |
| **Maintenance** | Complex | Simple |
| **Scalability** | Limited | Highly scalable |
| **Code Reuse** | None | High |

## 💡 Pro Tips

1. **Start with Web Interface**: Easiest for beginners
2. **Use CLI for Automation**: Better for scripting
3. **Test Individual Modules**: Great for debugging
4. **Check scan_results/**: All outputs saved here
5. **Monitor Progress**: Web interface shows real-time status

## 🎉 Success!

Vuln-Scan is now complete and ready to use. The refactoring has achieved:

✅ **Separation of Concerns**: Each tool is its own module  
✅ **Improved Debugging**: Issues can be isolated to specific modules  
✅ **Better Maintainability**: Code is organized and clean  
✅ **Enhanced Testing**: Each module can be tested independently  
✅ **Increased Reusability**: Modules can be used in other projects  
✅ **Web + CLI Interfaces**: Choose your preferred method  

**Choose your preferred method and start scanning! 🔍**
