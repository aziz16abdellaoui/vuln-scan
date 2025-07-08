# Vulnerability Scanner Web Application

A comprehensive, modular vulnerability scanner with web interface and CLI support. Features 8 specialized scanning tools integrated into a unified platform.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)

## 🚀 Features

- **Modular Architecture**: 8 independent scanning modules that can run separately or together
- **Dual Interface**: Web dashboard and command-line interface
- **Comprehensive Scanning**: Network, subdomain, directory, email, breach, vulnerability, and HTTP analysis
- **Nuclei Integration**: CVE detection and exploit identification
- **Real-time Monitoring**: Live scan progress and results display
- **Smart Scoring**: AI-powered vulnerability assessment (0-100%)
- **Multiple Output Formats**: JSON, CSV, PDF, HTML reports
- **Performance Optimized**: Concurrent scanning with sub-90 second completion

## 🛡️ Scanning Modules

1. **Nmap Scanner** - Network port and service discovery
2. **Subfinder Scanner** - Subdomain enumeration
3. **Gobuster Scanner** - Directory and file discovery
4. **Email Crawler** - Email address harvesting
5. **Pwned Checker** - Data breach verification
6. **Nuclei Scanner** - CVE and vulnerability detection
7. **HTTP Analyzer** - Web application analysis
8. **Vulnerability Scorer** - Risk assessment and scoring

## 📁 Project Structure

```
vuln_scanner_web/
├── main.py                 # Main entry point (starts web UI)
├── main_scanner.py         # CLI orchestrator
├── app_modular.py          # Modular Flask web application
├── app_legacy.py           # Legacy monolithic app (reference)
├── tools/                  # Scanning modules
│   ├── nmap_scanner.py
│   ├── subfinder_scanner.py
│   ├── gobuster_scanner.py
│   ├── email_crawler.py
│   ├── pwned_checker.py
│   ├── nuclei_scanner.py
│   ├── http_analyzer.py
│   └── vulnerability_scorer.py
├── static/                 # Web assets
├── templates/              # HTML templates
├── scan_results/           # Output reports
├── test_modular.py         # Test suite
├── requirements.txt        # Python dependencies
└── HOW_TO_RUN.md          # Detailed usage guide
```

## 🚀 Quick Start

### Prerequisites
```bash
# Install system dependencies
sudo apt update
sudo apt install nmap python3 python3-pip firefox-esr

# Install Go (for subfinder and gobuster)
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install scanning tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest
```

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/vuln_scanner_web.git
cd vuln_scanner_web

# Install Python dependencies
pip3 install -r requirements.txt

# Install Nuclei (optional but recommended)
chmod +x install_nuclei.sh
./install_nuclei.sh
```

### Usage

#### Web Interface (Recommended)
```bash
python3 main.py
# Open http://localhost:5000 in your browser
```

#### Command Line Interface
```bash
# Run all scans
python3 main_scanner.py example.com

# Run specific modules
python3 main_scanner.py example.com --tools nmap,subfinder,nuclei

# Custom output directory
python3 main_scanner.py example.com --output custom_results/
```

#### Individual Modules
```bash
# Run single module
python3 tools/nmap_scanner.py example.com

# Test all modules
python3 test_modular.py
```

## 🧪 Test Targets

Safe targets for testing:
- `testphp.vulnweb.com` - Web application vulnerabilities
- `demo.testfire.net` - Banking demo with security issues
- `scanme.nmap.org` - Nmap test server
- `httpbin.org` - HTTP testing service

## 📊 Sample Output

```json
{
  "target": "example.com",
  "scan_date": "2024-01-01T12:00:00",
  "tools_used": ["nmap", "subfinder", "nuclei"],
  "vulnerability_score": 85,
  "risk_level": "Medium",
  "findings": {
    "open_ports": ["80", "443", "22"],
    "subdomains": ["www.example.com", "api.example.com"],
    "vulnerabilities": [...]
  }
}
```

## 🔧 Configuration

Edit tool configurations in `tools/` directory:
- Modify timeouts and scan parameters
- Customize output formats
- Add new vulnerability checks

## 🧪 Testing

```bash
# Run the complete test suite
python3 test_modular.py

# Test individual components
python3 -m pytest test_modular.py -v
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-scanner`)
3. Commit your changes (`git commit -am 'Add new scanner'`)
4. Push to the branch (`git push origin feature/new-scanner`)
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and obtaining proper authorization before scanning any systems they do not own.

## 📚 Documentation

For detailed setup and usage instructions, see [HOW_TO_RUN.md](HOW_TO_RUN.md).

## 🔗 Dependencies

- Python 3.7+
- Flask, requests, selenium, beautifulsoup4
- Nmap, Subfinder, Gobuster, Nuclei
- Firefox/Geckodriver for breach checking
