#!/usr/bin/env python3
"""
New Flask Web Application using Modular Scanner Architecture
This file integrates the modular scanner with a web interface
"""

import os
import sys
import threading
from flask import Flask, render_template, request, jsonify, send_file

# Add tools directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))

# Import the main scanner
from main_scanner import VulnerabilityScanner

app = Flask(__name__)
scan_data = {}

class WebVulnerabilityScanner:
    def __init__(self):
        self.scanner = VulnerabilityScanner()
    
    def status_callback(self, target, message):
        """Callback function to update scan status in real-time"""
        if target not in scan_data:
            scan_data[target] = {"status": [], "completed": False}
        scan_data[target]["status"].append(message)
    
    def scan_target_web(self, target, wordlist_path=None):
        """Run scan with web interface integration"""
        try:
            # Initialize scan data
            scan_data[target] = {
                "status": [f"Starting comprehensive scan for {target}"],
                "completed": False,
                "results": {},
                "error": None
            }
            
            # Create status callback for this target
            def status_update(message):
                self.status_callback(target, message)
            
            # Run the modular scan
            results = self.scanner.scan_target(
                target, 
                wordlist_path, 
                status_callback=status_update
            )
            
            # Update scan data with results
            scan_data[target].update({
                "completed": True,
                "results": results,
                "vulnerabilities": results["vulnerabilities"],
                "score": results["score"],
                "grade": results["grade"],
                "grouped": results["grouped_vulnerabilities"],
                "recommendations": results["recommendations"],
                "module_results": results["module_results"]
            })
            
            # Save results
            self.scanner.save_results(results)
            
            scan_data[target]["status"].append("✅ Scan completed successfully!")
            
        except Exception as e:
            scan_data[target]["error"] = str(e)
            scan_data[target]["status"].append(f"❌ Scan failed: {e}")
            scan_data[target]["completed"] = True

# Initialize the web scanner
web_scanner = WebVulnerabilityScanner()

@app.route("/")
def index():
    """Main dashboard page"""
    return render_template("dashboard.html")

@app.route("/start_scan", methods=["POST"])
def start_scan():
    """Start a new vulnerability scan"""
    target = request.form.get("target", "").strip()
    file = request.files.get("wordlist")
    wordlist_path = None

    if file and file.filename:
        os.makedirs("uploads", exist_ok=True)
        wordlist_path = os.path.join("uploads", file.filename)
        file.save(wordlist_path)

    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    # Clear any existing scan data for this target
    if target in scan_data:
        scan_data.pop(target)

    # Start scan in background thread
    threading.Thread(
        target=web_scanner.scan_target_web, 
        args=(target, wordlist_path), 
        daemon=True
    ).start()
    
    return jsonify({"message": f"Scan started for {target}"}), 202

@app.route("/scan_status/<target>")
def scan_status(target):
    """Get current scan status and results"""
    if target not in scan_data:
        return jsonify({"error": "No scan data found"}), 404
    
    data = scan_data[target]
    
    # Format response for web interface compatibility
    response = {
        "status": data.get("status", []),
        "completed": data.get("completed", False),
        "error": data.get("error"),
        "score": data.get("score", 0),
        "grade": data.get("grade", "F"),
        "vulnerabilities": data.get("vulnerabilities", []),
        "grouped": data.get("grouped", {"high": [], "medium": [], "low": [], "info": []}),
        "recommendations": data.get("recommendations", []),
        "results": data.get("results", {}),
        "module_results": data.get("module_results", {})
    }
    
    return jsonify(response)

@app.route("/download_report/<target>")
def download_report(target):
    """Download scan report as text file"""
    if target not in scan_data or not scan_data[target].get("completed"):
        return "No completed scan data found", 404
    
    data = scan_data[target]
    report_path = f"report_{target.replace('.', '_')}.txt"
    
    try:
        with open(report_path, "w") as f:
            f.write(f"Vulnerability Scan Report for: {target}\n")
            f.write("=" * 50 + "\n\n")
            
            # Basic info
            f.write(f"Security Score: {data.get('score', 0)}% (Grade: {data.get('grade', 'F')})\n")
            f.write(f"Total Vulnerabilities: {len(data.get('vulnerabilities', []))}\n\n")
            
            # Status log
            f.write("SCAN STATUS LOG:\n")
            f.write("-" * 20 + "\n")
            for status in data.get("status", []):
                f.write(f"• {status}\n")
            f.write("\n")
            
            # Module results summary
            module_results = data.get("module_results", {})
            f.write("MODULE RESULTS SUMMARY:\n")
            f.write("-" * 25 + "\n")
            
            if "nmap" in module_results:
                f.write(f"Nmap: {module_results['nmap'].get('ports_found', 0)} ports found\n")
            if "subfinder" in module_results:
                f.write(f"Subfinder: {module_results['subfinder'].get('count', 0)} subdomains found\n")
            if "email_crawler" in module_results:
                f.write(f"Email Crawler: {module_results['email_crawler'].get('count', 0)} emails found\n")
            if "pwned_checker" in module_results:
                f.write(f"Pwned Checker: {module_results['pwned_checker'].get('count', 0)} pwned emails found\n")
            if "nuclei" in module_results:
                nuclei = module_results['nuclei']
                f.write(f"Nuclei: {nuclei.get('count', 0)} findings ({nuclei.get('cve_count', 0)} CVEs)\n")
            f.write("\n")
            
            # Vulnerabilities by severity
            grouped = data.get("grouped", {})
            for level in ["high", "medium", "low", "info"]:
                vulns = grouped.get(level, [])
                if vulns:
                    f.write(f"{level.upper()} SEVERITY VULNERABILITIES:\n")
                    f.write("-" * 30 + "\n")
                    for vuln in vulns:
                        f.write(f"• {vuln}\n")
                    f.write("\n")
            
            # Recommendations
            recommendations = data.get("recommendations", [])
            if recommendations:
                f.write("SECURITY RECOMMENDATIONS:\n")
                f.write("-" * 25 + "\n")
                for rec in recommendations:
                    f.write(f"• {rec}\n")
                f.write("\n")
            
        return send_file(report_path, as_attachment=True)
        
    except Exception as e:
        return f"Error generating report: {e}", 500

@app.route("/test_modules")
def test_modules():
    """Test endpoint to verify all modules are working"""
    test_results = {}
    
    try:
        # Test each scanner module individually
        from nmap_scanner import NmapScanner
        from nuclei_scanner import NucleiScanner
        from http_analyzer import HTTPAnalyzer
        
        test_results["nmap"] = "✅ Available"
        test_results["nuclei"] = "✅ Available" 
        test_results["http_analyzer"] = "✅ Available"
        test_results["overall"] = "✅ All modules loaded successfully"
        
    except ImportError as e:
        test_results["error"] = f"❌ Module import failed: {e}"
        test_results["overall"] = "❌ Module loading failed"
    
    return jsonify(test_results)

if __name__ == "__main__":
    print("🚀 Starting Modular Vulnerability Scanner Web Interface")
    print("📁 Using tools from: tools/")
    print("🌐 Access at: http://localhost:5000")
    app.run(debug=True)
