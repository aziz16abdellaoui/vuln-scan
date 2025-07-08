#!/usr/bin/env python3
"""
Main Vulnerability Scanner
Orchestrates all scanning tools and generates comprehensive reports
"""

import os
import sys
import json
import threading
from datetime import datetime

# Add tools directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))

# Import all scanner modules
from nmap_scanner import NmapScanner
from subfinder_scanner import SubfinderScanner
from gobuster_scanner import GobusterScanner
from email_crawler import EmailCrawler
from pwned_checker import PwnedChecker
from nuclei_scanner import NucleiScanner
from http_analyzer import HTTPAnalyzer
from vulnerability_scorer import VulnerabilityScorer

class VulnerabilityScanner:
    def __init__(self):
        self.scanners = {
            'nmap': NmapScanner(),
            'subfinder': SubfinderScanner(),
            'gobuster': GobusterScanner(),
            'email_crawler': EmailCrawler(),
            'pwned_checker': PwnedChecker(),
            'nuclei': NucleiScanner(),
            'http_analyzer': HTTPAnalyzer(),
            'scorer': VulnerabilityScorer()
        }
        
        self.recommendation_patterns = [
            {"keywords": ["x-powered-by"], "recommendation": "Remove or obfuscate the 'X-Powered-By' header."},
            {"keywords": ["x-frame-options"], "recommendation": "Add 'X-Frame-Options' header."},
            {"keywords": ["x-content-type-options"], "recommendation": "Set 'X-Content-Type-Options' to 'nosniff'."},
            {"keywords": ["strict-transport-security"], "recommendation": "Implement HSTS to enforce HTTPS."},
            {"keywords": ["content-security-policy"], "recommendation": "Set a strong CSP to reduce XSS."},
            {"keywords": ["directory listing"], "recommendation": "Disable directory listing."},
            {"keywords": ["default files"], "recommendation": "Remove default or backup files."},
            {"keywords": ["insecure cookies"], "recommendation": "Use 'Secure' and 'HttpOnly' cookie flags."},
            {"keywords": ["xss", "cross-site-scripting"], "recommendation": "Sanitize user input to prevent XSS."},
            {"keywords": ["outdated software", "apache 2.4.7"], "recommendation": "Update all outdated software."},
            {"keywords": ["server header"], "recommendation": "Remove or customize 'Server' header."},
            {"keywords": [".htaccess", ".htpasswd", ".svn", "server-status"], "recommendation": "Restrict access to sensitive paths."},
            {"keywords": ["nuclei: cve-"], "recommendation": "Apply security patches for identified CVEs immediately."},
            {"keywords": ["nuclei: critical"], "recommendation": "Address critical vulnerabilities with highest priority."},
            {"keywords": ["nuclei: high"], "recommendation": "Implement fixes for high-severity vulnerabilities."},
            {"keywords": ["nuclei: exposed-panel"], "recommendation": "Secure or remove exposed administrative panels."},
            {"keywords": ["nuclei: sqli"], "recommendation": "Implement proper input validation and parameterized queries."},
            {"keywords": ["nuclei: rce"], "recommendation": "Patch remote code execution vulnerabilities immediately."},
            {"keywords": ["nuclei: lfi"], "recommendation": "Validate and sanitize file path inputs."}
        ]
    
    def get_recommendations(self, vulnerabilities):
        """Generate recommendations based on vulnerabilities found"""
        recommendations = set()
        for vuln in vulnerabilities:
            for pattern in self.recommendation_patterns:
                if any(keyword in vuln.lower() for keyword in pattern["keywords"]):
                    recommendations.add(pattern["recommendation"])
        return list(recommendations)
    
    def analyze_manual_vulnerabilities(self, gobuster_results):
        """Analyze gobuster results for sensitive paths"""
        manual_vulns = []
        sensitive_paths = [".svn", ".htaccess", ".htpasswd", "server-status"]
        
        for line in gobuster_results.get("directories", []):
            if any(path in line for path in sensitive_paths):
                manual_vulns.append(f"Sensitive path found: {line}")
        
        return manual_vulns
    
    def scan_target(self, target, wordlist_path=None, status_callback=None):
        """
        Run comprehensive vulnerability scan on target
        Returns complete scan results
        """
        def update_status(message):
            if status_callback:
                status_callback(message)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
        scan_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        update_status(f"Starting comprehensive scan for {target}")
        
        # Initialize results structure
        results = {
            "target": target,
            "start_time": scan_start,
            "status": [],
            "module_results": {},
            "vulnerabilities": [],
            "recommendations": [],
            "score": 0,
            "grade": "F"
        }
        
        # 1. Nmap scan
        update_status("Running Nmap port scan...")
        nmap_results = self.scanners['nmap'].scan(target)
        results["module_results"]["nmap"] = nmap_results
        update_status(f"Nmap completed: {nmap_results['ports_found']} ports found")
        
        # 2. Subfinder scan
        update_status("Running subdomain enumeration...")
        subfinder_results = self.scanners['subfinder'].scan(target)
        results["module_results"]["subfinder"] = subfinder_results
        update_status(f"Subfinder completed: {subfinder_results['count']} subdomains found")
        
        # 3. Gobuster scan (if wordlist provided)
        update_status("Running directory scan...")
        gobuster_results = self.scanners['gobuster'].scan(target, wordlist_path)
        results["module_results"]["gobuster"] = gobuster_results
        if gobuster_results["status"] == "skipped":
            update_status("Directory scan skipped - no wordlist provided")
        else:
            update_status(f"Gobuster completed: {gobuster_results['count']} directories found")
        
        # 4. Email crawling
        update_status("Crawling for email addresses...")
        email_results = self.scanners['email_crawler'].crawl(target)
        results["module_results"]["email_crawler"] = email_results
        update_status(f"Email crawl completed: {email_results['count']} emails found")
        
        # 5. Pwned email check
        update_status("Checking emails for data breaches...")
        pwned_results = self.scanners['pwned_checker'].check_emails(email_results["emails_found"])
        results["module_results"]["pwned_checker"] = pwned_results
        update_status(f"Breach check completed: {pwned_results['count']} pwned emails found")
        
        # 6. HTTP security analysis
        update_status("Analyzing HTTP security...")
        http_results = self.scanners['http_analyzer'].analyze(target)
        results["module_results"]["http_analyzer"] = http_results
        update_status(f"HTTP analysis completed: {http_results['count']} issues found")
        
        # 7. Nuclei scan
        update_status("Running Nuclei CVE/exploit detection...")
        nuclei_results = self.scanners['nuclei'].scan(target, nmap_results["raw_output"])
        results["module_results"]["nuclei"] = nuclei_results
        update_status(f"Nuclei completed: {nuclei_results['count']} findings ({nuclei_results['cve_count']} CVEs)")
        
        # Compile all vulnerabilities
        all_vulnerabilities = []
        
        # Add HTTP vulnerabilities
        all_vulnerabilities.extend(http_results["vulnerabilities"])
        
        # Add Nuclei vulnerabilities
        for finding in nuclei_results["findings"]:
            vuln_entry = f"Nuclei: {finding['name']} (Severity: {finding['severity']})"
            all_vulnerabilities.append(vuln_entry)
        
        # Add pwned email vulnerabilities
        for email in pwned_results["pwned_emails"]:
            all_vulnerabilities.append(f"Email {email} found in data breach (pwned)")
        
        # Add manual vulnerabilities from gobuster
        manual_vulns = self.analyze_manual_vulnerabilities(gobuster_results)
        all_vulnerabilities.extend(manual_vulns)
        
        results["vulnerabilities"] = all_vulnerabilities
        
        # Generate recommendations
        update_status("Generating security recommendations...")
        results["recommendations"] = self.get_recommendations(all_vulnerabilities)
        
        # Calculate security score
        update_status("Calculating security score...")
        score_data = self.scanners['scorer'].calculate_score(
            all_vulnerabilities,
            nuclei_results["findings"],
            results["module_results"]
        )
        results["score"] = score_data["score"]
        results["grade"] = score_data["grade"]
        results["score_breakdown"] = score_data["breakdown"]
        
        # Group vulnerabilities by severity
        results["grouped_vulnerabilities"] = self.scanners['scorer'].group_vulnerabilities(all_vulnerabilities)
        
        # Final status
        scan_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        results["end_time"] = scan_end
        
        update_status(f"Scan completed! Security Score: {results['score']}% (Grade: {results['grade']})")
        update_status(f"Found {len(all_vulnerabilities)} total vulnerabilities")
        
        return results
    
    def save_results(self, results, output_dir="scan_results"):
        """Save scan results to JSON files"""
        os.makedirs(output_dir, exist_ok=True)
        target = results["target"].replace(".", "_")
        
        # Save comprehensive results
        comprehensive_file = os.path.join(output_dir, f"scan_{target}.json")
        with open(comprehensive_file, "w") as f:
            json.dump(results, f, indent=4)
        
        # Save simplified results
        simple_data = {
            "target": results["target"],
            "scan_time": results["start_time"],
            "security_score_percentage": results["score"],
            "security_grade": results["grade"],
            "vulnerabilities_count": len(results["vulnerabilities"]),
            "subdomains_found": results["module_results"]["subfinder"]["count"],
            "emails_found": results["module_results"]["email_crawler"]["count"],
            "pwned_emails": results["module_results"]["pwned_checker"]["count"],
            "nuclei_findings": results["module_results"]["nuclei"]["count"],
            "cve_count": results["module_results"]["nuclei"]["cve_count"],
            "exploit_count": results["module_results"]["nuclei"]["exploit_count"],
            "score_explanation": f"Starting from 100%, deducted {100 - results['score']}% for vulnerabilities found"
        }
        
        simple_file = os.path.join(output_dir, f"scan_{target}_simple.json")
        with open(simple_file, "w") as f:
            json.dump(simple_data, f, indent=4)
        
        print(f"✅ Results saved:")
        print(f"   📄 Full report: {comprehensive_file}")
        print(f"   📄 Simple report: {simple_file}")
        
        return comprehensive_file, simple_file

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive Vulnerability Scanner")
    parser.add_argument("target", help="Target domain to scan")
    parser.add_argument("-w", "--wordlist", help="Wordlist file for directory scanning")
    parser.add_argument("-o", "--output", default="scan_results", help="Output directory")
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = VulnerabilityScanner()
    
    # Run scan
    print(f"🔍 Starting vulnerability scan for {args.target}")
    results = scanner.scan_target(args.target, args.wordlist)
    
    # Save results
    scanner.save_results(results, args.output)
    
    # Print summary
    print(f"\n📊 Scan Summary:")
    print(f"   🎯 Target: {results['target']}")
    print(f"   🔢 Security Score: {results['score']}% (Grade: {results['grade']})")
    print(f"   🚨 Vulnerabilities: {len(results['vulnerabilities'])}")
    print(f"   🔍 Subdomains: {results['module_results']['subfinder']['count']}")
    print(f"   📧 Emails: {results['module_results']['email_crawler']['count']}")
    print(f"   💥 Nuclei Findings: {results['module_results']['nuclei']['count']}")

if __name__ == "__main__":
    main()
