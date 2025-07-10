#!/usr/bin/env python3
"""
Main Vulnerability Scanner - Command Line Interface
This file controls all scanning tools and creates detailed reports
Run with: python3 main_scanner.py <target>
Author: Mohamed Aziz Abdellaoui
"""

# Import basic libraries we need
import os
import sys
import json
import threading
from datetime import datetime

# Add tools directory to Python path so we can import our modules
sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))

# Import all our scanning modules
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
        """Set up all the scanning tools we will use"""
        # Dictionary with all our scanning tools
        self.scanners = {
            'nmap': NmapScanner(),           # Scans network ports
            'subfinder': SubfinderScanner(), # Finds subdomains  
            'gobuster': GobusterScanner(),   # Finds hidden directories
            'email_crawler': EmailCrawler(), # Finds email addresses
            'pwned_checker': PwnedChecker(), # Checks for data breaches
            'nuclei': NucleiScanner(),       # Finds security vulnerabilities
            'http_analyzer': HTTPAnalyzer(), # Analyzes web security headers
            'scorer': VulnerabilityScorer()  # Gives security score
        }
        
        # Security recommendation templates
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
        """توليد التوصيات بناءً على الثغرات المكتشفة - Generate recommendations based on vulnerabilities found"""
        recommendations = set()  # مجموعة لتجنب التكرار - Set to avoid duplicates
        
        # تكرار عبر كل ثغرة مكتشفة - Loop through each discovered vulnerability
        for vuln in vulnerabilities:
            # البحث عن أنماط مطابقة في قائمة التوصيات - Search for matching patterns in recommendations list
            for pattern in self.recommendation_patterns:
                if any(keyword in vuln.lower() for keyword in pattern["keywords"]):
                    recommendations.add(pattern["recommendation"])
        return list(recommendations)  # إرجاع القائمة - Return the list
    
    def analyze_manual_vulnerabilities(self, gobuster_results):
        """تحليل نتائج gobuster للبحث عن مسارات حساسة - Analyze gobuster results for sensitive paths"""
        manual_vulns = []  # قائمة الثغرات اليدوية - Manual vulnerabilities list
        
        # مسارات حساسة يجب البحث عنها - Sensitive paths to look for
        sensitive_paths = [".svn", ".htaccess", ".htpasswd", "server-status"]
        
        # البحث في المجلدات المكتشفة - Search through discovered directories
        for line in gobuster_results.get("directories", []):
            if any(path in line for path in sensitive_paths):
                manual_vulns.append(f"Sensitive path found: {line}")
        
        return manual_vulns  # إرجاع الثغرات المكتشفة - Return discovered vulnerabilities
    
    def _get_profile_config(self, profile):
        """Get configuration for the selected scan profile"""
        profiles = {
            'quick': {
                'description': 'Fast scan for basic vulnerabilities (30-60s)',
                'enable_subfinder': True,
                'enable_gobuster': False,  # Skip for speed
                'enable_email_crawler': False,  # Skip for speed
                'enable_pwned_checker': False,  # Skip for speed
                'nuclei_timeout': 30,
                'nuclei_phases': ['Essential Security Checks']
            },
            'standard': {
                'description': 'Balanced scan with good coverage (90-120s)',
                'enable_subfinder': True,
                'enable_gobuster': True,
                'enable_email_crawler': True,
                'enable_pwned_checker': True,
                'nuclei_timeout': 45,
                'nuclei_phases': ['Essential Security Checks', 'Technology Detection', 'Critical CVEs']
            },
            'comprehensive': {
                'description': 'Deep scan with maximum coverage (3-5min)',
                'enable_subfinder': True,
                'enable_gobuster': True,
                'enable_email_crawler': True,
                'enable_pwned_checker': True,
                'nuclei_timeout': 90,
                'nuclei_phases': ['Essential Security Checks', 'Technology Detection', 'Critical CVEs', 'Service-Specific']
            }
        }
        
        return profiles.get(profile, profiles['standard'])  # Default to standard if unknown profile
    
    def scan_target(self, target, wordlist_path=None, status_callback=None, profile="standard"):
        """
        تشغيل فحص شامل للهدف - Run comprehensive vulnerability scan on target
        إرجاع نتائج الفحص الكاملة - Returns complete scan results
        """
        def update_status(message):
            """تحديث حالة الفحص - Update scan status"""
            if status_callback:
                status_callback(message)  # استدعاء دالة التحديث إذا متوفرة - Call update function if available
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
        # بداية الفحص - Scan start
        scan_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        update_status(f"Starting {profile} scan for {target}")
        
        # Get profile configuration
        profile_config = self._get_profile_config(profile)
        update_status(f"Using {profile} profile: {profile_config.get('description', 'Custom configuration')}")
        
        # إعداد هيكل النتائج - Initialize results structure
        results = {
            "target": target,
            "start_time": scan_start,
            "profile": profile,
            "status": [],
            "module_results": {},
            "vulnerabilities": [],
            "recommendations": [],
            "score": 0,
            "grade": "F"
        }
        
        # 1. Nmap scan (always runs - needed for service detection)
        update_status("Running Nmap port scan...")
        nmap_results = self.scanners['nmap'].scan(target)
        results["module_results"]["nmap"] = nmap_results
        update_status(f"Nmap completed: {nmap_results['ports_found']} ports found")
        
        # 2. Subfinder scan (profile-dependent)
        if profile_config.get('enable_subfinder', True):
            update_status("Running subdomain enumeration...")
            subfinder_results = self.scanners['subfinder'].scan(target)
            results["module_results"]["subfinder"] = subfinder_results
            update_status(f"Subfinder completed: {subfinder_results['count']} subdomains found")
        else:
            update_status("Skipping subdomain enumeration (profile setting)")
            results["module_results"]["subfinder"] = {"count": 0, "status": "skipped", "subdomains": []}
        
        # 3. Gobuster scan (directory discovery) - profile-dependent
        if profile_config.get('enable_gobuster', True):
            update_status("Running directory scan...")
            gobuster_results = self.scanners['gobuster'].scan(target, wordlist_path)
            results["module_results"]["gobuster"] = gobuster_results
            if gobuster_results["status"] == "skipped":
                update_status("Directory scan skipped - Gobuster not available or wordlist issues")
            else:
                update_status(f"Directory scan completed: {gobuster_results['count']} directories found")
        else:
            update_status("Skipping directory scan (profile setting)")
            results["module_results"]["gobuster"] = {"count": 0, "status": "skipped", "directories": []}
        
        # 4. Email crawling (profile-dependent)
        if profile_config.get('enable_email_crawler', True):
            update_status("Crawling for email addresses...")
            email_results = self.scanners['email_crawler'].crawl(target)
            results["module_results"]["email_crawler"] = email_results
            update_status(f"Email crawl completed: {email_results['count']} emails found")
        else:
            update_status("Skipping email crawling (profile setting)")
            email_results = {"count": 0, "emails_found": [], "status": "skipped"}
            results["module_results"]["email_crawler"] = email_results
        
        # 5. Pwned email check (profile-dependent)
        if profile_config.get('enable_pwned_checker', True) and email_results.get('emails_found'):
            update_status("Checking emails for data breaches...")
            pwned_results = self.scanners['pwned_checker'].check_emails(email_results["emails_found"])
            results["module_results"]["pwned_checker"] = pwned_results
            update_status(f"Breach check completed: {pwned_results['count']} pwned emails found")
        else:
            update_status("Skipping breach check (profile setting or no emails found)")
            results["module_results"]["pwned_checker"] = {"count": 0, "pwned_emails": [], "status": "skipped"}
        
        # 6. HTTP security analysis (always runs)
        update_status("Analyzing HTTP security...")
        http_results = self.scanners['http_analyzer'].analyze(target)
        results["module_results"]["http_analyzer"] = http_results
        update_status(f"HTTP analysis completed: {http_results['count']} issues found")

        # 7. Nuclei scan with enhanced status reporting and profile-based timeout
        nuclei_timeout = profile_config.get('nuclei_timeout', 45)
        update_status("🎯 Starting advanced Nuclei vulnerability scan...")
        update_status(f"⚙️ Using {profile} profile with {nuclei_timeout}s timeout...")
        
        # Temporarily update nuclei scanner timeout for this scan
        original_timeout = self.scanners['nuclei'].timeout
        self.scanners['nuclei'].timeout = nuclei_timeout
        
        # Run Nuclei scan with Nmap results for context
        nuclei_results = self.scanners['nuclei'].scan(target, nmap_results["raw_output"])
        
        # Restore original timeout
        self.scanners['nuclei'].timeout = original_timeout
        results["module_results"]["nuclei"] = nuclei_results
        
        # Provide detailed status based on Nuclei results
        if nuclei_results['status'] == "completed":
            update_status("✅ Nuclei scan completed successfully!")
            update_status(f"📊 Vulnerabilities found: {nuclei_results['count']}")
            update_status(f"🚨 CVEs detected: {nuclei_results['cve_count']}")
            update_status(f"💥 Exploitable issues: {nuclei_results['exploit_count']}")
            if nuclei_results.get('phases_completed') and nuclei_results.get('total_phases'):
                update_status(f"⚡ Scan phases: {nuclei_results['phases_completed']}/{nuclei_results['total_phases']} completed")
        elif nuclei_results['status'] == "partial":
            update_status("⚠️ Nuclei scan partially completed")
            update_status(f"📊 Partial results: {nuclei_results['count']} vulnerabilities found")
            if nuclei_results.get('phases_completed') and nuclei_results.get('total_phases'):
                update_status(f"⚡ Phases completed: {nuclei_results['phases_completed']}/{nuclei_results['total_phases']}")
        elif nuclei_results['status'] == "timeout":
            update_status("⏱️ Nuclei scan timed out - partial results available")
            update_status(f"📊 Found {nuclei_results['count']} vulnerabilities before timeout")
        elif nuclei_results['status'] == "not_found":
            update_status("❌ Nuclei not found - vulnerability scan skipped")
            update_status("💡 Install Nuclei for advanced vulnerability detection")
        elif nuclei_results['status'] == "error":
            update_status("⚠️ Nuclei scan encountered errors")
            update_status(f"📊 Partial results: {nuclei_results['count']} vulnerabilities found")
        else:
            update_status(f"Nuclei scan status: {nuclei_results['status']}")
            
        # Show key findings if any were discovered
        if nuclei_results['count'] > 0:
            high_severity_count = sum(1 for f in nuclei_results['findings'] 
                                    if f.get('severity') in ['critical', 'high'])
            if high_severity_count > 0:
                update_status(f"🔴 High/Critical findings: {high_severity_count}")
            
            # Show top 3 most critical findings
            sorted_findings = sorted(nuclei_results['findings'], 
                                   key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x.get('severity', 'info'), 4))
            top_findings = sorted_findings[:3]
            if top_findings:
                update_status("🔍 Top vulnerabilities:")
                for i, finding in enumerate(top_findings, 1):
                    severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}.get(finding.get('severity', 'info'), '⚪')
                    update_status(f"   {i}. {severity_emoji} {finding.get('name', 'Unknown vulnerability')}")
        else:
            update_status("✅ No critical vulnerabilities detected by Nuclei")
        
        # Compile all vulnerabilities
        all_vulnerabilities = []
        
        # Add HTTP vulnerabilities
        all_vulnerabilities.extend(http_results["vulnerabilities"])
        
        # Add Nuclei vulnerabilities
        for finding in nuclei_results["findings"]:
            vuln_entry = f"Nuclei: {finding['name']} (Severity: {finding['severity']})"
            all_vulnerabilities.append(vuln_entry)
        
        # Add pwned email vulnerabilities
        if 'pwned_checker' in results["module_results"] and results["module_results"]["pwned_checker"].get("pwned_emails"):
            for email in results["module_results"]["pwned_checker"]["pwned_emails"]:
                all_vulnerabilities.append(f"Email {email} found in data breach (pwned)")
        
        # Add manual vulnerabilities from gobuster (if gobuster was run)
        if 'gobuster' in results["module_results"] and results["module_results"]["gobuster"]["status"] != "skipped":
            manual_vulns = self.analyze_manual_vulnerabilities(results["module_results"]["gobuster"])
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
