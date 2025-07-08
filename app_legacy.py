import re
import requests
from urllib.parse import urljoin, urlparse
import time
import subprocess
import threading
from flask import Flask, render_template, request, jsonify, send_file
import os
import json
from datetime import datetime

# Selenium imports for pwn check
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

app = Flask(__name__)
scan_data = {}

# Vulnerability explanations and mappings
vuln_explanations = {
    "x-powered-by header": "The server exposes the 'X-Powered-By' HTTP header revealing technologies.",
    "x-frame-options header missing": "Makes site vulnerable to clickjacking.",
    "x-content-type-options header missing": "Allows MIME-type sniffing.",
    "strict-transport-security header missing": "Allows protocol downgrade and cookie hijacking.",
    "content-security-policy header missing": "Increases risk of XSS attacks.",
    "server header discloses software": "Reveals server info aiding targeted attacks.",
    "directory listing enabled": "Leads to hidden file exposure.",
    "default files found": "Default/backup files may expose vulnerabilities.",
    "insecure cookies": "Cookies lacking Secure/HttpOnly flags are vulnerable.",
    "cross-site-scripting vulnerability": "XSS allows malicious script injection.",
    "outdated software": "Older services/plugins may have known exploits."
}

recommendation_patterns = [
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

severity_map = {
    "high": ["xss", "outdated", "sensitive path", "wordpress vulnerabilities", "pwned"],
    "medium": ["directory listing", "server header", "insecure cookies", "pwned"],
    "low": ["x-powered-by", "x-frame-options", "x-content-type-options", "strict-transport-security", "content-security-policy"]
}

SEVERITY_SCORES = {
    "high": 25,    # High severity vulnerabilities deduct 25 points
    "medium": 15,  # Medium severity vulnerabilities deduct 15 points
    "low": 5,      # Low severity vulnerabilities deduct 5 points
    "info": 0      # Informational findings don't affect score
}

def get_severity(vuln):
    v = vuln.lower()
    for level, keywords in severity_map.items():
        if any(k in v for k in keywords):
            return level
    return "info"

def analyze_manual_vulns(data, target):
    gobuster = data[target]["results"].get("gobuster", [])
    for line in gobuster:
        if any(s in line for s in [".svn", ".htaccess", ".htpasswd", "server-status"]):
            data[target]["vulnerabilities"].append(f"Sensitive path found: {line}")
    data[target]["vulnerabilities"] = list(set(data[target]["vulnerabilities"]))

def get_recommendations(vulnerabilities):
    recs = set()
    for vuln in vulnerabilities:
        for pattern in recommendation_patterns:
            if any(k in vuln.lower() for k in pattern["keywords"]):
                recs.add(pattern["recommendation"])
    return list(recs)

def run_cmd(cmd, label, next_step, target, capture_file=False):
    scan_data[target]["status"].append(f"Running {label}...")
    try:
        if capture_file:
            output_file = f"output_{target.replace('.', '_')}.json"
            cmd += ["-f", output_file]
            subprocess.check_call(cmd, stderr=subprocess.DEVNULL)
            with open(output_file, "r") as f:
                output = f.read()
            os.remove(output_file)
        else:
            output = subprocess.check_output(cmd, stderr=subprocess.PIPE, text=True)
        scan_data[target]["status"].append(f"{label} completed.")
        if next_step:
            scan_data[target]["status"].append(f"Next: {next_step}")
        return output.strip()
    except subprocess.CalledProcessError as e:
        scan_data[target]["status"].append(f"{label} failed: {e}")
        return ""

# --- Email crawler ---
def extract_emails_from_text(text):
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return set(re.findall(email_pattern, text))

def is_internal_link(base_url, link):
    base_domain = urlparse(base_url).netloc
    link_domain = urlparse(link).netloc
    return (link_domain == "" or link_domain == base_domain)

def crawl_emails(start_url, max_depth=1, delay=0.1, max_links_per_page=3):
    visited_urls = set()
    emails_found = set()
    urls_to_visit = [(start_url, 0)]

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; EmailCrawler/1.0; +https://github.com/)",
        "Connection": "keep-alive"
    }
    
    crawl_times = {"start": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    
    # Use a session to reuse connections
    with requests.Session() as session:
        session.headers.update(headers)
        session.timeout = 2  # Very short timeout
        
        while urls_to_visit:
            current_batch = []
            # Process only 2 URLs at once for speed
            while urls_to_visit and len(current_batch) < 2:
                current_batch.append(urls_to_visit.pop(0))

            for url, depth in current_batch:
                if url in visited_urls or depth > max_depth:
                    continue
                
                try:
                    response = session.get(url, timeout=2)
                    response.raise_for_status()
                    visited_urls.add(url)

                    # Extract emails on this page
                    new_emails = extract_emails_from_text(response.text)
                    emails_found.update(new_emails)

                    # Only crawl deeper if we haven't found many emails yet
                    if depth < max_depth and len(emails_found) < 5:
                        links = re.findall(r'href=["\'](.*?)["\']', response.text, re.IGNORECASE)
                        count = 0
                        for link in links:
                            if count >= max_links_per_page:
                                break
                            absolute_link = urljoin(url, link)
                            if is_internal_link(start_url, absolute_link):
                                urls_to_visit.append((absolute_link, depth + 1))
                                count += 1

                except Exception as e:
                    continue

            # Very small delay
            time.sleep(0.05)

    crawl_times["end"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return emails_found, crawl_times

# --- Selenium pwn check ---
def check_email_pwned(email, driver, wait, target):
    try:
        driver.get("https://haveibeenpwned.com/")
        search_box = wait.until(EC.presence_of_element_located((By.ID, "emailInput")))
        search_box.clear()
        search_box.send_keys(email)
        search_box.send_keys(Keys.RETURN)

        wait.until(
            EC.any_of(
                EC.presence_of_element_located((By.ID, "breaches")),
                EC.text_to_be_present_in_element((By.TAG_NAME, "body"), "Good news"),
                EC.text_to_be_present_in_element((By.TAG_NAME, "body"), "pwned")
            )
        )
        body_text = driver.find_element(By.TAG_NAME, "body").text.lower()

        if "pwned" in body_text:
            scan_data[target]["status"].append(f"[+] {email} has been pwned!")
            return True
        elif "good news" in body_text:
            scan_data[target]["status"].append(f"[-] {email} has NOT been pwned.")
            return False
        else:
            scan_data[target]["status"].append(f"[?] Results unclear for {email}.")
            return None
    except Exception as e:
        scan_data[target]["status"].append(f"Error checking {email}: {e}")
        return None

def check_email_pwned_batch(emails, driver, wait, target):
    pwned_emails = []
    
    # Limit to max 3 emails to avoid long waits
    limited_emails = list(emails)[:3]
    
    for email in limited_emails:
        try:
            driver.get("https://haveibeenpwned.com/")
            search_box = wait.until(EC.presence_of_element_located((By.ID, "emailInput")))
            search_box.clear()
            search_box.send_keys(email)
            search_box.send_keys(Keys.RETURN)

            # Much reduced wait time
            try:
                wait.until(
                    EC.any_of(
                        EC.presence_of_element_located((By.ID, "breaches")),
                        EC.text_to_be_present_in_element((By.TAG_NAME, "body"), "Good news")
                    ),
                    timeout=5
                )
                
                body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
                
                if "pwned" in body_text:
                    scan_data[target]["status"].append(f"[+] {email} has been pwned!")
                    pwned_emails.append(email)
                else:
                    scan_data[target]["status"].append(f"[-] {email} has NOT been pwned.")
                    
            except Exception:
                scan_data[target]["status"].append(f"[?] Skipping {email} - timeout.")
                
        except Exception as e:
            scan_data[target]["status"].append(f"Error checking {email}: skipping")
            continue
            
        # Very small delay
        time.sleep(0.5)
        
    return pwned_emails

def calculate_vulnerability_score(target):
    """
    Calculate a security score as a percentage (0-100%)
    100% = completely secure (no vulnerabilities)
    Score decreases based on severity and number of vulnerabilities
    Enhanced with Nuclei findings
    """
    vulnerabilities = scan_data[target]["vulnerabilities"]
    nuclei_findings = scan_data[target]["results"].get("nuclei", [])
    
    # Start with perfect score (100%)
    base_score = 100
    total_deduction = 0
    
    # Count vulnerabilities by severity
    high_count = 0
    medium_count = 0
    low_count = 0
    critical_count = 0  # For nuclei critical findings
    
    for vuln in vulnerabilities:
        severity = get_severity(vuln)
        if severity == "high":
            high_count += 1
        elif severity == "medium":
            medium_count += 1
        elif severity == "low":
            low_count += 1
    
    # Count nuclei-specific critical findings
    for finding in nuclei_findings:
        if finding.get('severity') == 'critical':
            critical_count += 1
    
    # Calculate deductions with enhanced scoring for critical vulnerabilities
    if critical_count > 0:
        critical_deduction = min(critical_count * 35, 70)  # Critical vulnerabilities deduct 35 points each, max 70%
        total_deduction += critical_deduction
    
    if high_count > 0:
        high_deduction = min(high_count * 25, 60)  # Cap high severity deduction at 60%
        total_deduction += high_deduction
    
    if medium_count > 0:
        medium_deduction = min(medium_count * 15, 40)  # Cap medium severity deduction at 40%
        total_deduction += medium_deduction
    
    if low_count > 0:
        low_deduction = min(low_count * 5, 20)  # Cap low severity deduction at 20%
        total_deduction += low_deduction
    
    # Calculate final score (minimum 0%)
    final_score = max(0, base_score - total_deduction)
    
    # Add bonus points for good security practices
    bonus_points = 0
    
    # Check for positive security indicators
    results = scan_data[target]["results"]
    
    # Bonus for HTTPS enforcement
    if any("https" in str(result).lower() for result in results.values()):
        bonus_points += 2
    
    # Bonus for security headers
    security_headers = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"]
    if any(header in str(results).lower() for header in security_headers):
        bonus_points += 3
    
    # Bonus for no exposed sensitive ports
    sensitive_ports = ["21", "22", "23", "25", "53", "110", "143", "993", "995"]
    nmap_output = results.get("nmap_raw", "")
    if nmap_output and not any(port in nmap_output for port in sensitive_ports):
        bonus_points += 2
    
    # Bonus for clean nuclei scan
    if len(nuclei_findings) == 0:
        bonus_points += 5
    
    # Apply bonus (max 100%)
    final_score = min(100, final_score + bonus_points)
    
    # Store both the percentage score and letter grade
    scan_data[target]["score"] = final_score
    scan_data[target]["grade"] = get_security_grade(final_score)
    
    print(f"Security Score Calculation for {target}:")
    print(f"  Critical vulnerabilities: {critical_count} (-{min(critical_count * 35, 70)}%)")
    print(f"  High vulnerabilities: {high_count} (-{min(high_count * 25, 60)}%)")
    print(f"  Medium vulnerabilities: {medium_count} (-{min(medium_count * 15, 40)}%)")
    print(f"  Low vulnerabilities: {low_count} (-{min(low_count * 5, 20)}%)")
    print(f"  Nuclei findings: {len(nuclei_findings)}")
    print(f"  Bonus points: +{bonus_points}%")
    print(f"  Final Security Score: {final_score}% (Grade: {scan_data[target]['grade']})")

def get_security_grade(score):
    """Convert percentage score to letter grade"""
    if score >= 90:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 50:
        return "D"
    else:
        return "F"

def save_scan_json(target):
    os.makedirs("scan_results", exist_ok=True)
    filename = f"scan_results/scan_{target.replace('.', '_')}.json"
    
    # Create comprehensive JSON output with all module results
    comprehensive_data = {
        "target": target,
        "scan_metadata": {
            "start_time": scan_data[target]["timestamp"],
            "total_duration": scan_data[target]["timestamps"],
            "scan_type": "comprehensive_vulnerability_scan",
            "tools_used": ["nmap", "subfinder", "gobuster", "email_crawler", "haveibeenpwned"]
        },
        "module_results": {
            "nmap": {
                "raw_output": scan_data[target]["results"].get("nmap_raw", ""),
                "status": "completed" if scan_data[target]["results"].get("nmap_raw") else "failed",
                "execution_time": scan_data[target]["timestamps"].get("nmap", {}),
                "ports_found": len([line for line in scan_data[target]["results"].get("nmap_raw", "").split('\n') if '/tcp' in line or '/udp' in line])
            },
            "subfinder": {
                "subdomains": scan_data[target]["results"].get("subdomains", []),
                "count": len(scan_data[target]["results"].get("subdomains", [])),
                "execution_time": scan_data[target]["timestamps"].get("subfinder", {}),
                "status": "completed" if scan_data[target]["results"].get("subdomains") else "no_results"
            },
            "gobuster": {
                "directories": scan_data[target]["results"].get("gobuster", []),
                "count": len(scan_data[target]["results"].get("gobuster", [])),
                "execution_time": scan_data[target]["timestamps"].get("gobuster", {}),
                "status": "completed" if scan_data[target]["results"].get("gobuster") else "skipped"
            },
            "email_crawler": {
                "emails_found": scan_data[target]["results"].get("emails", []),
                "count": len([e for e in scan_data[target]["results"].get("emails", []) if e != "No emails found"]),
                "execution_time": scan_data[target]["timestamps"].get("email_crawl", {}),
                "status": "completed"
            },
            "haveibeenpwned": {
                "pwned_emails": scan_data[target].get("pwned_emails", []),
                "count": len(scan_data[target].get("pwned_emails", [])),
                "execution_time": scan_data[target]["timestamps"].get("pwn_check", {}),
                "status": "completed" if scan_data[target]["timestamps"].get("pwn_check") else "skipped"
            },
            "nuclei": {
                "findings": scan_data[target]["results"].get("nuclei", []),
                "count": len(scan_data[target]["results"].get("nuclei", [])),
                "execution_time": scan_data[target]["timestamps"].get("nuclei", {}),
                "status": "completed" if scan_data[target]["timestamps"].get("nuclei") else "skipped",
                "cve_count": len([f for f in scan_data[target]["results"].get("nuclei", []) if 'cve' in f.get('template_id', '').lower()]),
                "exploit_count": len([f for f in scan_data[target]["results"].get("nuclei", []) if 'exploit' in f.get('template_id', '').lower()])
            }
        },
        "vulnerability_analysis": {
            "total_vulnerabilities": len(scan_data[target]["vulnerabilities"]),
            "security_score_percentage": scan_data[target]["score"],
            "security_grade": scan_data[target]["grade"],
            "score_breakdown": {
                "base_score": 100,
                "deductions": {
                    "high_severity": len(scan_data[target]["grouped"]["high"]) * 25,
                    "medium_severity": len(scan_data[target]["grouped"]["medium"]) * 15,
                    "low_severity": len(scan_data[target]["grouped"]["low"]) * 5
                },
                "final_score": scan_data[target]["score"]
            },
            "vulnerabilities_by_severity": scan_data[target]["grouped"],
            "all_vulnerabilities": scan_data[target]["vulnerabilities"]
        },
        "recommendations": scan_data[target]["recommendations"],
        "status_log": scan_data[target]["status"],
        "raw_data": scan_data[target]["results"]
    }
    
    with open(filename, "w") as f:
        json.dump(comprehensive_data, f, indent=4)
    
    # Also save a simplified version for quick reference
    simple_filename = f"scan_results/scan_{target.replace('.', '_')}_simple.json"
    simple_data = {
        "target": target,
        "scan_time": scan_data[target]["timestamp"],
        "security_score_percentage": scan_data[target]["score"],
        "security_grade": scan_data[target]["grade"],
        "vulnerabilities_count": len(scan_data[target]["vulnerabilities"]),
        "subdomains_found": len(scan_data[target]["results"].get("subdomains", [])),
        "emails_found": len([e for e in scan_data[target]["results"].get("emails", []) if e != "No emails found"]),
        "pwned_emails": len(scan_data[target].get("pwned_emails", [])),
        "nuclei_findings": len(scan_data[target]["results"].get("nuclei", [])),
        "cve_count": len([f for f in scan_data[target]["results"].get("nuclei", []) if 'cve' in f.get('template_id', '').lower()]),
        "exploit_count": len([f for f in scan_data[target]["results"].get("nuclei", []) if 'exploit' in f.get('template_id', '').lower()]),
        "high_risk_vulns": len(scan_data[target]["grouped"]["high"]),
        "medium_risk_vulns": len(scan_data[target]["grouped"]["medium"]),
        "low_risk_vulns": len(scan_data[target]["grouped"]["low"]),
        "score_explanation": f"Starting from 100%, deducted {100 - scan_data[target]['score']}% for vulnerabilities found"
    }
    
    with open(simple_filename, "w") as f:
        json.dump(simple_data, f, indent=4)
    
    # Print to console for confirmation
    print(f"✅ JSON reports saved:")
    print(f"   📄 Full report: {filename}")
    print(f"   📄 Simple report: {simple_filename}")
    
    # Add to scan status
    scan_data[target]["status"].append(f"JSON reports saved: {filename}")
    scan_data[target]["status"].append(f"Simple JSON saved: {simple_filename}")

def scan_target(target, gobuster_wordlist=None, fast_mode=False):
    scan_data[target] = {
        "status": [f"Starting comprehensive scan for {target}"],
        "results": {},
        "vulnerabilities": [],
        "grouped": {"high": [], "medium": [], "low": [], "info": []},
        "recommendations": [],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "score": 0,
        "pwned_emails": [],
        "timestamps": {}
    }

    # Faster Nmap scan - focused on most common ports
    nmap_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        nmap_out = subprocess.check_output(
            ["nmap", "-T4", "--top-ports", "20", "--open", "-Pn", target], 
            stderr=subprocess.PIPE, text=True, timeout=30  # Reduced from 45 to 30
        )
        scan_data[target]["status"].append("Nmap scan completed")
    except:
        nmap_out = "Nmap scan failed or timed out"
        scan_data[target]["status"].append("Nmap failed - continuing")
    nmap_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_data[target]["results"]["nmap_raw"] = nmap_out
    scan_data[target]["timestamps"]["nmap"] = {"start": nmap_start, "end": nmap_end}

    # Quick subdomain enumeration with reduced timeout
    subfinder_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        subfinder_out = subprocess.check_output(
            ["subfinder", "-d", target, "-silent", "-max-time", "20"], 
            stderr=subprocess.PIPE, text=True, timeout=25  # Reduced from 35 to 25
        )
        subdomains = subfinder_out.splitlines()[:10] if subfinder_out else []  # Limit to 10
        scan_data[target]["status"].append(f"Found {len(subdomains)} subdomains")
    except:
        subdomains = []
        scan_data[target]["status"].append("Subfinder failed - continuing")
    subfinder_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_data[target]["results"]["subdomains"] = subdomains
    scan_data[target]["timestamps"]["subfinder"] = {"start": subfinder_start, "end": subfinder_end}

    # Quick gobuster scan if wordlist provided
    if gobuster_wordlist:
        gobuster_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            gobuster_out = subprocess.check_output(
                ["gobuster", "dir", "-u", f"http://{target}", "-w", gobuster_wordlist, "-q", "--timeout", "10s", "-t", "20"],
                stderr=subprocess.PIPE, text=True, timeout=40
            )
            scan_data[target]["results"]["gobuster"] = gobuster_out.splitlines()
            scan_data[target]["status"].append(f"Directory scan found {len(gobuster_out.splitlines())} paths")
        except:
            scan_data[target]["results"]["gobuster"] = []
            scan_data[target]["status"].append("Directory scan failed - continuing")
        gobuster_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_data[target]["timestamps"]["gobuster"] = {"start": gobuster_start, "end": gobuster_end}
    else:
        scan_data[target]["results"]["gobuster"] = []
        scan_data[target]["status"].append("No wordlist provided - skipping directory scan")

    # Enhanced email crawling
    emails, crawl_times = crawl_emails(f"http://{target}", max_depth=1, delay=0.05, max_links_per_page=8)
    scan_data[target]["results"]["emails"] = list(emails) if emails else ["No emails found"]
    scan_data[target]["timestamps"]["email_crawl"] = crawl_times
    scan_data[target]["status"].append(f"Found {len(emails)} emails")

    # Quick pwned check for first 2 emails only
    if emails and len(emails) > 0:
        scan_data[target]["status"].append("Checking emails for breaches...")
        try:
            options = webdriver.FirefoxOptions()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-logging")
            driver = webdriver.Firefox(options=options)
            wait = WebDriverWait(driver, 8)

            pwned_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            pwned_emails = check_email_pwned_batch(list(emails)[:2], driver, wait, target)  # Only check first 2
            for email in pwned_emails:
                vuln_msg = f"Email {email} found in data breach (pwned)"
                scan_data[target]["vulnerabilities"].append(vuln_msg)
                scan_data[target]["pwned_emails"].append(email)
            pwned_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            scan_data[target]["timestamps"]["pwn_check"] = {"start": pwned_start, "end": pwned_end}

            driver.quit()
        except Exception as e:
            scan_data[target]["status"].append(f"Email breach check failed - continuing")

    # Enhanced vulnerability detection
    scan_data[target]["status"].append("Analyzing vulnerabilities...")
    
    # HTTP header analysis
    try:
        response = requests.get(f"http://{target}", timeout=8, allow_redirects=True)
        headers = response.headers
        
        if 'X-Powered-By' in headers:
            scan_data[target]["vulnerabilities"].append(f"X-Powered-By header exposes technology: {headers['X-Powered-By']}")
        if 'Server' in headers:
            scan_data[target]["vulnerabilities"].append(f"Server header reveals information: {headers['Server']}")
        if 'X-Frame-Options' not in headers:
            scan_data[target]["vulnerabilities"].append("X-Frame-Options header missing - clickjacking vulnerability")
        if 'X-Content-Type-Options' not in headers:
            scan_data[target]["vulnerabilities"].append("X-Content-Type-Options header missing - MIME sniffing vulnerability")
        if 'Strict-Transport-Security' not in headers:
            scan_data[target]["vulnerabilities"].append("HSTS header missing - protocol downgrade attacks possible")
        if 'Content-Security-Policy' not in headers:
            scan_data[target]["vulnerabilities"].append("Content-Security-Policy header missing - XSS vulnerability")
            
        # Check for common vulnerabilities in response
        if "Index of /" in response.text:
            scan_data[target]["vulnerabilities"].append("Directory listing enabled - information disclosure")
        if "apache" in headers.get('Server', '').lower() and "2.4.7" in headers.get('Server', ''):
            scan_data[target]["vulnerabilities"].append("Outdated Apache server detected - potential security vulnerabilities")
            
        scan_data[target]["status"].append("HTTP security analysis completed")
    except:
        scan_data[target]["status"].append("HTTP analysis failed - continuing")

    # Run Nuclei scan for CVEs and exploits
    nuclei_findings = run_nuclei_scan(target, nmap_out)

    # Manual vulnerability analysis from scan results
    analyze_manual_vulns(scan_data, target)

    # Group vulnerabilities by severity
    for vuln in scan_data[target]["vulnerabilities"]:
        level = get_severity(vuln)
        scan_data[target]["grouped"][level].append(vuln)

    # Calculate vulnerability score
    calculate_vulnerability_score(target)

    # Generate recommendations
    scan_data[target]["recommendations"] = get_recommendations(scan_data[target]["vulnerabilities"])

    scan_data[target]["status"].append("Comprehensive scan completed!")
    
    # Debug print
    print(f"🔥 SCAN COMPLETED FOR {target}")
    print(f"Found {len(scan_data[target]['vulnerabilities'])} vulnerabilities")
    print(f"Risk Score: {scan_data[target]['score']}")

    # Save JSON report file
    save_scan_json(target)
    
    # Final status update
    scan_data[target]["status"].append("All tasks finished - detailed report ready!")

def run_nuclei_scan(target, nmap_results=""):
    """
    Run Nuclei scan to detect CVEs and exploits based on identified services/ports
    """
    nuclei_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_data[target]["status"].append("Running Nuclei CVE/exploit detection...")
    
    try:
        # Faster Nuclei scan with reduced scope
        nuclei_cmd = [
            "nuclei", 
            "-u", f"http://{target}", 
            "-t", "http/technologies/",  # Focus on technology detection first
            "-t", "http/exposures/",  # Quick exposure checks
            "-silent",
            "-timeout", "3",  # Faster individual timeouts
            "-rate-limit", "50",  # Higher rate limit
            "-max-host-error", "3",  # Stop after 3 errors
            "-jsonl"
        ]
        
        # Add specific technology-based templates if detected
        if nmap_results:
            # Check for specific services and add relevant templates
            if "apache" in nmap_results.lower():
                nuclei_cmd.extend(["-t", "technologies/apache-*"])
            if "nginx" in nmap_results.lower():
                nuclei_cmd.extend(["-t", "technologies/nginx-*"])
            if "ssh" in nmap_results.lower() or "22/tcp" in nmap_results:
                nuclei_cmd.extend(["-t", "network/ssh-*"])
            if "mysql" in nmap_results.lower() or "3306/tcp" in nmap_results:
                nuclei_cmd.extend(["-t", "network/mysql-*"])
            if "ftp" in nmap_results.lower() or "21/tcp" in nmap_results:
                nuclei_cmd.extend(["-t", "network/ftp-*"])
        
        # Run Nuclei with optimized timeout
        nuclei_output = subprocess.check_output(
            nuclei_cmd,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60  # Reduced to 60 seconds for faster results
        )
        
        # Parse Nuclei JSON output
        nuclei_findings = []
        cve_count = 0
        exploit_count = 0
        
        if nuclei_output.strip():
            for line in nuclei_output.strip().split('\n'):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        info = finding.get('info', {})
                        template_id = finding.get('template-id', '')
                        severity = info.get('severity', 'info').lower()
                        name = info.get('name', template_id)
                        
                        # Create vulnerability entry
                        vuln_entry = f"Nuclei: {name} (Severity: {severity})"
                        nuclei_findings.append({
                            'template_id': template_id,
                            'name': name,
                            'severity': severity,
                            'url': finding.get('matched-at', ''),
                            'description': info.get('description', ''),
                            'reference': info.get('reference', []),
                            'tags': info.get('tags', [])
                        })
                        
                        # Count CVEs and exploits more comprehensively
                        template_lower = template_id.lower()
                        tags_str = str(info.get('tags', [])).lower()
                        
                        if ('cve-' in template_lower or 'cve-' in tags_str or 
                            'cve' in template_lower or 'cve' in tags_str):
                            cve_count += 1
                        if ('exploit' in template_lower or 'exploit' in tags_str or
                            'rce' in template_lower or 'sqli' in template_lower or
                            'xss' in template_lower or 'lfi' in template_lower):
                            exploit_count += 1
                        
                        # Add to vulnerabilities
                        scan_data[target]["vulnerabilities"].append(vuln_entry)
                        
                    except json.JSONDecodeError:
                        continue
        
        # If first scan completed quickly, try CVE scan
        if nuclei_output.strip() and len(nuclei_findings) < 10:
            try:
                scan_data[target]["status"].append("Running additional CVE scan...")
                cve_cmd = [
                    "nuclei", 
                    "-u", f"http://{target}", 
                    "-t", "http/cves/",  # CVE templates only
                    "-silent",
                    "-timeout", "3",
                    "-rate-limit", "50",
                    "-max-host-error", "2",
                    "-jsonl"
                ]
                
                cve_output = subprocess.check_output(
                    cve_cmd,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30  # Quick 30-second CVE scan
                )
                
                if cve_output.strip():
                    for line in cve_output.strip().split('\n'):
                        if line.strip():
                            try:
                                finding = json.loads(line)
                                info = finding.get('info', {})
                                template_id = finding.get('template-id', '')
                                name = info.get('name', template_id)
                                severity = info.get('severity', 'info').lower()
                                
                                nuclei_findings.append({
                                    'template_id': template_id,
                                    'name': name,
                                    'severity': severity,
                                    'url': finding.get('matched-at', ''),
                                    'description': info.get('description', ''),
                                    'reference': info.get('reference', []),
                                    'tags': info.get('tags', [])
                                })
                                
                                # Count additional CVEs and exploits
                                template_lower = template_id.lower()
                                tags_str = str(info.get('tags', [])).lower()
                                
                                if ('cve-' in template_lower or 'cve-' in tags_str or 
                                    'cve' in template_lower or 'cve' in tags_str):
                                    cve_count += 1
                                if ('exploit' in template_lower or 'exploit' in tags_str or
                                    'rce' in template_lower or 'sqli' in template_lower or
                                    'xss' in template_lower or 'lfi' in template_lower):
                                    exploit_count += 1
                                
                                vuln_entry = f"Nuclei CVE: {name} (Severity: {severity})"
                                scan_data[target]["vulnerabilities"].append(vuln_entry)
                                
                            except json.JSONDecodeError:
                                continue
                                
                    scan_data[target]["status"].append(f"CVE scan completed: {len(cve_output.strip().split())} additional findings")
                else:
                    scan_data[target]["status"].append("No additional CVEs found")
                    
            except subprocess.TimeoutExpired:
                scan_data[target]["status"].append("CVE scan timed out - continuing")
            except Exception as e:
                scan_data[target]["status"].append(f"CVE scan failed: {str(e)}")
        
        scan_data[target]["results"]["nuclei"] = nuclei_findings
        scan_data[target]["status"].append(f"Nuclei scan completed: {len(nuclei_findings)} findings ({cve_count} CVEs, {exploit_count} exploits)")
        
        # Update severity mapping for nuclei findings
        for finding in nuclei_findings:
            severity = finding['severity']
            if severity in ['critical', 'high']:
                scan_data[target]["grouped"]["high"].append(f"Nuclei: {finding['name']}")
            elif severity == 'medium':
                scan_data[target]["grouped"]["medium"].append(f"Nuclei: {finding['name']}")
            elif severity == 'low':
                scan_data[target]["grouped"]["low"].append(f"Nuclei: {finding['name']}")
            else:
                scan_data[target]["grouped"]["info"].append(f"Nuclei: {finding['name']}")
        
    except subprocess.TimeoutExpired:
        scan_data[target]["status"].append("Nuclei scan timed out - skipping for performance")
        scan_data[target]["results"]["nuclei"] = []
    except subprocess.CalledProcessError:
        scan_data[target]["status"].append("Nuclei scan failed - command error")
        scan_data[target]["results"]["nuclei"] = []
    except Exception as e:
        scan_data[target]["status"].append(f"Nuclei scan error: {str(e)}")
        scan_data[target]["results"]["nuclei"] = []
    
    nuclei_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_data[target]["timestamps"]["nuclei"] = {"start": nuclei_start, "end": nuclei_end}
    
    return scan_data[target]["results"].get("nuclei", [])

# Enhanced severity mapping to include nuclei findings
def update_severity_mapping():
    """Update severity mapping to include nuclei-specific patterns"""
    global severity_map
    severity_map["high"].extend(["nuclei: critical", "nuclei: high", "cve-", "exploit"])
    severity_map["medium"].extend(["nuclei: medium", "exposed-panel"])
    severity_map["low"].extend(["nuclei: low", "nuclei: info"])

# Call the update function
update_severity_mapping()

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/start_scan", methods=["POST"])
def start_scan():
    target = request.form.get("target", "").strip()
    file = request.files.get("wordlist")
    wordlist_path = None

    if file:
        os.makedirs("uploads", exist_ok=True)
        wordlist_path = os.path.join("uploads", file.filename)
        file.save(wordlist_path)

    if not target:
        return jsonify({"error": "No target provided"}), 400
    if target in scan_data:
        scan_data.pop(target)

    threading.Thread(target=scan_target, args=(target, wordlist_path), daemon=True).start()
    return jsonify({"message": f"Scan started for {target}"}), 202

@app.route("/scan_status/<target>")
def scan_status(target):
    return jsonify(scan_data.get(target, {"error": "No scan data found"}))

@app.route("/download_report/<target>")
def download_report(target):
    if target not in scan_data:
        return "No scan data found", 404
    report_path = f"report_{target.replace('.', '_')}.txt"
    with open(report_path, "w") as f:
        f.write(f"Scan Report for: {target}\n\n")
        f.write("STATUS LOG:\n")
        f.write("\n".join(scan_data[target]["status"]) + "\n\n")

        f.write("EMAILS FOUND:\n")
        for email in scan_data[target]["results"].get("emails", []):
            f.write(f"- {email}\n")

        f.write("\nPWNED EMAILS:\n")
        for pwn_email in scan_data[target].get("pwned_emails", []):
            f.write(f"- {pwn_email}\n")

        f.write("\nSUBDOMAINS FOUND:\n")
        for subd in scan_data[target]["results"].get("subdomains", []):
            f.write(f"- {subd}\n")

        f.write("\nVULNERABILITIES:\n")
        for level, vulns in scan_data[target]["grouped"].items():
            f.write(f"{level.upper()}:\n")
            for vuln in vulns:
                f.write(f"- {vuln}\n")
            f.write("\n")

        f.write(f"Total Vulnerability Score: {scan_data[target]['score']}\n\n")

        f.write("RECOMMENDATIONS:\n")
        for rec in scan_data[target]["recommendations"]:
            f.write(f"- {rec}\n")
    return send_file(report_path, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
