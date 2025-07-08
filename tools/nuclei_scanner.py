#!/usr/bin/env python3
"""
Nuclei Scanner Module
Handles CVE detection and vulnerability scanning with Nuclei
"""

import subprocess
import json
from datetime import datetime

class NucleiScanner:
    def __init__(self, timeout=60, rate_limit=50, max_host_error=3):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.max_host_error = max_host_error
    
    def run_scan(self, target, templates, scan_timeout=None):
        """Run a Nuclei scan with specified templates"""
        if scan_timeout is None:
            scan_timeout = self.timeout
            
        cmd = [
            "nuclei",
            "-u", f"http://{target}",
            "-silent",
            "-timeout", "3",
            "-rate-limit", str(self.rate_limit),
            "-max-host-error", str(self.max_host_error),
            "-jsonl"
        ]
        
        # Add templates
        for template in templates:
            cmd.extend(["-t", template])
        
        try:
            output = subprocess.check_output(
                cmd,
                stderr=subprocess.PIPE,
                text=True,
                timeout=scan_timeout
            )
            return output, "completed"
            
        except subprocess.TimeoutExpired:
            return "", "timeout"
        except subprocess.CalledProcessError:
            return "", "failed"
        except Exception as e:
            return "", "error"
    
    def parse_nuclei_output(self, output):
        """Parse Nuclei JSON output into structured data"""
        findings = []
        cve_count = 0
        exploit_count = 0
        
        if not output.strip():
            return findings, cve_count, exploit_count
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
                
            try:
                finding = json.loads(line)
                info = finding.get('info', {})
                template_id = finding.get('template-id', '')
                severity = info.get('severity', 'info').lower()
                name = info.get('name', template_id)
                
                findings.append({
                    'template_id': template_id,
                    'name': name,
                    'severity': severity,
                    'url': finding.get('matched-at', ''),
                    'description': info.get('description', ''),
                    'reference': info.get('reference', []),
                    'tags': info.get('tags', [])
                })
                
                # Count CVEs and exploits
                template_lower = template_id.lower()
                tags_str = str(info.get('tags', [])).lower()
                
                if ('cve-' in template_lower or 'cve-' in tags_str or 
                    'cve' in template_lower or 'cve' in tags_str):
                    cve_count += 1
                    
                if ('exploit' in template_lower or 'exploit' in tags_str or
                    'rce' in template_lower or 'sqli' in template_lower or
                    'xss' in template_lower or 'lfi' in template_lower):
                    exploit_count += 1
                    
            except json.JSONDecodeError:
                continue
        
        return findings, cve_count, exploit_count
    
    def scan(self, target, nmap_results=""):
        """
        Run comprehensive Nuclei scan on target
        Returns dict with vulnerability results and timing
        """
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Primary scan with technology detection and exposures
        primary_templates = [
            "http/technologies/",
            "http/exposures/"
        ]
        
        # Add specific templates based on nmap results
        if nmap_results:
            if "apache" in nmap_results.lower():
                primary_templates.append("technologies/apache-*")
            if "nginx" in nmap_results.lower():
                primary_templates.append("technologies/nginx-*")
            if "ssh" in nmap_results.lower() or "22/tcp" in nmap_results:
                primary_templates.append("network/ssh-*")
            if "mysql" in nmap_results.lower() or "3306/tcp" in nmap_results:
                primary_templates.append("network/mysql-*")
            if "ftp" in nmap_results.lower() or "21/tcp" in nmap_results:
                primary_templates.append("network/ftp-*")
        
        # Run primary scan
        output, status = self.run_scan(target, primary_templates)
        findings, cve_count, exploit_count = self.parse_nuclei_output(output)
        
        # If primary scan completed quickly and found few results, try CVE scan
        if status == "completed" and len(findings) < 10:
            cve_output, cve_status = self.run_scan(target, ["http/cves/"], 30)
            
            if cve_status == "completed":
                cve_findings, additional_cves, additional_exploits = self.parse_nuclei_output(cve_output)
                findings.extend(cve_findings)
                cve_count += additional_cves
                exploit_count += additional_exploits
        
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return {
            "findings": findings,
            "count": len(findings),
            "cve_count": cve_count,
            "exploit_count": exploit_count,
            "status": status,
            "execution_time": {"start": start_time, "end": end_time},
            "target": target
        }

def main():
    """Test the Nuclei scanner"""
    scanner = NucleiScanner()
    result = scanner.scan("testphp.vulnweb.com")
    print(f"Nuclei scan result: {result['status']}")
    print(f"Findings: {result['count']}")
    print(f"CVEs: {result['cve_count']}")
    print(f"Exploits: {result['exploit_count']}")
    
    if result['findings']:
        print("\nFirst finding:")
        print(f"  - {result['findings'][0]['name']} ({result['findings'][0]['severity']})")

if __name__ == "__main__":
    main()
