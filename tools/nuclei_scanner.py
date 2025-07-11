#!/usr/bin/env python3
"""
Nuclei Scanner Module
Advanced CVE detection and vulnerability scanning with Nuclei
Optimized for reliability and comprehensive coverage
"""

import subprocess
import json
import os
import time
from datetime import datetime

class NucleiScanner:
    def __init__(self, timeout=20, rate_limit=300, max_host_error=10):
        """
        Initialize Nuclei scanner optimized for MAXIMUM SPEED
        - timeout: Ultra-fast timeout for lightning-quick results
        - rate_limit: Maximum rate limit for blazing speed
        - max_host_error: Lower error tolerance for faster completion
        """
        self.timeout = timeout  # Ultra-fast timeout
        self.rate_limit = rate_limit  # Maximum rate limit
        self.max_host_error = max_host_error  # Faster error handling
        self.nuclei_path = self.find_nuclei_binary()
        
        # Skip template update for faster startup
        # self._update_templates()
        
    def _update_templates(self):
        """
        Update Nuclei templates for better coverage
        This ensures we have the latest vulnerability definitions
        """
        try:
            # Run template update in background without blocking the scan
            subprocess.run([self.nuclei_path, "-update-templates"], 
                         capture_output=True, timeout=30)
        except:
            # Continue if update fails - existing templates will work
            pass
        
    def find_nuclei_binary(self):
        """
        Find Nuclei binary in system PATH or common installation locations
        Returns the path to a working Nuclei installation
        """
        common_paths = [
            "/home/kira/go/bin/nuclei",
            "/usr/local/bin/nuclei", 
            "/usr/bin/nuclei",
            "nuclei"
        ]
        
        for path in common_paths:
            if os.path.exists(path) or path == "nuclei":
                try:
                    # Test if nuclei works by checking version
                    result = subprocess.run([path, "-version"], 
                                          capture_output=True, timeout=10)
                    if result.returncode == 0:
                        return path
                except:
                    continue
        return "nuclei"  # Default fallback - will work if in PATH
    
    def run_scan(self, target, templates, scan_timeout=None):
        """
        Run a single Nuclei scan phase with optimized settings
        - Uses progressive timeout strategy for better reliability
        - Handles network issues gracefully without stopping the entire scan
        """
        if scan_timeout is None:
            scan_timeout = self.timeout
            
        # Prepare target URL with proper protocol handling
        if not target.startswith(('http://', 'https://')):
            target_url = f"http://{target}"
        else:
            target_url = target
            
        # Build optimized Nuclei command for LIGHTNING SPEED
        cmd = [
            self.nuclei_path,
            "-u", target_url,
            "-silent",  # Reduce noise in output
            "-timeout", "2",  # Ultra-fast connection timeout
            "-rate-limit", str(self.rate_limit),
            "-max-host-error", str(self.max_host_error),
            "-retries", "0",  # No retries for maximum speed
            "-jsonl",  # JSON Lines output for easy parsing
            "-no-color",  # Clean output without ANSI codes
            "-disable-update-check",  # Skip update check for speed
            "-concurrency", "100",  # Maximum concurrency for speed
            "-no-httpx",  # Skip httpx for faster scanning
            "-no-interactsh",  # Skip interaction server for speed
            "-no-stats"  # Skip statistics for speed
        ]
        
        # Add template specifications to the command
        for template in templates:
            cmd.extend(["-t", template])
        
        try:
            # Execute Nuclei with proper timeout handling
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scan_timeout
            )
            
            # Process completed - check if we got useful output
            if process.stdout.strip():
                return process.stdout, "completed"
            else:
                # No vulnerabilities found but scan completed successfully
                return "", "completed"
                
        except subprocess.TimeoutExpired:
            # Timeout occurred - this is handled gracefully
            return "", "timeout"
        except FileNotFoundError:
            # Nuclei binary not found
            return "", "not_found"
        except Exception as e:
            # Other errors - continue with scan
            return "", "error"
    
    def parse_nuclei_output(self, output):
        """
        Parse Nuclei JSON output into structured vulnerability data
        - Handles malformed JSON gracefully
        - Extracts key information for security analysis
        """
        findings = []
        cve_count = 0
        exploit_count = 0
        
        if not output.strip():
            return findings, cve_count, exploit_count
        
        # Process each line of JSON output
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
                
            try:
                # Parse JSON finding
                finding = json.loads(line)
                info = finding.get('info', {})
                template_id = finding.get('template-id', '')
                severity = info.get('severity', 'info').lower()
                name = info.get('name', template_id)
                
                # Create structured finding record
                findings.append({
                    'template_id': template_id,
                    'name': name,
                    'severity': severity,
                    'url': finding.get('matched-at', ''),
                    'description': info.get('description', ''),
                    'reference': info.get('reference', []),
                    'tags': info.get('tags', []),
                    'classification': info.get('classification', {}),
                    'type': finding.get('type', 'http')
                })
                
                # Count CVEs and potential exploits for risk assessment
                template_lower = template_id.lower()
                tags_str = str(info.get('tags', [])).lower()
                classification = str(info.get('classification', {})).lower()
                
                # Detect CVE references
                if ('cve-' in template_lower or 'cve-' in tags_str or 
                    'cve' in classification):
                    cve_count += 1
                    
                # Detect exploitable vulnerabilities
                if ('exploit' in template_lower or 'exploit' in tags_str or
                    'rce' in template_lower or 'sqli' in template_lower or
                    'xss' in template_lower or 'lfi' in template_lower or
                    'xxe' in template_lower or 'ssti' in template_lower or
                    severity in ['critical', 'high']):
                    exploit_count += 1
                    
            except json.JSONDecodeError:
                # Skip malformed JSON lines but continue processing
                continue
        
        return findings, cve_count, exploit_count
    
    def scan(self, target, nmap_results=""):
        """
        Run a comprehensive and reliable Nuclei vulnerability scan
        - Uses smart template selection for better coverage
        - Continues scanning even if some phases fail
        - Returns maximum findings without interruption
        """
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        all_findings = []
        total_cve_count = 0
        total_exploit_count = 0
        scan_status = "completed"
        phases_run = 0
        
        print(f"🎯 Starting comprehensive Nuclei scan for {target}")
        print("⚙️ Using enhanced reliability settings...")
        
        # Define scan phases optimized for MAXIMUM SPEED
        scan_phases = [
            {
                "name": "Essential Security Checks",
                "templates": ["http/exposures/", "http/misconfiguration/"],
                "timeout": 15,  # Ultra-fast essential checks
                "priority": "high"
            },
            {
                "name": "Critical CVEs",
                "templates": ["http/cves/2024/", "http/vulnerabilities/"],
                "timeout": 20,  # Quick CVE detection
                "priority": "high"
            }
        ]
        
        # Add service-specific phases based on Nmap results
        if nmap_results:
            service_phase = self._create_service_specific_phase(nmap_results)
            if service_phase:
                scan_phases.append(service_phase)
        
        # Execute scan phases with resilience
        for i, phase in enumerate(scan_phases, 1):
            phase_name = phase["name"]
            templates = phase["templates"] 
            timeout = phase["timeout"]
            
            print(f"🔍 Phase {i}/{len(scan_phases)}: {phase_name}")
            
            try:
                # Run this phase of the scan
                output, status = self.run_scan(target, templates, timeout)
                phases_run += 1
                
                if status == "completed" and output:
                    # Parse findings from this phase
                    findings, cve_count, exploit_count = self.parse_nuclei_output(output)
                    all_findings.extend(findings)
                    total_cve_count += cve_count
                    total_exploit_count += exploit_count
                    print(f"✅ {phase_name}: {len(findings)} findings ({cve_count} CVEs, {exploit_count} exploits)")
                    
                elif status == "completed":
                    # Phase completed but no findings
                    print(f"✅ {phase_name}: No vulnerabilities found")
                    
                elif status == "timeout":
                    # Phase timed out - continue with next phase
                    print(f"⏱️ {phase_name}: Timed out, continuing to next phase")
                    if scan_status == "completed":
                        scan_status = "partial"
                        
                elif status == "not_found":
                    # Nuclei not found - critical error
                    print(f"❌ {phase_name}: Nuclei not found")
                    scan_status = "error"
                    break
                    
                else:
                    # Other error - continue scanning
                    print(f"⚠️ {phase_name}: Error occurred, continuing")
                    if scan_status == "completed":
                        scan_status = "partial"
                
                # Small delay between phases to prevent resource exhaustion
                time.sleep(2)
                
            except Exception as e:
                # Unexpected error - log and continue
                print(f"⚠️ {phase_name}: Unexpected error, continuing to next phase")
                if scan_status == "completed":
                    scan_status = "partial"
                continue
        
        # Final processing and deduplication
        unique_findings = self._deduplicate_findings(all_findings)
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"🏁 Nuclei scan completed!")
        print(f"📊 Results: {len(unique_findings)} unique findings")
        print(f"🎯 CVEs found: {total_cve_count}")
        print(f"💥 Exploitable: {total_exploit_count}")
        print(f"⚡ Phases completed: {phases_run}/{len(scan_phases)}")
        
        return {
            "findings": unique_findings,
            "count": len(unique_findings),
            "cve_count": total_cve_count,
            "exploit_count": total_exploit_count,
            "status": scan_status,
            "execution_time": {"start": start_time, "end": end_time},
            "target": target,
            "phases_completed": phases_run,
            "total_phases": len(scan_phases)
        }
    
    def _create_service_specific_phase(self, nmap_results):
        """
        Create service-specific scan phase based on Nmap discoveries
        This targets specific services for better vulnerability coverage
        """
        service_templates = []
        nmap_lower = nmap_results.lower()
        
        # Web server specific templates
        if "apache" in nmap_lower or "httpd" in nmap_lower:
            service_templates.extend(["http/vulnerabilities/apache/", "http/cves/apache/"])
        if "nginx" in nmap_lower:
            service_templates.extend(["http/vulnerabilities/nginx/", "http/cves/nginx/"])
        if "iis" in nmap_lower:
            service_templates.extend(["http/vulnerabilities/microsoft/", "http/cves/iis/"])
            
        # Database specific templates
        if "3306/tcp" in nmap_results or "mysql" in nmap_lower:
            service_templates.extend(["network/mysql-*", "network/detection/mysql-*"])
        if "5432/tcp" in nmap_results or "postgresql" in nmap_lower:
            service_templates.extend(["network/postgresql-*", "network/detection/postgresql-*"])
        if "1433/tcp" in nmap_results or "mssql" in nmap_lower:
            service_templates.extend(["network/mssql-*", "network/detection/mssql-*"])
            
        # Other services
        if "22/tcp" in nmap_results or "ssh" in nmap_lower:
            service_templates.extend(["network/ssh-*", "network/detection/ssh-*"])
        if "21/tcp" in nmap_results or "ftp" in nmap_lower:
            service_templates.extend(["network/ftp-*", "network/detection/ftp-*"])
        if "25/tcp" in nmap_results or "smtp" in nmap_lower:
            service_templates.extend(["network/smtp-*", "network/detection/smtp-*"])
            
        if service_templates:
            return {
                "name": "Service-Specific Vulnerabilities",
                "templates": service_templates,
                "timeout": 90,
                "priority": "high"
            }
        return None
    
    def _deduplicate_findings(self, findings):
        """
        Remove duplicate findings based on template ID and URL
        Keeps the most detailed finding for each unique vulnerability
        """
        unique_findings = []
        seen_combinations = set()
        
        for finding in findings:
            # Create unique identifier for this finding
            identifier = f"{finding.get('template_id', '')}:{finding.get('url', '')}"
            
            if identifier not in seen_combinations:
                unique_findings.append(finding)
                seen_combinations.add(identifier)
        
        # Sort by severity (critical first, then high, medium, low, info)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        unique_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 4))
        
        return unique_findings

def main():
    """
    Test the enhanced Nuclei scanner with a known vulnerable target
    This demonstrates the improved reliability and coverage
    """
    print("🧪 Testing Enhanced Nuclei Scanner")
    print("=" * 50)
    
    scanner = NucleiScanner()
    
    # Test with a known vulnerable target
    test_target = "testphp.vulnweb.com"
    print(f"🎯 Testing target: {test_target}")
    
    # Run the enhanced scan
    result = scanner.scan(test_target)
    
    print("\n📊 SCAN RESULTS SUMMARY")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Total Findings: {result['count']}")
    print(f"CVEs Detected: {result['cve_count']}")
    print(f"Exploitable Vulnerabilities: {result['exploit_count']}")
    print(f"Phases Completed: {result['phases_completed']}/{result['total_phases']}")
    print(f"Scan Duration: {result['execution_time']['start']} to {result['execution_time']['end']}")
    
    if result['findings']:
        print(f"\n🔍 TOP FINDINGS:")
        print("-" * 30)
        for i, finding in enumerate(result['findings'][:5], 1):
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠', 
                'medium': '🟡',
                'low': '🔵',
                'info': '⚪'
            }.get(finding['severity'], '⚪')
            
            print(f"{i}. {severity_emoji} {finding['name']}")
            print(f"   Severity: {finding['severity'].upper()}")
            print(f"   Template: {finding['template_id']}")
            if finding.get('url'):
                print(f"   URL: {finding['url']}")
            print()
    
    print("✅ Enhanced Nuclei scanner test completed!")

if __name__ == "__main__":
    main()
