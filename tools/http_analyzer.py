#!/usr/bin/env python3
"""
HTTP Security Analyzer Module
This module checks web applications for common security issues
Looks at HTTP headers and page content for vulnerabilities
"""

import requests
from datetime import datetime

class HTTPAnalyzer:
    def __init__(self, timeout=3):
        self.timeout = timeout  # Ultra-fast timeout for web requests
    
    def analyze_headers(self, headers):
        """Check HTTP headers for security problems"""
        vulnerabilities = []
        
        # Look for headers that reveal too much information
        if 'X-Powered-By' in headers:
            vulnerabilities.append(f"X-Powered-By header exposes technology: {headers['X-Powered-By']}")
            
        if 'Server' in headers:
            vulnerabilities.append(f"Server header reveals information: {headers['Server']}")
        
        # Check for important security headers that are missing
        security_headers = {
            'X-Frame-Options': "X-Frame-Options header missing - clickjacking vulnerability",
            'X-Content-Type-Options': "X-Content-Type-Options header missing - MIME sniffing vulnerability", 
            'Strict-Transport-Security': "HSTS header missing - protocol downgrade attacks possible",
            'Content-Security-Policy': "Content-Security-Policy header missing - XSS vulnerability"
        }
        
        # Check each security header and report if missing
        for header, message in security_headers.items():
            if header not in headers:
                vulnerabilities.append(message)
        
        return vulnerabilities
    
    def analyze_content(self, content):
        """Look through web page content for security issues"""
        vulnerabilities = []
        
        # Check for directory listing
        if "Index of /" in content:
            vulnerabilities.append("Directory listing enabled - information disclosure")
        
        # Check for common error pages that reveal info
        error_indicators = [
            ("apache", "2.4.7", "Outdated Apache server detected - potential security vulnerabilities"),
            ("nginx", "error", "Server error page reveals information"),
            ("php", "warning", "PHP warnings exposed - information disclosure")
        ]
        
        content_lower = content.lower()
        for indicator1, indicator2, message in error_indicators:
            if indicator1 in content_lower and indicator2 in content_lower:
                vulnerabilities.append(message)
                break
        
        return vulnerabilities
    
    def analyze(self, target):
        """
        Analyze target for HTTP security issues
        Returns dict with vulnerability results and timing
        """
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        vulnerabilities = []
        status = "completed"
        headers_info = {}
        
        try:
            response = requests.get(
                f"http://{target}", 
                timeout=self.timeout, 
                allow_redirects=True
            )
            
            headers_info = dict(response.headers)
            
            # Analyze headers
            header_vulns = self.analyze_headers(response.headers)
            vulnerabilities.extend(header_vulns)
            
            # Analyze content
            content_vulns = self.analyze_content(response.text)
            vulnerabilities.extend(content_vulns)
            
        except requests.RequestException as e:
            status = "failed"
            vulnerabilities.append(f"HTTP analysis failed: {str(e)}")
            
        except Exception as e:
            status = "error"
            vulnerabilities.append(f"HTTP analysis error: {str(e)}")
        
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return {
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities),
            "headers": headers_info,
            "status": status,
            "execution_time": {"start": start_time, "end": end_time},
            "target": target
        }

def main():
    """Test the HTTP Analyzer"""
    analyzer = HTTPAnalyzer()
    result = analyzer.analyze("testphp.vulnweb.com")
    print(f"HTTP analysis result: {result['status']}")
    print(f"Vulnerabilities found: {result['count']}")
    print("Vulnerabilities:")
    for vuln in result['vulnerabilities']:
        print(f"  - {vuln}")

if __name__ == "__main__":
    main()
