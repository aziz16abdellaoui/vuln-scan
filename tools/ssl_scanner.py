#!/usr/bin/env python3
"""
SSL/TLS Security Scanner Module
Analyzes SSL certificates and TLS configuration
"""

import ssl
import socket
import datetime
from urllib.parse import urlparse

class SSLScanner:
    def __init__(self, timeout=10):
        self.timeout = timeout
    
    def scan(self, target):
        """Analyze SSL/TLS configuration of target"""
        start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        results = {
            "certificate_info": {},
            "ssl_issues": [],
            "cipher_suites": [],
            "protocol_versions": [],
            "status": "completed",
            "execution_time": {"start": start_time}
        }
        
        try:
            # Parse target to get hostname and port
            if '://' not in target:
                hostname = target
                port = 443  # Default HTTPS port
            else:
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or 443
            
            # Get SSL certificate information
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    results["certificate_info"] = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "version": cert['version'],
                        "not_before": cert['notBefore'],
                        "not_after": cert['notAfter'],
                        "serial_number": cert['serialNumber']
                    }
                    
                    results["cipher_suites"] = [cipher]
                    
                    # Check for common SSL issues
                    self._check_ssl_issues(cert, results)
                    
        except Exception as e:
            results["status"] = "error"
            results["ssl_issues"].append(f"SSL scan failed: {str(e)}")
        
        results["execution_time"]["end"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return results
    
    def _check_ssl_issues(self, cert, results):
        """Check for common SSL/TLS issues"""
        # Check certificate expiration
        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_until_expiry = (not_after - datetime.datetime.now()).days
        
        if days_until_expiry < 30:
            results["ssl_issues"].append(f"Certificate expires in {days_until_expiry} days")
        
        # Check for weak signature algorithm
        if 'sha1' in cert.get('signatureAlgorithm', '').lower():
            results["ssl_issues"].append("Weak SHA1 signature algorithm detected")
        
        # Add more SSL security checks here...
