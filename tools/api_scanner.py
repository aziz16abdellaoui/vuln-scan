#!/usr/bin/env python3
"""
API Security Scanner Module
Tests for common API vulnerabilities and misconfigurations
"""

import requests
import json
from datetime import datetime

class APIScanner:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/swagger', '/openapi.json', '/api-docs',
            '/admin/api', '/dev/api', '/test/api'
        ]
    
    def scan(self, target):
        """Scan for API endpoints and security issues"""
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        results = {
            "api_endpoints": [],
            "vulnerabilities": [],
            "authentication_issues": [],
            "rate_limiting": "unknown",
            "status": "completed",
            "execution_time": {"start": start_time}
        }
        
        base_url = f"http://{target}" if not target.startswith('http') else target
        
        try:
            # Discover API endpoints
            for path in self.common_api_paths:
                try:
                    response = requests.get(f"{base_url}{path}", timeout=self.timeout)
                    if response.status_code < 400:
                        results["api_endpoints"].append({
                            "path": path,
                            "status_code": response.status_code,
                            "content_type": response.headers.get('content-type', '')
                        })
                        
                        # Check for API documentation exposure
                        if 'swagger' in path or 'api-docs' in path:
                            results["vulnerabilities"].append(f"API documentation exposed at {path}")
                        
                        # Test for authentication bypass
                        self._test_auth_bypass(f"{base_url}{path}", results)
                        
                except requests.RequestException:
                    continue
            
            # Test rate limiting
            self._test_rate_limiting(base_url, results)
            
        except Exception as e:
            results["status"] = "error"
            results["vulnerabilities"].append(f"API scan failed: {str(e)}")
        
        results["execution_time"]["end"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return results
    
    def _test_auth_bypass(self, url, results):
        """Test for authentication bypass vulnerabilities"""
        # Test common authentication bypass techniques
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'User-Agent': 'internal-scanner'}
        ]
        
        for headers in bypass_headers:
            try:
                response = requests.get(url, headers=headers, timeout=self.timeout)
                if response.status_code == 200 and 'admin' in response.text.lower():
                    results["authentication_issues"].append(f"Potential auth bypass with headers: {headers}")
            except:
                continue
    
    def _test_rate_limiting(self, base_url, results):
        """Test if rate limiting is implemented"""
        try:
            # Make multiple rapid requests
            for i in range(5):
                response = requests.get(base_url, timeout=self.timeout)
                if response.status_code == 429:  # Too Many Requests
                    results["rate_limiting"] = "enabled"
                    return
            results["rate_limiting"] = "disabled"
        except:
            results["rate_limiting"] = "unknown"
