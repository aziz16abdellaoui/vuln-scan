#!/usr/bin/env python3
"""
Subfinder Module
Handles subdomain enumeration
"""

import subprocess
from datetime import datetime

class SubfinderScanner:
    def __init__(self, timeout=25, max_time=20, max_results=10):
        self.timeout = timeout
        self.max_time = max_time
        self.max_results = max_results
    
    def scan(self, target):
        """
        Run Subfinder scan on target domain
        Returns dict with subdomain results and timing
        """
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Quick subdomain enumeration
            result = subprocess.check_output(
                ["subfinder", "-d", target, "-silent", "-max-time", str(self.max_time)],
                stderr=subprocess.PIPE, 
                text=True, 
                timeout=self.timeout
            )
            
            # Limit results and filter
            subdomains = result.splitlines()[:self.max_results] if result else []
            status = "completed" if subdomains else "no_results"
            
        except subprocess.TimeoutExpired:
            subdomains = []
            status = "timeout"
            
        except subprocess.CalledProcessError as e:
            subdomains = []
            status = "failed"
            
        except Exception as e:
            subdomains = []
            status = "error"
        
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return {
            "subdomains": subdomains,
            "count": len(subdomains),
            "status": status,
            "execution_time": {"start": start_time, "end": end_time},
            "target": target
        }

def main():
    """Test the Subfinder scanner"""
    scanner = SubfinderScanner()
    result = scanner.scan("example.com")
    print(f"Subfinder scan result: {result['status']}")
    print(f"Subdomains found: {result['count']}")
    print(f"Subdomains: {result['subdomains'][:5]}")

if __name__ == "__main__":
    main()
