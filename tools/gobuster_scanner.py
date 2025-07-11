#!/usr/bin/env python3
"""
Gobuster Directory Scanner Module
Handles directory and file discovery
"""

import subprocess
import os
from datetime import datetime

class GobusterScanner:
    def __init__(self, timeout=15, threads=50, request_timeout="3s"):
        self.timeout = timeout  # Ultra-fast timeout
        self.threads = threads  # High concurrency
        self.request_timeout = request_timeout  # Quick requests
    
    def scan(self, target, wordlist_path=None):
        """
        Run Gobuster directory scan on target
        Returns dict with directory results and timing
        """
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Use default wordlist if none provided
        if not wordlist_path:
            default_wordlist = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlist_common.txt')
            if os.path.exists(default_wordlist):
                wordlist_path = default_wordlist
            else:
                return {
                    "directories": [],
                    "count": 0,
                    "status": "skipped",
                    "execution_time": {"start": start_time, "end": start_time},
                    "target": target,
                    "message": "No wordlist provided and default wordlist not found"
                }
        
        try:
            # Quick directory scan
            result = subprocess.check_output([
                "gobuster", "dir", 
                "-u", f"http://{target}",
                "-w", wordlist_path,
                "-q",  # Quiet mode
                "--timeout", self.request_timeout,
                "-t", str(self.threads)
            ],
            stderr=subprocess.PIPE, 
            text=True, 
            timeout=self.timeout
            )
            
            directories = result.splitlines() if result else []
            status = "completed"
            
        except subprocess.TimeoutExpired:
            directories = []
            status = "timeout"
            
        except subprocess.CalledProcessError as e:
            directories = []
            status = "failed"
            
        except Exception as e:
            directories = []
            status = "error"
        
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return {
            "directories": directories,
            "count": len(directories),
            "status": status,
            "execution_time": {"start": start_time, "end": end_time},
            "target": target
        }

def main():
    """Test the Gobuster scanner"""
    scanner = GobusterScanner()
    # Test without wordlist
    result = scanner.scan("example.com")
    print(f"Gobuster scan result: {result['status']}")
    print(f"Directories found: {result['count']}")
    print(f"Message: {result.get('message', 'N/A')}")

if __name__ == "__main__":
    main()
