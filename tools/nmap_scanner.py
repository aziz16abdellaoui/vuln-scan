#!/usr/bin/env python3
"""
Nmap Scanner Module
This module handles network port scanning and service detection
Uses the popular Nmap tool to find open ports on target systems
"""


import subprocess
from datetime import datetime

class NmapScanner:
    def __init__(self, timeout=30, top_ports=20):
        """Set up the scanner with default settings"""
        self.timeout = timeout        # How long to wait before giving up
        self.top_ports = top_ports   # Number of most common ports to check
    
    def scan(self, target):
        """
        Run an Nmap scan on the target system
        Returns a dictionary with scan results and timing information
        """
        # Record when we started the scan
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Run a fast Nmap scan on the most common ports
            # -T4: Use timing template 4 (aggressive but not too fast)
            # --top-ports: Scan only the most commonly used ports
            # --open: Show only ports that are actually open
            # -Pn: Skip ping test (assume host is up)
            result = subprocess.check_output(
                ["nmap", "-T4", f"--top-ports", str(self.top_ports), "--open", "-Pn", target],
                stderr=subprocess.PIPE, 
                text=True, 
                timeout=self.timeout
            )
            status = "completed"  # Scan finished successfully
            
        except subprocess.TimeoutExpired:
            # Scan took too long and was cancelled
            result = f"Nmap scan timed out after {self.timeout} seconds"
            status = "timeout"
            
        except subprocess.CalledProcessError as e:
            # Nmap command failed for some reason
            result = f"Nmap scan failed: {e}"
            status = "failed"
            
        except Exception as e:
            # Some other unexpected error happened
            result = f"Nmap scan error: {e}"
            status = "error"
        
        # وقت انتهاء الفحص - End time of scan
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # عد المنافذ المفتوحة - Count open ports
        ports_found = len([line for line in result.split('\n') if '/tcp' in line or '/udp' in line])
        
        return {
            "raw_output": result,
            "status": status,
            "execution_time": {"start": start_time, "end": end_time},
            "ports_found": ports_found,
            "target": target
        }

def main():
    """Test the Nmap scanner"""
    scanner = NmapScanner()
    result = scanner.scan("scanme.nmap.org")
    print(f"Nmap scan result: {result['status']}")
    print(f"Ports found: {result['ports_found']}")
    print(f"Output: {result['raw_output'][:200]}...")

if __name__ == "__main__":
    main()
