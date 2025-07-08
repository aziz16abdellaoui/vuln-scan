#!/usr/bin/env python3
"""
Nmap Scanner Module
Handles port scanning and service detection
"""

import subprocess
from datetime import datetime

class NmapScanner:
    def __init__(self, timeout=30, top_ports=20):
        self.timeout = timeout
        self.top_ports = top_ports
    
    def scan(self, target):
        """
        Run Nmap scan on target
        Returns dict with scan results and timing
        """
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Fast Nmap scan focused on most common ports
            result = subprocess.check_output(
                ["nmap", "-T4", f"--top-ports", str(self.top_ports), "--open", "-Pn", target],
                stderr=subprocess.PIPE, 
                text=True, 
                timeout=self.timeout
            )
            status = "completed"
            
        except subprocess.TimeoutExpired:
            result = f"Nmap scan timed out after {self.timeout} seconds"
            status = "timeout"
            
        except subprocess.CalledProcessError as e:
            result = f"Nmap scan failed: {e}"
            status = "failed"
            
        except Exception as e:
            result = f"Nmap scan error: {e}"
            status = "error"
        
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Count open ports
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
