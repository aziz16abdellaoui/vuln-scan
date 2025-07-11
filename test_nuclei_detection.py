#!/usr/bin/env python3
"""
Test Nuclei Detection on testphp.vulnweb.com
This script verifies that Nuclei is properly detecting vulnerabilities
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from tools.nuclei_scanner import NucleiScanner, test_testphp_detection

def main():
    print("🔥 Testing Nuclei Detection Capabilities")
    print("=" * 50)
    
    # Test 1: Basic Nuclei functionality
    print("Test 1: Basic Nuclei Scanner Initialization")
    try:
        scanner = NucleiScanner()
        print(f"✅ Nuclei binary found at: {scanner.nuclei_path}")
    except Exception as e:
        print(f"❌ Nuclei initialization failed: {e}")
        return
    
    # Test 2: Quick scan of testphp.vulnweb.com
    print("\nTest 2: Quick vulnerability scan")
    try:
        result = scanner.scan("http://testphp.vulnweb.com")
        print(f"✅ Scan completed - Found {result['count']} vulnerabilities")
        
        if result['findings']:
            print("\n🎯 Detected Vulnerabilities:")
            for i, finding in enumerate(result['findings'][:5], 1):
                print(f"{i}. {finding['name']} - {finding['severity'].upper()}")
                print(f"   Template: {finding['template_id']}")
                if finding.get('url'):
                    print(f"   URL: {finding['url']}")
                print()
        else:
            print("⚠️  No vulnerabilities detected - this might indicate a configuration issue")
            
    except Exception as e:
        print(f"❌ Scan failed: {e}")
    
    # Test 3: Manual Nuclei command test
    print("\nTest 3: Manual Nuclei Command Test")
    import subprocess
    try:
        # Test basic Nuclei command
        cmd = [scanner.nuclei_path, "-u", "http://testphp.vulnweb.com", "-t", "http/vulnerabilities/", "-silent", "-jsonl"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            print(f"✅ Manual test found {len(lines)} potential vulnerabilities")
            print("Sample output:")
            print(result.stdout[:500])
        else:
            print("⚠️  Manual test found no vulnerabilities")
            if result.stderr:
                print(f"Error output: {result.stderr[:200]}")
                
    except Exception as e:
        print(f"❌ Manual test failed: {e}")

if __name__ == "__main__":
    main()
