#!/usr/bin/env python3
"""
Quick test script to verify the error handling improvements
"""

import requests
import json
import time

def test_error_handling():
    """Test the improved error handling in the web interface"""
    base_url = "http://localhost:5000"
    
    print("🧪 Testing Error Handling Improvements")
    print("=" * 50)
    
    # Test 1: Check status endpoint for non-existent scan
    print("Test 1: Non-existent scan status")
    try:
        response = requests.get(f"{base_url}/scan_status/nonexistent.com")
        data = response.json()
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(data, indent=2)}")
        if data.get('error_type') == 'scan_not_found':
            print("✅ Proper error handling for non-existent scan")
        else:
            print("❌ Error handling not working as expected")
    except Exception as e:
        print(f"❌ Error testing non-existent scan: {e}")
    
    print("\n" + "-" * 30 + "\n")
    
    # Test 2: Check scan_alive endpoint
    print("Test 2: Scan alive endpoint")
    try:
        response = requests.get(f"{base_url}/scan_alive/nonexistent.com")
        data = response.json()
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(data, indent=2)}")
        if data.get('message') and 'No scan found' in data.get('message'):
            print("✅ Proper error handling for scan_alive")
        else:
            print("❌ Scan alive error handling not working as expected")
    except Exception as e:
        print(f"❌ Error testing scan_alive: {e}")
    
    print("\n" + "-" * 30 + "\n")
    
    # Test 3: Check general endpoints
    print("Test 3: General endpoint health")
    try:
        response = requests.get(f"{base_url}/")
        if response.status_code == 200:
            print("✅ Main page loads successfully")
        else:
            print(f"❌ Main page error: {response.status_code}")
            
        response = requests.get(f"{base_url}/test_modules")
        data = response.json()
        if data.get('overall') == "✅ All modules loaded successfully":
            print("✅ All modules loading successfully")
        else:
            print(f"❌ Module loading issues: {data}")
    except Exception as e:
        print(f"❌ Error testing general endpoints: {e}")

if __name__ == "__main__":
    print("Make sure the web interface is running on localhost:5000")
    print("Run: python3 app_modular.py")
    print()
    input("Press Enter when ready to test...")
    test_error_handling()
