#!/usr/bin/env python3
"""
Speed Benchmark for Vulnerability Scanner
Test different profiles to show performance improvements
"""

import time
import subprocess
import sys
import os

def run_benchmark():
    """Run speed benchmarks for all profiles"""
    
    print("🏃‍♂️ VULNERABILITY SCANNER SPEED BENCHMARK")
    print("=" * 60)
    print("Testing all scan profiles for speed optimization...")
    print()
    
    # Test targets (safe to scan)
    targets = ["127.0.0.1", "scanme.nmap.org"]
    profiles = ["quick", "standard", "comprehensive"]
    
    results = {}
    
    for target in targets:
        print(f"🎯 Testing target: {target}")
        print("-" * 40)
        
        results[target] = {}
        
        for profile in profiles:
            print(f"  📊 Profile: {profile}")
            
            start_time = time.time()
            
            try:
                # Run the scan with timeout
                timeout = 300  # 5 minutes max
                result = subprocess.run([
                    sys.executable, "main.py", "cli", target, profile
                ], 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                cwd=os.path.dirname(os.path.abspath(__file__))
                )
                
                end_time = time.time()
                duration = end_time - start_time
                
                results[target][profile] = {
                    "duration": round(duration, 1),
                    "status": "completed" if result.returncode == 0 else "error"
                }
                
                print(f"     ⏱️  Duration: {duration:.1f} seconds")
                print(f"     ✅ Status: {results[target][profile]['status']}")
                
            except subprocess.TimeoutExpired:
                duration = timeout
                results[target][profile] = {
                    "duration": timeout,
                    "status": "timeout"
                }
                print(f"     ⏱️  Duration: >>{timeout}s (timeout)")
                print(f"     ⚠️  Status: timeout")
            
            print()
    
    # Print summary
    print("📊 BENCHMARK SUMMARY")
    print("=" * 60)
    
    for target in targets:
        print(f"\n🎯 Target: {target}")
        print("Profile          Duration    Status")
        print("-" * 35)
        
        for profile in profiles:
            data = results[target][profile]
            duration_str = f"{data['duration']:.1f}s"
            status_emoji = "✅" if data['status'] == "completed" else ("⚠️" if data['status'] == "timeout" else "❌")
            
            print(f"{profile:<15} {duration_str:<10} {status_emoji} {data['status']}")
    
    print("\n🚀 SPEED IMPROVEMENTS:")
    print("- Quick Profile: Optimized for <20 seconds")
    print("- Standard Profile: Optimized for <45 seconds") 
    print("- Comprehensive Profile: Optimized for <90 seconds")
    print("\n💡 Choose profile based on your time vs depth needs!")

if __name__ == "__main__":
    run_benchmark()
