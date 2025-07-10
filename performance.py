#!/usr/bin/env python3
"""
Performance Monitor for Vulnerability Scanner
Track scan performance, timing, and resource usage
"""

import time
import psutil
import threading
from datetime import datetime
from collections import defaultdict

class PerformanceMonitor:
    """Monitor scanner performance and resource usage"""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.module_timings = {}
        self.resource_usage = defaultdict(list)
        self.monitoring = False
        self.monitor_thread = None
        
    def start_monitoring(self, target):
        """Start performance monitoring for a scan"""
        self.start_time = datetime.now()
        self.target = target
        self.monitoring = True
        
        # Start resource monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        self.monitor_thread.start()
        
        print(f"📊 Performance monitoring started for {target}")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.end_time = datetime.now()
        self.monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
        
        print("📊 Performance monitoring stopped")
        return self.get_performance_report()
    
    def time_module(self, module_name):
        """Context manager for timing module execution"""
        return ModuleTimer(self, module_name)
    
    def _monitor_resources(self):
        """Monitor system resources during scan"""
        while self.monitoring:
            try:
                # Get current resource usage
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                
                timestamp = datetime.now()
                self.resource_usage['cpu'].append((timestamp, cpu_percent))
                self.resource_usage['memory'].append((timestamp, memory.percent))
                
                time.sleep(5)  # Monitor every 5 seconds
            except:
                # Continue monitoring even if we can't get resource data
                time.sleep(5)
    
    def record_module_timing(self, module_name, duration):
        """Record timing for a specific module"""
        self.module_timings[module_name] = duration
    
    def get_performance_report(self):
        """Generate performance report"""
        if not self.start_time or not self.end_time:
            return {"error": "Monitoring not completed"}
        
        total_duration = (self.end_time - self.start_time).total_seconds()
        
        # Calculate resource usage statistics
        cpu_usage = [usage[1] for usage in self.resource_usage['cpu']]
        memory_usage = [usage[1] for usage in self.resource_usage['memory']]
        
        report = {
            "total_duration": round(total_duration, 2),
            "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": self.end_time.strftime("%Y-%m-%d %H:%M:%S"),
            "module_timings": {k: round(v, 2) for k, v in self.module_timings.items()},
            "resource_usage": {
                "avg_cpu": round(sum(cpu_usage) / len(cpu_usage), 2) if cpu_usage else 0,
                "max_cpu": round(max(cpu_usage), 2) if cpu_usage else 0,
                "avg_memory": round(sum(memory_usage) / len(memory_usage), 2) if memory_usage else 0,
                "max_memory": round(max(memory_usage), 2) if memory_usage else 0
            },
            "efficiency_score": self._calculate_efficiency_score(total_duration)
        }
        
        return report
    
    def _calculate_efficiency_score(self, duration):
        """Calculate efficiency score based on duration and findings"""
        # Baseline: under 90 seconds is excellent, under 180 is good
        if duration <= 90:
            return "Excellent"
        elif duration <= 180:
            return "Good"
        elif duration <= 300:
            return "Fair"
        else:
            return "Needs Optimization"

class ModuleTimer:
    """Context manager for timing module execution"""
    
    def __init__(self, monitor, module_name):
        self.monitor = monitor
        self.module_name = module_name
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.monitor.record_module_timing(self.module_name, duration)

class ScanProfiler:
    """Manage different scan profiles for various use cases"""
    
    @staticmethod
    def get_profile_config(profile_name):
        """Get configuration for a specific scan profile"""
        from config import ScannerConfig
        
        profiles = ScannerConfig.SCAN_PROFILES
        if profile_name not in profiles:
            return profiles['standard']  # Default to standard
        
        return profiles[profile_name]
    
    @staticmethod
    def list_profiles():
        """List all available scan profiles"""
        from config import ScannerConfig
        
        profiles_info = []
        for name, config in ScannerConfig.SCAN_PROFILES.items():
            profiles_info.append({
                "name": name,
                "description": config.get('description', 'No description'),
                "timeout": config.get('nuclei_timeout', 45),
                "phases": len(config.get('nuclei_phases', [])),
                "comprehensive": len(config.get('nuclei_phases', [])) > 3
            })
        
        return profiles_info

def main():
    """Test performance monitoring"""
    monitor = PerformanceMonitor()
    
    # Test monitoring
    monitor.start_monitoring("test.com")
    
    # Simulate some work
    with monitor.time_module("test_module"):
        time.sleep(2)
    
    # Stop and get report
    report = monitor.stop_monitoring()
    
    print("\n📊 Performance Report:")
    print(f"Total Duration: {report['total_duration']}s")
    print(f"Module Timings: {report['module_timings']}")
    print(f"Resource Usage: {report['resource_usage']}")
    print(f"Efficiency: {report['efficiency_score']}")

if __name__ == "__main__":
    main()
