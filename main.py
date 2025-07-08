#!/usr/bin/env python3
"""
Main Entry Point for Modular Vulnerability Scanner
Run with: python main.py or python3 main.py
Directly starts the user-friendly web interface
"""

import os
import sys
import subprocess
import time
from datetime import datetime

def print_startup_banner():
    """Display the startup banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    🔥 MODULAR VULNERABILITY SCANNER 🔥                               ║
║                                                                      ║
║    Starting User-Friendly Web Interface...                          ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def check_dependencies():
    """Check if required dependencies are available"""
    print("🔍 Checking dependencies...")
    
    # Check Python modules
    python_deps = ['flask', 'requests', 'selenium']
    missing_python = []
    
    for dep in python_deps:
        try:
            __import__(dep)
            print(f"✓ Python: {dep}")
        except ImportError:
            missing_python.append(dep)
            print(f"✗ Python: {dep}")
    
    # Check project files
    required_files = ['app_modular.py', 'tools/nmap_scanner.py']
    missing_files = []
    
    for file in required_files:
        if os.path.exists(file):
            print(f"✓ File: {file}")
        else:
            missing_files.append(file)
            print(f"✗ File: {file}")
    
    if missing_python or missing_files:
        print("\n⚠️  Missing dependencies detected!")
        if missing_python:
            print(f"   Install Python packages: pip3 install {' '.join(missing_python)}")
        if missing_files:
            print(f"   Missing files: {', '.join(missing_files)}")
        print()
        return False
    else:
        print("✅ All dependencies are available!")
        print()
        return True

def start_web_interface():
    """Start the web interface"""
    print("🌐 Starting User-Friendly Web Interface...")
    print()
    print("📌 Once started:")
    print("   🌐 Open your browser")
    print("   🔗 Go to: http://localhost:5000")
    print("   🎯 Enter a target domain (e.g., scanme.nmap.org)")
    print("   ▶️  Click 'Start Scan'")
    print("   📊 Watch real-time progress")
    print("   💾 Download reports when complete")
    print()
    print("🛑 Press Ctrl+C to stop the server")
    print("=" * 60)
    
    try:
        subprocess.run([sys.executable, "app_modular.py"])
    except KeyboardInterrupt:
        print("\n🛑 Web server stopped by user")
        print("👋 Thank you for using the Modular Vulnerability Scanner!")
    except FileNotFoundError:
        print("❌ Error: app_modular.py not found")
        print("💡 Make sure you're in the correct directory")

def main():
    """Main function - directly start web interface"""
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Clear screen (works on most terminals)
    os.system('clear' if os.name == 'posix' else 'cls')
    
    print_startup_banner()
    
    # Check dependencies
    deps_ok = check_dependencies()
    
    if not deps_ok:
        print("❌ Cannot start web interface - missing dependencies")
        print("\n💡 To install missing Python dependencies:")
        print("   pip3 install -r requirements.txt")
        print("\n💡 For help, see: HOW_TO_RUN.md")
        sys.exit(1)
    
    # Start web interface directly
    start_web_interface()

if __name__ == "__main__":
    main()
