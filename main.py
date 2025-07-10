#!/usr/bin/env python3
"""
Main Entry Point for Modular Vulnerability Scanner
This file starts the web interface automatically
Run with: python main.py or python3 main.py
Author: Mohamed Aziz Abdellaoui
"""

# Import needed libraries for the main program
import os
import sys
import subprocess
import time
from datetime import datetime

def print_startup_banner():
    """Show a nice banner when program starts"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    🔥 MODULAR VULNERABILITY SCANNER 🔥                               ║
║                                                                      ║
║    Starting User-Friendly Web Interface...                           ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def check_dependencies():
    """Check if all required libraries and files are installed"""
    print("🔍 Checking dependencies...")
    
    # List of Python libraries we need for the scanner
    python_deps = ['flask', 'requests', 'selenium']
    missing_python = []
    
    # Check each Python library one by one
    for dep in python_deps:
        try:
            __import__(dep)  # Try to import the library
            print(f"✓ Python: {dep}")
        except ImportError:
            missing_python.append(dep)  # Add to missing list if not found
            print(f"✗ Python: {dep}")
    
    # Check if important project files exist
    required_files = ['app_modular.py', 'tools/nmap_scanner.py']
    missing_files = []
    
    # Make sure all important files are in the project
    for file in required_files:
        if os.path.exists(file):
            print(f"✓ File: {file}")
        else:
            missing_files.append(file)  # Add missing file to our list
            print(f"✗ File: {file}")
    
    # If something is missing, show a warning message
    if missing_python or missing_files:
        print("\n⚠️  Missing dependencies detected!")
        if missing_python:
            print(f"   Install Python packages: pip3 install {' '.join(missing_python)}")
        if missing_files:
            print(f"   Missing files: {', '.join(missing_files)}")
        print()
        return False  # Return error status
    else:
        print("✅ All dependencies are available!")
        print()
        return True  # Everything is ready to go

def start_web_interface():
    """Start the web interface and show user instructions"""
    print("🌐 Starting User-Friendly Web Interface...")
    print()
    print("📌 Once started:")
    print("   🌐 Open your browser")
    print("   🔗 Go to the URL that will be shown below")
    print("   🎯 Enter a target domain (e.g., scanme.nmap.org)")
    print("   ▶️  Click 'Start Scan'")
    print("   📊 Watch real-time progress")
    print("   💾 Download reports when complete")
    print()
    print("🛑 Press Ctrl+C to stop the server")
    print("=" * 60)
    print("⏳ Starting web server...")
    
    try:
        # Run the Flask web application
        subprocess.run([sys.executable, "app_modular.py"])
    except KeyboardInterrupt:
        print("\n🛑 Web server stopped by user")
        print("👋 Thank you for using the Modular Vulnerability Scanner!")
    except FileNotFoundError:
        print("❌ Error: app_modular.py not found")
        print("💡 Make sure you're in the correct directory")
    except Exception as e:
        print(f"❌ Error starting web interface: {e}")
        print("💡 Try running directly: python3 app_modular.py")

def main():
    """Main function - this starts everything"""
    # Change to the script directory so files can be found
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Clear the terminal screen for better display
    os.system('clear' if os.name == 'posix' else 'cls')
    
    print_startup_banner()  # Show the welcome banner
    
    # Check if all dependencies are installed
    deps_ok = check_dependencies()
    
    # If dependencies are missing, exit with error message
    if not deps_ok:
        print("❌ Cannot start - missing dependencies")
        print("\n💡 To install missing Python dependencies:")
        print("   pip3 install -r requirements.txt")
        print("\n💡 For help, see: HOW_TO_RUN.md")
        sys.exit(1)
    
    # Parse command line arguments
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] == "web"):
        # No arguments or 'web' argument: start web interface
        start_web_interface()
    elif len(sys.argv) >= 3 and sys.argv[1] == "cli":
        # CLI mode: run scan on command line
        target = sys.argv[2]
        print(f"🎯 Starting CLI scan of: {target}")
        print("=" * 60)
        
        # Import and run the main scanner
        from main_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner()
        scanner.scan_target(target)
        
        print("=" * 60)
        print("✅ Scan completed! Check scan_results/ directory for reports.")
    else:
        # Invalid arguments: show usage
        print("❌ Invalid arguments")
        print("\nUsage:")
        print("  python main.py              # Start web interface")
        print("  python main.py web          # Start web interface")
        print("  python main.py cli <target> # Run CLI scan")
        print("\nExamples:")
        print("  python main.py web")
        print("  python main.py cli scanme.nmap.org")
        sys.exit(1)

# This runs when the script is executed directly
if __name__ == "__main__":
    main()  # Call the main function to start everything
