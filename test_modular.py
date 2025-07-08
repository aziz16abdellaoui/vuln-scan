#!/usr/bin/env python3
"""
Test Script for Modular Vulnerability Scanner
Tests individual modules and the main orchestrator
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add the project directory to Python path
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)
sys.path.insert(0, os.path.join(project_dir, 'tools'))

# Import modules to test
try:
    from tools.nmap_scanner import NmapScanner
    from tools.subfinder_scanner import SubfinderScanner
    from tools.gobuster_scanner import GobusterScanner
    from tools.email_crawler import EmailCrawler
    from tools.pwned_checker import PwnedChecker
    from tools.nuclei_scanner import NucleiScanner
    from tools.http_analyzer import HTTPAnalyzer
    from tools.vulnerability_scorer import VulnerabilityScorer
    from main_scanner import VulnerabilityScanner
    print("✓ All modules imported successfully")
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)

class TestModularScanner(unittest.TestCase):
    """Test cases for the modular vulnerability scanner"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_target = "scanme.nmap.org"
        self.test_ip = "127.0.0.1"
    
    def test_nmap_scanner_creation(self):
        """Test that NmapScanner can be instantiated"""
        scanner = NmapScanner()
        self.assertIsNotNone(scanner)
        print("✓ NmapScanner instantiation test passed")
    
    def test_subfinder_scanner_creation(self):
        """Test that SubfinderScanner can be instantiated"""
        scanner = SubfinderScanner()
        self.assertIsNotNone(scanner)
        print("✓ SubfinderScanner instantiation test passed")
    
    def test_gobuster_scanner_creation(self):
        """Test that GobusterScanner can be instantiated"""
        scanner = GobusterScanner()
        self.assertIsNotNone(scanner)
        print("✓ GobusterScanner instantiation test passed")
    
    def test_email_crawler_creation(self):
        """Test that EmailCrawler can be instantiated"""
        crawler = EmailCrawler()
        self.assertIsNotNone(crawler)
        print("✓ EmailCrawler instantiation test passed")
    
    def test_http_analyzer_creation(self):
        """Test that HTTPAnalyzer can be instantiated"""
        analyzer = HTTPAnalyzer()
        self.assertIsNotNone(analyzer)
        print("✓ HTTPAnalyzer instantiation test passed")
    
    def test_vulnerability_scorer_creation(self):
        """Test that VulnerabilityScorer can be instantiated"""
        scorer = VulnerabilityScorer()
        self.assertIsNotNone(scorer)
        print("✓ VulnerabilityScorer instantiation test passed")
    
    def test_main_scanner_creation(self):
        """Test that VulnerabilityScanner (main orchestrator) can be instantiated"""
        scanner = VulnerabilityScanner()
        self.assertIsNotNone(scanner)
        print("✓ Main VulnerabilityScanner instantiation test passed")
    
    def test_vulnerability_scorer_scoring(self):
        """Test vulnerability scoring functionality"""
        scorer = VulnerabilityScorer()
        
        # Test data - vulnerability scorer expects strings, not dicts
        vulnerabilities = [
            'Missing security header',
            'SQL Injection vulnerability',
            'XSS vulnerability'
        ]
        nuclei_findings = [
            {'severity': 'high', 'template-id': 'sql-injection-test'}
        ]
        scan_results = {
            'open_ports': [{'port': 22, 'protocol': 'tcp', 'service': 'ssh'}]
        }
        
        result = scorer.calculate_score(vulnerabilities, nuclei_findings, scan_results)
        self.assertIsInstance(result, dict)
        self.assertIn('score', result)
        self.assertIn('grade', result)
        
        score = result['score']
        self.assertIsInstance(score, (int, float))
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        print(f"✓ Vulnerability scoring test passed (score: {score}, grade: {result['grade']})")
    
    @patch('requests.get')
    def test_http_analyzer_mock(self, mock_get):
        """Test HTTP analyzer with mocked response"""
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'nginx/1.18.0',
            'Content-Type': 'text/html'
        }
        mock_response.text = '<html><title>Test</title></html>'
        mock_get.return_value = mock_response
        
        analyzer = HTTPAnalyzer()
        result = analyzer.analyze("http://example.com")
        
        self.assertIsInstance(result, dict)
        self.assertIn('headers', result)
        self.assertIn('vulnerabilities', result)
        print("✓ HTTP analyzer mock test passed")

def run_basic_tests():
    """Run basic functionality tests"""
    print("Running Modular Vulnerability Scanner Tests...")
    print("=" * 50)
    
    # Run the unit tests
    unittest.main(argv=[''], exit=False, verbosity=0)
    
    print("\n" + "=" * 50)
    print("Basic tests completed!")
    
    # Test that we can import and create the main scanner
    try:
        scanner = VulnerabilityScanner()
        print("✓ Main scanner created successfully")
        
        # Test the available tools
        available_tools = [
            'nmap', 'subfinder', 'gobuster',
            'email_crawler', 'pwned_checker', 'nuclei',
            'http_analyzer', 'scorer'
        ]
        
        for tool in available_tools:
            if tool in scanner.scanners:
                print(f"✓ {tool} is available")
            else:
                print(f"✗ {tool} is missing")
        
    except Exception as e:
        print(f"✗ Error creating main scanner: {e}")
    
    print("\nTo run a full scan test, use:")
    print("python main_scanner.py --target scanme.nmap.org")

if __name__ == "__main__":
    run_basic_tests()
