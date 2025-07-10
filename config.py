#!/usr/bin/env python3
"""
Configuration Management for Vulnerability Scanner
Centralized settings for all scanner modules
"""

import os

class ScannerConfig:
    """Central configuration for all scanner components"""
    
    # Core settings
    DEFAULT_TIMEOUT = 45
    DEFAULT_THREADS = 20
    DEFAULT_RATE_LIMIT = 150
    
    # Nuclei settings
    NUCLEI_TIMEOUT = 45
    NUCLEI_RATE_LIMIT = 150
    NUCLEI_MAX_HOST_ERROR = 20
    NUCLEI_CONCURRENCY = 50
    
    # Gobuster settings
    GOBUSTER_TIMEOUT = 40
    GOBUSTER_THREADS = 20
    GOBUSTER_REQUEST_TIMEOUT = "10s"
    
    # Web interface settings
    WEB_PORT_START = 5000
    WEB_PORT_MAX_ATTEMPTS = 10
    POLL_TIMEOUT = 180  # 3 minutes
    
    # File paths
    @staticmethod
    def get_wordlist_path():
        """Get default wordlist path"""
        return os.path.join(os.path.dirname(__file__), 'wordlist_common.txt')
    
    @staticmethod
    def get_output_dir():
        """Get default output directory"""
        return os.path.join(os.path.dirname(__file__), 'scan_results')
    
    # Scan profiles
    SCAN_PROFILES = {
        'quick': {
            'nuclei_timeout': 30,
            'nuclei_phases': ['Essential Security Checks'],
            'enable_gobuster': True,
            'enable_subfinder': True,
            'description': 'Fast scan for basic vulnerabilities'
        },
        'standard': {
            'nuclei_timeout': 45,
            'nuclei_phases': ['Essential Security Checks', 'Technology Detection', 'Critical CVEs'],
            'enable_gobuster': True,
            'enable_subfinder': True,
            'description': 'Balanced scan with good coverage'
        },
        'comprehensive': {
            'nuclei_timeout': 90,
            'nuclei_phases': ['Essential Security Checks', 'Technology Detection', 'Critical CVEs', 'Service-Specific'],
            'enable_gobuster': True,
            'enable_subfinder': True,
            'enable_ssl_scan': True,
            'enable_api_scan': True,
            'description': 'Deep scan with maximum coverage'
        }
    }
    
    # Security scoring weights
    VULNERABILITY_WEIGHTS = {
        'critical': 25,
        'high': 15,
        'medium': 8,
        'low': 3,
        'info': 1
    }
    
    # Template categories for Nuclei
    NUCLEI_TEMPLATES = {
        'essential': ['http/exposures/', 'http/misconfiguration/'],
        'technology': ['http/technologies/'],
        'cves': ['http/cves/2024/', 'http/vulnerabilities/'],
        'network': ['network/'],
        'dns': ['dns/'],
        'ssl': ['ssl/']
    }

def get_config():
    """Get scanner configuration instance"""
    return ScannerConfig()
