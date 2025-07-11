#!/usr/bin/env python3
"""
Configuration Management for Vulnerability Scanner
Centralized settings for all scanner modules
"""

import os

class ScannerConfig:
    """Central configuration for all scanner components"""
    
    # Core settings - OPTIMIZED FOR SPEED
    DEFAULT_TIMEOUT = 15  # Reduced from 45
    DEFAULT_THREADS = 50  # Increased from 20
    DEFAULT_RATE_LIMIT = 300  # Increased from 150
    
    # Nuclei settings - ULTRA FAST
    NUCLEI_TIMEOUT = 20  # Reduced from 45
    NUCLEI_RATE_LIMIT = 300  # Increased from 150
    NUCLEI_MAX_HOST_ERROR = 10  # Reduced from 20
    NUCLEI_CONCURRENCY = 100  # Increased from 50
    
    # Gobuster settings - LIGHTNING FAST
    GOBUSTER_TIMEOUT = 15  # Reduced from 40
    GOBUSTER_THREADS = 50  # Increased from 20
    GOBUSTER_REQUEST_TIMEOUT = "3s"  # Reduced from "10s"
    
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
    
    # Scan profiles - ULTRA SPEED OPTIMIZED
    SCAN_PROFILES = {
        'quick': {
            'nuclei_timeout': 5,  # Ultra fast - 5 seconds max
            'nuclei_phases': ['Critical Security Checks'],
            'enable_gobuster': False,  # Skip for maximum speed
            'enable_subfinder': False,  # Skip for maximum speed
            'enable_email_crawler': False,
            'enable_pwned_checker': False,
            'enable_nmap': False,  # Skip Nmap for ultra speed
            'enable_http_analyzer': True,  # Keep this for quick security headers check
            'description': 'Lightning fast scan (5-10s) - Critical vulnerabilities only'
        },
        'standard': {
            'nuclei_timeout': 10,  # Fast but thorough
            'nuclei_phases': ['Critical Security Checks'],
            'enable_gobuster': True,
            'enable_subfinder': False,  # Skip subfinder for speed
            'enable_email_crawler': False,  # Skip for speed
            'enable_pwned_checker': False,  # Skip for speed
            'enable_nmap': True,  # Include basic port scan
            'enable_http_analyzer': True,
            'description': 'Fast scan (15-25s) - Core vulnerabilities'
        },
        'comprehensive': {
            'nuclei_timeout': 30,  # Reduced from 45 for better speed
            'nuclei_phases': ['Critical Security Checks', 'High-Impact Vulnerabilities'],
            'enable_gobuster': True,
            'enable_subfinder': True,
            'enable_email_crawler': True,
            'enable_pwned_checker': True,
            'enable_nmap': True,
            'enable_http_analyzer': True,
            'description': 'Complete scan (45-60s) - Full coverage'
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
