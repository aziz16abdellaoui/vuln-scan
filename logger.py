#!/usr/bin/env python3
"""
Logging and Error Handling Module
Centralized logging for the vulnerability scanner
"""

import logging
import os
from datetime import datetime

class ScannerLogger:
    """Centralized logging for scanner operations"""
    
    def __init__(self, log_level=logging.INFO):
        self.log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Create timestamped log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(self.log_dir, f'scanner_{timestamp}.log')
        
        # Configure logger
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()  # Also log to console
            ]
        )
        
        self.logger = logging.getLogger('VulnScanner')
        self.logger.info("Scanner logging initialized")
    
    def info(self, message, target=None):
        """Log info message"""
        if target:
            message = f"[{target}] {message}"
        self.logger.info(message)
    
    def warning(self, message, target=None):
        """Log warning message"""
        if target:
            message = f"[{target}] {message}"
        self.logger.warning(message)
    
    def error(self, message, target=None, exception=None):
        """Log error message"""
        if target:
            message = f"[{target}] {message}"
        if exception:
            message = f"{message} - Exception: {str(exception)}"
        self.logger.error(message)
    
    def debug(self, message, target=None):
        """Log debug message"""
        if target:
            message = f"[{target}] {message}"
        self.logger.debug(message)

class ErrorHandler:
    """Centralized error handling"""
    
    @staticmethod
    def handle_scan_error(error, target, module_name, logger=None):
        """Handle scanner module errors gracefully"""
        error_message = f"{module_name} error for {target}: {str(error)}"
        
        if logger:
            logger.error(error_message, target, error)
        else:
            print(f"❌ {error_message}")
        
        return {
            "status": "error",
            "error": str(error),
            "module": module_name,
            "target": target,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    @staticmethod
    def handle_timeout_error(target, module_name, timeout_duration, logger=None):
        """Handle timeout errors"""
        error_message = f"{module_name} timed out after {timeout_duration}s for {target}"
        
        if logger:
            logger.warning(error_message, target)
        else:
            print(f"⏱️ {error_message}")
        
        return {
            "status": "timeout",
            "module": module_name,
            "target": target,
            "timeout": timeout_duration,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

# Global logger instance
_logger_instance = None

def get_logger():
    """Get global logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = ScannerLogger()
    return _logger_instance
