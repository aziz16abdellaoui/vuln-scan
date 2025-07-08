#!/usr/bin/env python3
"""
HaveIBeenPwned Checker Module
Handles checking if emails have been in data breaches
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
from datetime import datetime

class PwnedChecker:
    def __init__(self, timeout=8, max_emails=3):
        self.timeout = timeout
        self.max_emails = max_emails
    
    def setup_driver(self):
        """Setup Firefox driver for headless browsing"""
        options = webdriver.FirefoxOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-logging")
        
        driver = webdriver.Firefox(options=options)
        wait = WebDriverWait(driver, self.timeout)
        return driver, wait
    
    def check_single_email(self, email, driver, wait):
        """Check if a single email has been pwned"""
        try:
            driver.get("https://haveibeenpwned.com/")
            search_box = wait.until(EC.presence_of_element_located((By.ID, "emailInput")))
            search_box.clear()
            search_box.send_keys(email)
            search_box.send_keys(Keys.RETURN)

            # Wait for results with reduced timeout
            try:
                wait.until(
                    EC.any_of(
                        EC.presence_of_element_located((By.ID, "breaches")),
                        EC.text_to_be_present_in_element((By.TAG_NAME, "body"), "Good news")
                    ),
                    timeout=5
                )
                
                body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
                
                if "pwned" in body_text:
                    return {"email": email, "pwned": True, "status": "found"}
                else:
                    return {"email": email, "pwned": False, "status": "clean"}
                    
            except Exception:
                return {"email": email, "pwned": None, "status": "timeout"}
                
        except Exception as e:
            return {"email": email, "pwned": None, "status": "error"}
    
    def check_emails(self, emails):
        """
        Check multiple emails for breaches
        Returns dict with breach results and timing
        """
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if not emails or emails == ["No emails found"]:
            return {
                "pwned_emails": [],
                "count": 0,
                "status": "skipped",
                "execution_time": {"start": start_time, "end": start_time},
                "results": [],
                "message": "No emails to check"
            }
        
        # Limit emails to check
        limited_emails = list(emails)[:self.max_emails]
        pwned_emails = []
        results = []
        
        try:
            driver, wait = self.setup_driver()
            
            for email in limited_emails:
                result = self.check_single_email(email, driver, wait)
                results.append(result)
                
                if result["pwned"]:
                    pwned_emails.append(email)
                
                # Small delay between checks
                time.sleep(0.5)
            
            driver.quit()
            status = "completed"
            
        except Exception as e:
            status = "error"
            if 'driver' in locals():
                try:
                    driver.quit()
                except:
                    pass
        
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return {
            "pwned_emails": pwned_emails,
            "count": len(pwned_emails),
            "status": status,
            "execution_time": {"start": start_time, "end": end_time},
            "results": results,
            "emails_checked": limited_emails
        }

def main():
    """Test the Pwned Checker"""
    checker = PwnedChecker()
    test_emails = ["test@example.com"]
    result = checker.check_emails(test_emails)
    print(f"Pwned check result: {result['status']}")
    print(f"Pwned emails found: {result['count']}")
    print(f"Results: {result['results']}")

if __name__ == "__main__":
    main()
