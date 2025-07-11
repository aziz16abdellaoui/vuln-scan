#!/usr/bin/env python3
"""
Email Crawler Module
Handles email discovery from web pages
"""

import re
import requests
from urllib.parse import urljoin, urlparse
import time
from datetime import datetime

class EmailCrawler:
    def __init__(self, max_depth=1, delay=0, max_links_per_page=3, timeout=1):
        self.max_depth = max_depth  # Keep shallow
        self.delay = delay  # No delay for speed
        self.max_links_per_page = max_links_per_page  # Fewer links for speed  
        self.timeout = timeout  # Ultra-fast timeout
        self.email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    
    def extract_emails_from_text(self, text):
        """Extract email addresses from text"""
        return set(re.findall(self.email_pattern, text))
    
    def is_internal_link(self, base_url, link):
        """Check if link is internal to the domain"""
        base_domain = urlparse(base_url).netloc
        link_domain = urlparse(link).netloc
        return (link_domain == "" or link_domain == base_domain)
    
    def crawl(self, target):
        """
        Crawl target website for email addresses
        Returns dict with email results and timing
        """
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        start_url = f"http://{target}"
        
        visited_urls = set()
        emails_found = set()
        urls_to_visit = [(start_url, 0)]
        
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; EmailCrawler/1.0; +https://github.com/)",
            "Connection": "keep-alive"
        }
        
        try:
            # Use a session to reuse connections
            with requests.Session() as session:
                session.headers.update(headers)
                session.timeout = self.timeout
                
                while urls_to_visit:
                    current_batch = []
                    # Process only 2 URLs at once for speed
                    while urls_to_visit and len(current_batch) < 2:
                        current_batch.append(urls_to_visit.pop(0))

                    for url, depth in current_batch:
                        if url in visited_urls or depth > self.max_depth:
                            continue
                        
                        try:
                            response = session.get(url, timeout=self.timeout)
                            response.raise_for_status()
                            visited_urls.add(url)

                            # Extract emails on this page
                            new_emails = self.extract_emails_from_text(response.text)
                            emails_found.update(new_emails)

                            # Only crawl deeper if we haven't found many emails yet
                            if depth < self.max_depth and len(emails_found) < 5:
                                links = re.findall(r'href=["\'](.*?)["\']', response.text, re.IGNORECASE)
                                count = 0
                                for link in links:
                                    if count >= self.max_links_per_page:
                                        break
                                    absolute_link = urljoin(url, link)
                                    if self.is_internal_link(start_url, absolute_link):
                                        urls_to_visit.append((absolute_link, depth + 1))
                                        count += 1

                        except Exception as e:
                            continue

                    # Small delay between batches
                    time.sleep(self.delay)
            
            status = "completed"
            
        except Exception as e:
            status = "error"
        
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        emails_list = list(emails_found) if emails_found else ["No emails found"]
        
        return {
            "emails_found": emails_list,
            "count": len([e for e in emails_list if e != "No emails found"]),
            "status": status,
            "execution_time": {"start": start_time, "end": end_time},
            "target": target
        }

def main():
    """Test the Email Crawler"""
    crawler = EmailCrawler()
    result = crawler.crawl("example.com")
    print(f"Email crawl result: {result['status']}")
    print(f"Emails found: {result['count']}")
    print(f"Emails: {result['emails_found']}")

if __name__ == "__main__":
    main()
