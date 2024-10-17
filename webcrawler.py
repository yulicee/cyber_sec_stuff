import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import os
import threading
from urllib.robotparser import RobotFileParser

def can_fetch(url, user_agent='*'):
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    rp = RobotFileParser()
    rp.set_url(urljoin(base_url, '/robots.txt'))
    rp.read()
    return rp.can_fetch(user_agent, url)

def crawl(url, max_depth=2, delay=1):
    visited = set()  
    lock = threading.Lock()

    def _crawl(current_url, depth):
        if depth > max_depth or current_url in visited:
            return

        with lock:
            print(f"Crawling: {current_url} at depth {depth}")
            visited.add(current_url)

        if not can_fetch(current_url):
            print(f"Access denied by robots.txt for {current_url}")
            return

        try:
            response = requests.get(current_url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Failed to retrieve {current_url}: {e}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')

        with lock:
            with open("crawled_links.txt", "a") as file:
                file.write(current_url + "\n")

        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full_url = urljoin(current_url, href)
            if full_url not in visited:
                time.sleep(delay) 
                _crawl(full_url, depth + 1)

    threads = []
    for i in range(5):  
        t = threading.Thread(target=_crawl, args=(url, 0))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

if __name__ == "__main__":
    start_url = input("Bitte geben Sie die Start-URL ein: ")
    
    if not start_url.startswith(('http://', 'https://')):
        start_url = 'https://' + start_url

    max_depth = int(input("Bitte geben Sie die maximale Tiefe ein: "))
    delay = float(input("Bitte geben Sie die Verzögerung zwischen den Anfragen in Sekunden ein: "))

    if os.path.exists("crawled_links.txt"):
        os.remove("crawled_links.txt")

    crawl(start_url, max_depth, delay)
