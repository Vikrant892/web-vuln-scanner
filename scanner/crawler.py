# For educational and authorized testing ONLY
# bfs web crawler - grabs links and forms from the target
# stays on the same domain, doesn't go wandering off

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import time
import urllib3

# shut up the ssl warnings, we know what we're doing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


class Crawler:
    def __init__(self, target_url, max_depth=3, max_pages=100):
        self.target_url = target_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.urls = []
        self.forms = []
        self.domain = urlparse(target_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })

    def is_same_domain(self, url):
        """check if url is on the same domain - don't want to crawl the whole internet lol"""
        try:
            return urlparse(url).netloc == self.domain
        except Exception:
            return False

    def normalize_url(self, url):
        """clean up urls so we don't visit the same page twice"""
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized.rstrip("/")

    def extract_links(self, url, soup):
        """pull all <a href> links from a page"""
        links = set()
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full_url = urljoin(url, href)
            full_url = self.normalize_url(full_url)
            if self.is_same_domain(full_url) and full_url not in self.visited:
                links.add(full_url)
        return links

    def extract_forms(self, url, soup):
        """grab all forms from a page - need these for xss and sqli testing"""
        page_forms = []
        for form in soup.find_all("form"):
            form_data = {
                "url": url,
                "action": urljoin(url, form.get("action", "")),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }
            # get all the input fields
            for inp in form.find_all(["input", "textarea", "select"]):
                input_data = {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                }
                if input_data["name"]:  # skip nameless inputs, they're useless
                    form_data["inputs"].append(input_data)
            page_forms.append(form_data)
        return page_forms

    def crawl(self):
        """
        BFS crawl starting from target url.
        goes through each page, grabs links, follows them up to max_depth.
        returns discovered urls and forms for the scanners to use.
        """
        print(f"\n{BLUE}[*] Starting BFS crawl on {self.target_url}{RESET}")
        print(f"    Max depth: {self.max_depth}, Max pages: {self.max_pages}")

        queue = deque()
        queue.append((self.target_url, 0))
        self.visited.add(self.target_url)

        while queue and len(self.urls) < self.max_pages:
            current_url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            try:
                resp = self.session.get(current_url, timeout=10,
                                       verify=False, allow_redirects=True)

                # only care about html pages
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    continue

                self.urls.append({
                    "url": current_url,
                    "status": resp.status_code,
                    "depth": depth,
                })

                soup = BeautifulSoup(resp.text, "html.parser")

                # get forms for injection testing later
                forms = self.extract_forms(current_url, soup)
                self.forms.extend(forms)

                # discover new links and add to queue
                links = self.extract_links(current_url, soup)
                for link in links:
                    if link not in self.visited:
                        self.visited.add(link)
                        queue.append((link, depth + 1))

                print(f"    {GREEN}[+]{RESET} Crawled: {current_url} (depth={depth}, links={len(links)})")

                # be nice, don't hammer the server too hard
                time.sleep(0.3)

            except requests.exceptions.Timeout:
                print(f"    {YELLOW}[!]{RESET} Timeout: {current_url}")
            except requests.exceptions.ConnectionError:
                print(f"    {RED}[-]{RESET} Connection failed: {current_url}")
            except Exception as e:
                print(f"    {RED}[-]{RESET} Error crawling {current_url}: {str(e)}")

        print(f"\n{BLUE}[*] Crawl finished. Found {len(self.urls)} pages, {len(self.forms)} forms{RESET}\n")

        return {
            "urls": self.urls,
            "forms": self.forms,
            "total_pages": len(self.urls),
            "total_forms": len(self.forms),
        }
