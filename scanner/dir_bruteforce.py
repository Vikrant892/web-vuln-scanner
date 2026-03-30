# For educational and authorized testing ONLY
# directory bruteforce - tries common paths and reports what exists
# checks for 200, 301, 403 responses
# basically a poor mans gobuster/dirbuster

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import time


RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

# status codes that mean something is there
INTERESTING_CODES = {
    200: "OK",
    301: "Moved Permanently",
    302: "Found (redirect)",
    307: "Temporary Redirect",
    401: "Unauthorized (auth required!)",
    403: "Forbidden (exists but blocked)",
}


class DirBruteforcer:
    def __init__(self, session=None, threads=10):
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.threads = threads
        self.findings = []
        self.wordlist = self._load_wordlist()

    def _load_wordlist(self):
        """load directory wordlist from file"""
        wordlist_file = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                     "wordlists", "common_dirs.txt")
        try:
            with open(wordlist_file, "r") as f:
                dirs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            print(f"    Loaded {len(dirs)} directories to test")
            return dirs
        except FileNotFoundError:
            print(f"    {RED}[-]{RESET} Wordlist not found, using minimal default list")
            return ["admin", "login", "api", "backup", ".git", ".env", "wp-admin", "dashboard"]

    def _check_path(self, base_url, path):
        """check if a single path exists on the target"""
        url = f"{base_url.rstrip('/')}/{path}"
        try:
            resp = self.session.get(url, timeout=8, verify=False,
                                   allow_redirects=False)
            status = resp.status_code

            if status in INTERESTING_CODES:
                return {
                    "path": path,
                    "url": url,
                    "status": status,
                    "status_text": INTERESTING_CODES[status],
                    "length": len(resp.content),
                }
            return None

        except requests.exceptions.Timeout:
            return None
        except Exception:
            return None

    def scan(self, target_url):
        """
        bruteforce directories using threadpool
        tries each path from the wordlist and reports interesting responses
        """
        print(f"\n{BLUE}[*] Starting directory bruteforce on {target_url}{RESET}")
        print(f"    Threads: {self.threads}, Wordlist size: {len(self.wordlist)}")

        found_paths = []
        tested = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for path in self.wordlist:
                future = executor.submit(self._check_path, target_url, path)
                futures[future] = path

            for future in as_completed(futures):
                tested += 1
                result = future.result()

                if result:
                    found_paths.append(result)
                    status = result["status"]

                    # color based on status code
                    if status == 200:
                        color = GREEN
                    elif status in [301, 302, 307]:
                        color = CYAN
                    elif status == 401:
                        color = YELLOW
                    elif status == 403:
                        color = RED
                    else:
                        color = RESET

                    print(f"    {color}[{status}]{RESET} /{result['path']:<30} {result['status_text']:<25} ({result['length']} bytes)")

                    # determine severity based on what we found
                    severity = "LOW"
                    if result["path"] in [".git", ".env", ".git/config", "backup", ".htaccess", ".svn"]:
                        severity = "HIGH"  # these really shouldn't be accessible
                    elif status in [200, 401] and result["path"] in ["admin", "phpmyadmin", "wp-admin", "dashboard"]:
                        severity = "MEDIUM"

                    self.findings.append({
                        "type": "Directory/File Found",
                        "severity": severity,
                        "url": result["url"],
                        "parameter": f"/{result['path']}",
                        "payload": "N/A",
                        "method": "GET",
                        "evidence": f"HTTP {status} - {result['status_text']} ({result['length']} bytes)",
                        "description": f"Discovered path /{result['path']} with status {status}",
                    })

                # progress indicator every 20 paths
                if tested % 20 == 0:
                    print(f"    ... tested {tested}/{len(self.wordlist)} paths", end="\r")

        print(f"\n\n{BLUE}[*] Directory scan complete.{RESET}")
        print(f"    Tested: {tested} paths, Found: {len(found_paths)} interesting responses")

        if self.findings:
            high_sev = [f for f in self.findings if f["severity"] in ["HIGH", "CRITICAL"]]
            if high_sev:
                print(f"    {RED}{BOLD}[!] {len(high_sev)} sensitive paths exposed!{RESET}")
        print()

        return self.findings
