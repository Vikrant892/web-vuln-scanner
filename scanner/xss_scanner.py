# For educational and authorized testing ONLY
# reflected xss scanner - injects payloads into params and forms
# checks if they get reflected back in the response
# this only does reflected xss, stored/dom-based is way more complex

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import os
import time


RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


class XSSScanner:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []
        self.payloads = self._load_payloads()

    def _load_payloads(self):
        """load xss payloads from the payloads file"""
        payload_file = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                    "payloads", "xss_payloads.txt")
        try:
            with open(payload_file, "r") as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            print(f"    Loaded {len(payloads)} XSS payloads")
            return payloads
        except FileNotFoundError:
            print(f"    {RED}[-]{RESET} Payload file not found, using builtin defaults")
            return [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                "'-alert(1)-'",
                '<img src=x onerror=alert(1)>',
            ]

    def scan_url_params(self, url):
        """inject xss payloads into each GET parameter and see if they reflect back"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return  # nothing to test

        print(f"\n    {BLUE}[*]{RESET} Testing URL params: {url}")

        for param_name in params:
            for payload in self.payloads:
                test_params = dict(params)
                test_params[param_name] = [payload]

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                try:
                    resp = self.session.get(test_url, timeout=10,
                                           verify=False, allow_redirects=True)

                    # if our payload shows up in the response, thats a hit
                    if payload in resp.text:
                        finding = {
                            "type": "XSS",
                            "severity": "HIGH",
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "method": "GET",
                            "evidence": "Payload reflected in response body",
                            "description": f'Reflected XSS in parameter "{param_name}"',
                        }
                        self.findings.append(finding)
                        print(f"    {RED}{BOLD}[!] XSS FOUND{RESET} - param: {param_name}, payload: {payload[:50]}")
                        break  # confirmed, next param

                    time.sleep(0.2)

                except Exception:
                    pass  # network stuff happens

    def scan_forms(self, forms):
        """inject xss payloads into form inputs, handles GET and POST"""
        for form in forms:
            if not form["inputs"]:
                continue

            print(f"\n    {BLUE}[*]{RESET} Testing form: {form['action']} ({form['method'].upper()})")

            for payload in self.payloads:
                # shove the payload into every text-like field
                form_data = {}
                for inp in form["inputs"]:
                    if inp["type"] in ["text", "search", "email", "url", "tel", "textarea", "hidden", "password"]:
                        form_data[inp["name"]] = payload
                    else:
                        form_data[inp["name"]] = inp.get("value", "")

                if not form_data:
                    continue

                try:
                    if form["method"] == "post":
                        resp = self.session.post(form["action"], data=form_data,
                                                timeout=10, verify=False, allow_redirects=True)
                    else:
                        resp = self.session.get(form["action"], params=form_data,
                                               timeout=10, verify=False, allow_redirects=True)

                    if payload in resp.text:
                        finding = {
                            "type": "XSS",
                            "severity": "HIGH",
                            "url": form["action"],
                            "parameter": ", ".join(form_data.keys()),
                            "payload": payload,
                            "method": form["method"].upper(),
                            "evidence": "Payload reflected after form submission",
                            "description": f"Reflected XSS via form at {form['url']}",
                        }
                        self.findings.append(finding)
                        print(f"    {RED}{BOLD}[!] XSS FOUND{RESET} - form: {form['action']}")
                        break

                    time.sleep(0.2)

                except Exception:
                    pass

    def scan(self, crawl_results):
        """main entry point - test everything we found during crawling"""
        print(f"\n{BLUE}[*] Starting XSS scan...{RESET}")

        # test url parameters first
        for page in crawl_results["urls"]:
            self.scan_url_params(page["url"])

        # then test forms
        if crawl_results["forms"]:
            print(f"\n    Testing {len(crawl_results['forms'])} forms for XSS...")
            self.scan_forms(crawl_results["forms"])

        if self.findings:
            print(f"\n{RED}[!] Found {len(self.findings)} potential XSS vulnerabilities{RESET}\n")
        else:
            print(f"\n{GREEN}[+] No XSS vulnerabilities found{RESET}\n")

        return self.findings
