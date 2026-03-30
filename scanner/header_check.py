# For educational and authorized testing ONLY
# security headers checker
# grades the target A through F based on owasp recommended headers
# honestly this is the easiest check but also one of the most useful
# so many sites just forget to set these

import requests

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"

# headers we care about and why
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "severity": "HIGH",
        "recommendation": "Implement a CSP header. Start with report-only mode if unsure.",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still helps on old browsers)",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access (camera, mic, geolocation)",
        "severity": "LOW",
        "recommendation": "Add Permissions-Policy header to restrict feature access",
    },
}

# headers that probably shouldn't be exposed
BAD_HEADERS = {
    "Server": "Reveals web server software and version",
    "X-Powered-By": "Reveals backend technology (PHP, ASP.NET, Express, etc)",
    "X-AspNet-Version": "Reveals ASP.NET version",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
}


class HeaderChecker:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []

    def check_security_headers(self, url):
        """check which security headers are present and which are missing"""
        try:
            resp = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
        except Exception as e:
            print(f"    {RED}[-]{RESET} Failed to connect: {str(e)}")
            return []

        response_headers = {k.lower(): v for k, v in resp.headers.items()}

        print(f"\n    {'Header':<35} {'Status':<10} {'Severity'}")
        print(f"    {'─' * 35} {'─' * 10} {'─' * 10}")

        for header, info in SECURITY_HEADERS.items():
            if header.lower() in response_headers:
                print(f"    {header:<35} {GREEN}{'PRESENT':<10}{RESET} -")
            else:
                severity = info["severity"]
                # color by severity
                if severity == "HIGH":
                    color = RED
                elif severity == "MEDIUM":
                    color = YELLOW
                else:
                    color = BLUE
                print(f"    {header:<35} {RED}{'MISSING':<10}{RESET} {color}{severity}{RESET}")

                self.findings.append({
                    "type": "Missing Security Header",
                    "severity": info["severity"],
                    "url": url,
                    "parameter": header,
                    "payload": "N/A",
                    "method": "N/A",
                    "evidence": f'Header "{header}" not found in response',
                    "description": f'{info["description"]}. {info["recommendation"]}',
                })

        return self.findings

    def check_info_disclosure(self, url):
        """check for headers that leak server info - you'd be surprised how common this is"""
        try:
            resp = self.session.get(url, timeout=10, verify=False)
        except Exception:
            return []

        response_headers = {k: v for k, v in resp.headers.items()}

        print(f"\n    Checking for information disclosure headers...")

        for header, description in BAD_HEADERS.items():
            for resp_header, value in response_headers.items():
                if resp_header.lower() == header.lower():
                    self.findings.append({
                        "type": "Information Disclosure",
                        "severity": "LOW",
                        "url": url,
                        "parameter": resp_header,
                        "payload": "N/A",
                        "method": "N/A",
                        "evidence": f"{resp_header}: {value}",
                        "description": f"{description}. Consider removing this header.",
                    })
                    print(f"    {YELLOW}[!]{RESET} {resp_header}: {value} - {description}")

        return self.findings

    def calculate_grade(self):
        """
        rough grading system A through F
        based on how many important headers are missing
        real tools like securityheaders.com do this better but this works for coursework
        """
        high_missing = sum(1 for f in self.findings
                          if f["severity"] == "HIGH" and f["type"] == "Missing Security Header")
        medium_missing = sum(1 for f in self.findings
                            if f["severity"] == "MEDIUM" and f["type"] == "Missing Security Header")
        total_missing = sum(1 for f in self.findings if f["type"] == "Missing Security Header")

        if total_missing == 0:
            return "A"
        elif high_missing == 0 and medium_missing <= 1:
            return "B"
        elif high_missing <= 1:
            return "C"
        elif high_missing <= 2:
            return "D"
        else:
            return "F"

    def scan(self, target_url):
        """run the full header check"""
        print(f"\n{BLUE}[*] Checking security headers for {target_url}{RESET}")

        self.check_security_headers(target_url)
        self.check_info_disclosure(target_url)

        grade = self.calculate_grade()
        grade_colors = {"A": GREEN, "B": GREEN, "C": YELLOW, "D": RED, "F": RED}
        color = grade_colors.get(grade, RESET)

        print(f"\n    Security Headers Grade: {color}{BOLD}{grade}{RESET}")

        if self.findings:
            print(f"    {len(self.findings)} issues found\n")
        else:
            print(f"    {GREEN}All headers present!{RESET}\n")

        return self.findings
