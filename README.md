# web-vuln-scanner

Built this for my OWASP testing coursework - it's not Burp Suite but it gets the job done for basic web app security assessments. Scans for the most common web vulnerabilities and spits out an HTML report you can hand in or share with your team.

## Legal Disclaimer

**This tool is for educational purposes and authorized penetration testing ONLY.**

Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide. Always obtain written permission before scanning any target you don't own. I am not responsible for any misuse of this tool.

Seriously, don't be stupid with this. Get permission first.

## What it does

- **Web Crawling** - BFS crawler that discovers pages, links, and forms on the target
- **XSS Detection** - Tests URL parameters and form inputs for reflected cross-site scripting
- **SQL Injection** - Error-based and time-based blind SQLi detection across MySQL, PostgreSQL, SQLite, MSSQL, and Oracle
- **Security Headers** - Checks for OWASP recommended headers (HSTS, CSP, X-Frame-Options, etc.) and grades A-F
- **SSL/TLS Analysis** - Certificate validity, expiry, protocol version, weak cipher detection
- **Directory Bruteforce** - Discovers hidden paths using a common wordlist (admin panels, config files, backups, .git, .env)
- **HTML Reports** - Generates a dark-themed HTML report grouped by severity

## Installation

```bash
git clone https://github.com/Vikrant892/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
```

## Usage

```bash
# full scan (all modules)
python main.py -u https://target.com -s all

# just xss scanning
python main.py -u https://target.com -s xss

# just sql injection
python main.py -u https://target.com -s sqli

# security headers only (quick check)
python main.py -u https://target.com -s headers

# ssl/tls check
python main.py -u https://target.com -s ssl

# directory bruteforce with 20 threads
python main.py -u https://target.com -s dirs -t 20

# crawl only (just map the site)
python main.py -u https://target.com -s crawl -d 5

# full scan, text output only (no html report)
python main.py -u https://target.com -s all -o text
```

### CLI Options

```
-u, --url         Target URL (required)
-s, --scan        Scan type: all, xss, sqli, headers, ssl, dirs, crawl
-o, --output      Output format: html, text
-d, --depth       Crawl depth (default: 3)
-t, --threads     Threads for dir bruteforce (default: 10)
--max-pages       Max pages to crawl (default: 100)
--no-crawl        Skip crawling, test target URL directly
-v, --verbose     Verbose output
```

## Sample Output

```
╦ ╦╔═╗╔╗   ╦  ╦╦ ╦╦  ╔╗╔  ╔═╗╔═╗╔═╗╔╗╔
║║║║╣ ╠╩╗  ╚╗╔╝║ ║║  ║║║  ╚═╗║  ╠═╣║║║
╚╩╝╚═╝╚═╝   ╚╝ ╚═╝╩═╝╝╚╝  ╚═╝╚═╝╩ ╩╝╚╝

    OWASP Web Vulnerability Scanner v1.0

[*] Target: https://testsite.local
[*] Scan type: all

──────────────────────────────────────────────────────────
  PHASE 1: Crawling
──────────────────────────────────────────────────────────
[*] Starting BFS crawl on https://testsite.local
    [+] Crawled: https://testsite.local (depth=0, links=12)
    [+] Crawled: https://testsite.local/login (depth=1, links=3)
    [+] Crawled: https://testsite.local/search?q= (depth=1, links=5)

──────────────────────────────────────────────────────────
  PHASE 4: Security Headers Check
──────────────────────────────────────────────────────────
    Header                              Status     Severity
    Strict-Transport-Security           MISSING    HIGH
    Content-Security-Policy             MISSING    HIGH
    X-Frame-Options                     PRESENT    -
    X-Content-Type-Options              PRESENT    -

    Security Headers Grade: D

============================================================
  SCAN SUMMARY
============================================================
  Target:   https://testsite.local
  Total:    8 findings
  Critical: 1
  High:     3
  Medium:   2
  Low:      2
============================================================

[+] Report saved to: reports/scan_report_20250315_143022.html
[+] Scan completed in 45.3s
```

## Project Structure

```
web-vuln-scanner/
├── main.py                 # CLI entry point (argparse)
├── requirements.txt
├── scanner/
│   ├── crawler.py          # BFS web crawler
│   ├── xss_scanner.py      # Reflected XSS detection
│   ├── sqli_scanner.py     # SQL injection (error + blind)
│   ├── header_check.py     # Security headers grading
│   ├── ssl_check.py        # SSL/TLS certificate checks
│   ├── dir_bruteforce.py   # Directory enumeration
│   └── reporter.py         # HTML report generator
├── payloads/
│   ├── xss_payloads.txt    # XSS test strings
│   └── sqli_payloads.txt   # SQLi test strings
├── wordlists/
│   └── common_dirs.txt     # Directory wordlist
└── templates/
    └── report.html         # Jinja2 report template
```

## Limitations

I want to be upfront about what this thing can't do:

- **No stored XSS detection** - only checks reflected XSS. Stored and DOM-based XSS require a completely different approach
- **No authentication support** - can't scan behind login pages (would need cookie/session handling)
- **Basic crawling** - the BFS crawler is simple, it'll miss JavaScript-rendered content and complex SPAs
- **False positives on time-based SQLi** - slow servers can trigger false positives on the SLEEP-based detection
- **No WAF evasion** - if there's a WAF in front of the target, most payloads will get blocked
- **Single target only** - doesn't support scanning multiple hosts or CIDR ranges
- **Limited cipher checks** - checks the negotiated cipher, not all supported ciphers on the server

For proper pentesting use Burp Suite, OWASP ZAP, or sqlmap. This is a learning tool.

## Dependencies

- `requests` - HTTP library
- `beautifulsoup4` - HTML parsing for the crawler
- `Jinja2` - HTML report templating
- `colorama` - Cross-platform colored terminal output
- Python 3.8+

## License

MIT - do whatever you want with it, just don't use it to hack stuff you don't have permission to test.
