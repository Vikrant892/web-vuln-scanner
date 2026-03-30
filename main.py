#!/usr/bin/env python3
# For educational and authorized testing ONLY
# web vulnerability scanner - cli entry point
# built for owasp testing coursework

import argparse
import sys
import time
import urllib3

from scanner.crawler import Crawler
from scanner.xss_scanner import XSSScanner
from scanner.sqli_scanner import SQLiScanner
from scanner.header_check import HeaderChecker
from scanner.ssl_check import SSLChecker
from scanner.dir_bruteforce import DirBruteforcer
from scanner.reporter import Reporter

# suppress the ssl warnings, gets annoying fast
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = f"""
{RED}╦ ╦╔═╗╔╗   {CYAN}╦  ╦╦ ╦╦  ╔╗╔  {YELLOW}╔═╗╔═╗╔═╗╔╗╔
{RED}║║║║╣ ╠╩╗  {CYAN}╚╗╔╝║ ║║  ║║║  {YELLOW}╚═╗║  ╠═╣║║║
{RED}╚╩╝╚═╝╚═╝  {CYAN} ╚╝ ╚═╝╩═╝╝╚╝  {YELLOW}╚═╝╚═╝╩ ╩╝╚╝{RESET}

    {BOLD}OWASP Web Vulnerability Scanner v1.0{RESET}
    {YELLOW}For educational and authorized testing ONLY{RESET}
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner - OWASP testing tool",
        epilog="Example: python main.py -u https://example.com -s all -o html"
    )
    parser.add_argument("-u", "--url", required=True,
                       help="Target URL to scan (e.g., https://example.com)")
    parser.add_argument("-s", "--scan", default="all",
                       choices=["all", "xss", "sqli", "headers", "ssl", "dirs", "crawl"],
                       help="Scan type to run (default: all)")
    parser.add_argument("-o", "--output", default="html",
                       choices=["html", "text"],
                       help="Output format (default: html)")
    parser.add_argument("-d", "--depth", type=int, default=3,
                       help="Crawl depth (default: 3)")
    parser.add_argument("-t", "--threads", type=int, default=10,
                       help="Number of threads for directory bruteforce (default: 10)")
    parser.add_argument("--max-pages", type=int, default=100,
                       help="Maximum pages to crawl (default: 100)")
    parser.add_argument("--no-crawl", action="store_true",
                       help="Skip crawling, only test the target URL directly")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")

    args = parser.parse_args()

    # basic url validation
    if not args.url.startswith(("http://", "https://")):
        print(f"\n{RED}[!] URL must start with http:// or https://{RESET}")
        sys.exit(1)

    return args


def print_disclaimer():
    """print the legal disclaimer - important stuff"""
    print(f"\n{YELLOW}{'=' * 60}")
    print(f"  DISCLAIMER: This tool is for educational purposes and")
    print(f"  authorized penetration testing ONLY. Unauthorized access")
    print(f"  to computer systems is illegal. Always get written")
    print(f"  permission before scanning any target.")
    print(f"{'=' * 60}{RESET}\n")


def run_scan(args):
    """main scan orchestration - runs whatever scan types were requested"""
    all_findings = []
    start_time = time.time()
    scan_type = args.scan

    # step 1: crawl the target (unless skipped or just doing headers/ssl/dirs)
    crawl_results = None
    if scan_type in ["all", "xss", "sqli", "crawl"] and not args.no_crawl:
        print(f"\n{BLUE}{'─' * 60}{RESET}")
        print(f"{BOLD}  PHASE 1: Crawling{RESET}")
        print(f"{BLUE}{'─' * 60}{RESET}")

        crawler = Crawler(args.url, max_depth=args.depth, max_pages=args.max_pages)
        crawl_results = crawler.crawl()

        if scan_type == "crawl":
            # just crawling, we're done
            elapsed = time.time() - start_time
            print(f"\n{GREEN}[+] Crawl completed in {elapsed:.1f}s{RESET}")
            return []

    # step 2: run the selected scanners
    if scan_type in ["all", "xss"] and crawl_results:
        print(f"\n{BLUE}{'─' * 60}{RESET}")
        print(f"{BOLD}  PHASE 2: XSS Scanning{RESET}")
        print(f"{BLUE}{'─' * 60}{RESET}")

        xss = XSSScanner()
        findings = xss.scan(crawl_results)
        all_findings.extend(findings)

    if scan_type in ["all", "sqli"] and crawl_results:
        print(f"\n{BLUE}{'─' * 60}{RESET}")
        print(f"{BOLD}  PHASE 3: SQL Injection Scanning{RESET}")
        print(f"{BLUE}{'─' * 60}{RESET}")

        sqli = SQLiScanner()
        findings = sqli.scan(crawl_results)
        all_findings.extend(findings)

    if scan_type in ["all", "headers"]:
        print(f"\n{BLUE}{'─' * 60}{RESET}")
        print(f"{BOLD}  PHASE 4: Security Headers Check{RESET}")
        print(f"{BLUE}{'─' * 60}{RESET}")

        headers = HeaderChecker()
        findings = headers.scan(args.url)
        all_findings.extend(findings)

    if scan_type in ["all", "ssl"]:
        print(f"\n{BLUE}{'─' * 60}{RESET}")
        print(f"{BOLD}  PHASE 5: SSL/TLS Check{RESET}")
        print(f"{BLUE}{'─' * 60}{RESET}")

        ssl_checker = SSLChecker()
        findings = ssl_checker.scan(args.url)
        all_findings.extend(findings)

    if scan_type in ["all", "dirs"]:
        print(f"\n{BLUE}{'─' * 60}{RESET}")
        print(f"{BOLD}  PHASE 6: Directory Bruteforce{RESET}")
        print(f"{BLUE}{'─' * 60}{RESET}")

        dirb = DirBruteforcer(threads=args.threads)
        findings = dirb.scan(args.url)
        all_findings.extend(findings)

    elapsed = time.time() - start_time

    # step 3: generate report
    reporter = Reporter(args.url)
    reporter.print_summary(all_findings)

    if args.output == "html" and all_findings:
        reporter.generate_html(all_findings, scan_duration=elapsed)

    print(f"{GREEN}[+] Scan completed in {elapsed:.1f}s{RESET}\n")

    return all_findings


def main():
    print(BANNER)
    print_disclaimer()

    args = parse_args()

    print(f"{BLUE}[*] Target: {args.url}{RESET}")
    print(f"{BLUE}[*] Scan type: {args.scan}{RESET}")
    print(f"{BLUE}[*] Threads: {args.threads}{RESET}")

    try:
        findings = run_scan(args)
        if not findings:
            print(f"\n{GREEN}[+] No vulnerabilities found. Nice!{RESET}\n")
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[!] Scan interrupted by user{RESET}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}[-] Fatal error: {str(e)}{RESET}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
