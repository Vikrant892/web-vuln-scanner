# For educational and authorized testing ONLY
# html report generator using jinja2
# groups findings by severity and type

import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"

# severity ordering for sorting
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class Reporter:
    def __init__(self, target_url, output_dir="reports"):
        self.target_url = target_url
        self.output_dir = output_dir
        self.template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")

    def _group_by_severity(self, findings):
        """group findings by severity level for the report"""
        grouped = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for finding in findings:
            sev = finding.get("severity", "LOW")
            if sev in grouped:
                grouped[sev].append(finding)
            else:
                grouped["LOW"].append(finding)
        return grouped

    def _group_by_type(self, findings):
        """group findings by vulnerability type"""
        grouped = {}
        for finding in findings:
            vuln_type = finding.get("type", "Unknown")
            if vuln_type not in grouped:
                grouped[vuln_type] = []
            grouped[vuln_type].append(finding)
        return grouped

    def _get_summary_stats(self, findings):
        """calculate some basic stats for the report header"""
        stats = {
            "total": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
        }
        # overall risk score - nothing scientific, just a rough number
        stats["risk_score"] = (
            stats["critical"] * 10 +
            stats["high"] * 5 +
            stats["medium"] * 2 +
            stats["low"] * 1
        )
        return stats

    def generate_html(self, findings, scan_duration=0):
        """generate the html report from template"""
        print(f"\n{BLUE}[*] Generating HTML report...{RESET}")

        # sort findings by severity
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

        # prepare template data
        data = {
            "target_url": self.target_url,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration": f"{scan_duration:.1f}s" if scan_duration else "N/A",
            "findings": sorted_findings,
            "by_severity": self._group_by_severity(findings),
            "by_type": self._group_by_type(findings),
            "stats": self._get_summary_stats(findings),
        }

        try:
            env = Environment(loader=FileSystemLoader(self.template_dir))
            template = env.get_template("report.html")
            html = template.render(**data)
        except Exception as e:
            print(f"    {RED}[-]{RESET} Template error: {e}")
            print(f"    Falling back to basic report...")
            html = self._generate_basic_html(data)

        # write report file
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"    {GREEN}[+]{RESET} Report saved to: {filepath}")
        return filepath

    def _generate_basic_html(self, data):
        """fallback if jinja2 template fails - just dumps findings into a basic table"""
        html = f"""<!DOCTYPE html>
<html>
<head><title>Scan Report - {data['target_url']}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #333; color: white; }}
.CRITICAL {{ background: #ff4444; color: white; }}
.HIGH {{ background: #ff8800; color: white; }}
.MEDIUM {{ background: #ffcc00; }}
.LOW {{ background: #88cc88; }}
</style></head>
<body>
<h1>Vulnerability Scan Report</h1>
<p>Target: {data['target_url']}</p>
<p>Date: {data['scan_date']}</p>
<p>Total findings: {data['stats']['total']}</p>
<table>
<tr><th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>Description</th></tr>
"""
        for f in data["findings"]:
            html += f"""<tr>
<td class="{f['severity']}">{f['severity']}</td>
<td>{f['type']}</td>
<td>{f['url']}</td>
<td>{f['parameter']}</td>
<td>{f['description']}</td>
</tr>"""

        html += "</table></body></html>"
        return html

    def print_summary(self, findings):
        """print a text summary to terminal"""
        stats = self._get_summary_stats(findings)

        print(f"\n{'=' * 60}")
        print(f"{BOLD}  SCAN SUMMARY{RESET}")
        print(f"{'=' * 60}")
        print(f"  Target:   {self.target_url}")
        print(f"  Total:    {stats['total']} findings")
        print(f"  Critical: {RED}{stats['critical']}{RESET}")
        print(f"  High:     {RED}{stats['high']}{RESET}")
        print(f"  Medium:   {BLUE}{stats['medium']}{RESET}")
        print(f"  Low:      {GREEN}{stats['low']}{RESET}")
        print(f"  Risk:     {stats['risk_score']}/100")
        print(f"{'=' * 60}\n")
