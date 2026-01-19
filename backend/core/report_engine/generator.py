"""
NeuroSploit v3 - Report Generator

Generates professional HTML, PDF, and JSON reports.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional

from backend.models import Scan, Vulnerability
from backend.config import settings


class ReportGenerator:
    """Generates security assessment reports"""

    SEVERITY_COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d"
    }

    def __init__(self):
        self.reports_dir = settings.REPORTS_DIR

    async def generate(
        self,
        scan: Scan,
        vulnerabilities: List[Vulnerability],
        format: str = "html",
        title: Optional[str] = None,
        include_executive_summary: bool = True,
        include_poc: bool = True,
        include_remediation: bool = True
    ) -> Tuple[Path, str]:
        """
        Generate a report.

        Returns:
            Tuple of (file_path, executive_summary)
        """
        title = title or f"Security Assessment Report - {scan.name}"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Generate executive summary
        executive_summary = self._generate_executive_summary(scan, vulnerabilities)

        if format == "html":
            content = self._generate_html(
                scan, vulnerabilities, title,
                executive_summary if include_executive_summary else None,
                include_poc, include_remediation
            )
            filename = f"report_{timestamp}.html"
        elif format == "json":
            content = self._generate_json(scan, vulnerabilities, title, executive_summary)
            filename = f"report_{timestamp}.json"
        elif format == "pdf":
            # Generate HTML first, then convert to PDF
            html_content = self._generate_html(
                scan, vulnerabilities, title,
                executive_summary, include_poc, include_remediation
            )
            content = html_content  # PDF conversion would happen here
            filename = f"report_{timestamp}.html"  # For now, save as HTML
        else:
            raise ValueError(f"Unsupported format: {format}")

        # Save report
        file_path = self.reports_dir / filename
        file_path.write_text(content)

        return file_path, executive_summary

    def _generate_executive_summary(self, scan: Scan, vulnerabilities: List[Vulnerability]) -> str:
        """Generate executive summary text"""
        total = len(vulnerabilities)
        critical = sum(1 for v in vulnerabilities if v.severity == "critical")
        high = sum(1 for v in vulnerabilities if v.severity == "high")
        medium = sum(1 for v in vulnerabilities if v.severity == "medium")
        low = sum(1 for v in vulnerabilities if v.severity == "low")

        risk_level = "Critical" if critical > 0 else "High" if high > 0 else "Medium" if medium > 0 else "Low" if low > 0 else "Informational"

        summary = f"""A security assessment was conducted on the target application.
The assessment identified {total} vulnerabilities across the tested endpoints.

Risk Summary:
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}

Overall Risk Level: {risk_level}

{"Immediate attention is required to address critical and high severity findings." if critical or high else "The application has a reasonable security posture with some areas for improvement."}
"""
        return summary

    def _generate_html(
        self,
        scan: Scan,
        vulnerabilities: List[Vulnerability],
        title: str,
        executive_summary: Optional[str],
        include_poc: bool,
        include_remediation: bool
    ) -> str:
        """Generate HTML report"""
        # Count by severity
        severity_counts = {
            "critical": sum(1 for v in vulnerabilities if v.severity == "critical"),
            "high": sum(1 for v in vulnerabilities if v.severity == "high"),
            "medium": sum(1 for v in vulnerabilities if v.severity == "medium"),
            "low": sum(1 for v in vulnerabilities if v.severity == "low"),
            "info": sum(1 for v in vulnerabilities if v.severity == "info")
        }
        total = sum(severity_counts.values())

        # Generate vulnerability cards
        vuln_cards = ""
        for vuln in vulnerabilities:
            color = self.SEVERITY_COLORS.get(vuln.severity, "#6c757d")
            poc_section = ""
            if include_poc and (vuln.poc_request or vuln.poc_payload):
                poc_section = f"""
                <div class="poc-section">
                    <h4>Proof of Concept</h4>
                    {f'<div class="code-block"><pre>{self._escape_html(vuln.poc_payload or "")}</pre></div>' if vuln.poc_payload else ''}
                    {f'<div class="code-block"><pre>{self._escape_html(vuln.poc_request[:1000] if vuln.poc_request else "")}</pre></div>' if vuln.poc_request else ''}
                </div>
                """

            remediation_section = ""
            if include_remediation and vuln.remediation:
                remediation_section = f"""
                <div class="remediation-section">
                    <h4>Remediation</h4>
                    <p>{self._escape_html(vuln.remediation)}</p>
                </div>
                """

            vuln_cards += f"""
            <div class="vuln-card">
                <div class="vuln-header">
                    <span class="severity-badge" style="background-color: {color};">{vuln.severity.upper()}</span>
                    <h3>{self._escape_html(vuln.title)}</h3>
                </div>
                <div class="vuln-meta">
                    <span><strong>Type:</strong> {vuln.vulnerability_type}</span>
                    {f'<span><strong>CWE:</strong> {vuln.cwe_id}</span>' if vuln.cwe_id else ''}
                    {f'<span><strong>CVSS:</strong> {vuln.cvss_score}</span>' if vuln.cvss_score else ''}
                </div>
                <div class="vuln-body">
                    <p><strong>Affected Endpoint:</strong> {self._escape_html(vuln.affected_endpoint or 'N/A')}</p>
                    <p><strong>Description:</strong> {self._escape_html(vuln.description or 'N/A')}</p>
                    {f'<p><strong>Impact:</strong> {self._escape_html(vuln.impact)}</p>' if vuln.impact else ''}
                    {poc_section}
                    {remediation_section}
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self._escape_html(title)}</title>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #e94560;
            --border: #333;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{ color: var(--accent); margin-bottom: 10px; }}
        .header p {{ color: var(--text-secondary); }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .stat-card .number {{ font-size: 2em; font-weight: bold; }}
        .stat-card .label {{ color: var(--text-secondary); font-size: 0.9em; }}
        .section {{ background: var(--bg-secondary); padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .section h2 {{ color: var(--accent); margin-bottom: 20px; border-bottom: 2px solid var(--border); padding-bottom: 10px; }}
        .vuln-card {{
            background: var(--bg-card);
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .vuln-header {{
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 15px;
            border-bottom: 1px solid var(--border);
        }}
        .vuln-header h3 {{ flex: 1; }}
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.8em;
        }}
        .vuln-meta {{
            padding: 10px 20px;
            background: rgba(0,0,0,0.2);
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            font-size: 0.9em;
        }}
        .vuln-body {{ padding: 20px; }}
        .vuln-body p {{ margin-bottom: 15px; }}
        .poc-section, .remediation-section {{
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
        }}
        .poc-section h4, .remediation-section h4 {{ color: var(--accent); margin-bottom: 10px; }}
        .code-block {{
            background: #0a0a15;
            border-radius: 5px;
            padding: 15px;
            overflow-x: auto;
            margin-top: 10px;
        }}
        .code-block pre {{
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.85em;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .executive-summary {{ white-space: pre-wrap; }}
        .severity-chart {{
            display: flex;
            height: 30px;
            border-radius: 5px;
            overflow: hidden;
            margin-top: 20px;
        }}
        .severity-bar {{ display: flex; align-items: center; justify-content: center; color: white; font-size: 0.8em; font-weight: bold; }}
        .footer {{ text-align: center; padding: 20px; color: var(--text-secondary); font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>NeuroSploit Security Report</h1>
            <p>{self._escape_html(title)}</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="number" style="color: {self.SEVERITY_COLORS['critical']}">{severity_counts['critical']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: {self.SEVERITY_COLORS['high']}">{severity_counts['high']}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: {self.SEVERITY_COLORS['medium']}">{severity_counts['medium']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: {self.SEVERITY_COLORS['low']}">{severity_counts['low']}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card">
                <div class="number">{total}</div>
                <div class="label">Total</div>
            </div>
        </div>

        {f'''<div class="section">
            <h2>Executive Summary</h2>
            <p class="executive-summary">{self._escape_html(executive_summary)}</p>
        </div>''' if executive_summary else ''}

        <div class="section">
            <h2>Vulnerability Findings</h2>
            {vuln_cards if vuln_cards else '<p>No vulnerabilities found.</p>'}
        </div>

        <div class="footer">
            <p>Generated by NeuroSploit v3 - AI-Powered Penetration Testing Platform</p>
        </div>
    </div>
</body>
</html>"""
        return html

    def _generate_json(
        self,
        scan: Scan,
        vulnerabilities: List[Vulnerability],
        title: str,
        executive_summary: str
    ) -> str:
        """Generate JSON report"""
        report = {
            "title": title,
            "generated_at": datetime.now().isoformat(),
            "scan": {
                "id": scan.id,
                "name": scan.name,
                "status": scan.status,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "total_endpoints": scan.total_endpoints,
                "total_vulnerabilities": scan.total_vulnerabilities
            },
            "summary": {
                "executive_summary": executive_summary,
                "severity_counts": {
                    "critical": scan.critical_count,
                    "high": scan.high_count,
                    "medium": scan.medium_count,
                    "low": scan.low_count,
                    "info": scan.info_count
                }
            },
            "vulnerabilities": [v.to_dict() for v in vulnerabilities]
        }
        return json.dumps(report, indent=2, default=str)

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return ""
        return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))
