"""
NeuroSploit v3 - Report Generator

Generates professional HTML, PDF, and JSON reports
with OHVR structure and embedded screenshots.
"""
import base64
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

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self):
        self.reports_dir = settings.REPORTS_DIR
        self._scan_id: Optional[str] = None
        self._tool_executions: List = []

    async def generate(
        self,
        scan: Scan,
        vulnerabilities: List[Vulnerability],
        format: str = "html",
        title: Optional[str] = None,
        include_executive_summary: bool = True,
        include_poc: bool = True,
        include_remediation: bool = True,
        tool_executions: Optional[List] = None,
    ) -> Tuple[Path, str]:
        """
        Generate a report.

        Returns:
            Tuple of (file_path, executive_summary)
        """
        self._scan_id = str(scan.id) if scan else None
        self._tool_executions = tool_executions or []
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

        # Save report in a per-report folder with screenshots
        report_dir = self.reports_dir / f"report_{timestamp}"
        report_dir.mkdir(parents=True, exist_ok=True)

        file_path = report_dir / filename
        file_path.write_text(content)

        # Copy screenshots into the report folder
        self._copy_screenshots_to_report(vulnerabilities, report_dir)

        return file_path, executive_summary

    async def generate_ai_report(
        self,
        scan: Scan,
        vulnerabilities: List[Vulnerability],
        tool_executions: Optional[List] = None,
        title: Optional[str] = None,
    ) -> Tuple[Path, str]:
        """Generate an AI-enhanced report with LLM-written executive summary and per-finding analysis."""
        from core.llm_manager import LLMManager

        self._scan_id = str(scan.id) if scan else None
        self._tool_executions = tool_executions or []
        title = title or f"AI Security Assessment Report - {scan.name}"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Build findings context for AI
        findings_context = []
        for v in vulnerabilities:
            findings_context.append(
                f"- [{v.severity.upper()}] {v.title}: {v.vulnerability_type} at "
                f"{v.affected_endpoint or 'N/A'}"
                f"{' | CWE: ' + v.cwe_id if v.cwe_id else ''}"
                f"{' | CVSS: ' + str(v.cvss_score) if v.cvss_score else ''}"
            )

        tools_context = ""
        if self._tool_executions:
            tools_lines = []
            for te in self._tool_executions:
                tools_lines.append(
                    f"- {te.get('tool', 'unknown')}: {te.get('command', '')} "
                    f"({te.get('duration', 0)}s, {te.get('findings_count', 0)} findings)"
                )
            tools_context = "\n\nTools executed:\n" + "\n".join(tools_lines)

        total = len(vulnerabilities)
        critical = sum(1 for v in vulnerabilities if v.severity == "critical")
        high = sum(1 for v in vulnerabilities if v.severity == "high")
        medium = sum(1 for v in vulnerabilities if v.severity == "medium")
        low = sum(1 for v in vulnerabilities if v.severity == "low")

        prompt = (
            f"Write a professional executive summary for a penetration test report.\n"
            f"Target: {scan.name}\n"
            f"Total findings: {total} (Critical: {critical}, High: {high}, Medium: {medium}, Low: {low})\n\n"
            f"Findings:\n" + "\n".join(findings_context[:30]) + tools_context + "\n\n"
            f"Write 3-4 paragraphs covering: overall risk posture, key critical findings, "
            f"attack surface observations, and prioritized remediation recommendations. "
            f"Be specific and reference actual findings. Professional tone."
        )

        # Generate AI executive summary
        try:
            llm = LLMManager()
            ai_summary = await llm.generate(
                prompt,
                "You are a senior penetration testing consultant writing a client-facing report."
            )
        except Exception:
            ai_summary = self._generate_executive_summary(scan, vulnerabilities)

        # Generate HTML with AI summary
        content = self._generate_html(
            scan, vulnerabilities, title,
            ai_summary, include_poc=True, include_remediation=True
        )

        report_dir = self.reports_dir / f"report_{timestamp}"
        report_dir.mkdir(parents=True, exist_ok=True)
        filename = f"report_{timestamp}.html"
        file_path = report_dir / filename
        file_path.write_text(content)
        self._copy_screenshots_to_report(vulnerabilities, report_dir)

        return file_path, ai_summary

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
        # Separate confirmed and rejected vulnerabilities
        confirmed_vulns = [v for v in vulnerabilities if getattr(v, 'validation_status', 'ai_confirmed') != 'ai_rejected']
        rejected_vulns = [v for v in vulnerabilities if getattr(v, 'validation_status', 'ai_confirmed') == 'ai_rejected']

        # Count by severity (confirmed only)
        severity_counts = {
            "critical": sum(1 for v in confirmed_vulns if v.severity == "critical"),
            "high": sum(1 for v in confirmed_vulns if v.severity == "high"),
            "medium": sum(1 for v in confirmed_vulns if v.severity == "medium"),
            "low": sum(1 for v in confirmed_vulns if v.severity == "low"),
            "info": sum(1 for v in confirmed_vulns if v.severity == "info")
        }
        total = sum(severity_counts.values())

        # Sort vulnerabilities by severity (Critical first, Info last)
        confirmed_vulns = sorted(
            confirmed_vulns,
            key=lambda v: self.SEVERITY_ORDER.get(v.severity, 5)
        )
        rejected_vulns = sorted(
            rejected_vulns,
            key=lambda v: self.SEVERITY_ORDER.get(v.severity, 5)
        )

        # Generate vulnerability cards for confirmed findings
        vuln_cards = ""
        for vuln in confirmed_vulns:
            color = self.SEVERITY_COLORS.get(vuln.severity, "#6c757d")
            poc_section = ""
            if include_poc and (vuln.poc_request or vuln.poc_payload or getattr(vuln, 'poc_code', None)):
                # Build screenshot HTML if available
                screenshots_html = self._build_screenshots_html(vuln)

                # Build PoC code section (generated HTML/Python/curl exploitation code)
                poc_code_html = ""
                poc_code_value = getattr(vuln, 'poc_code', None) or ""
                if poc_code_value:
                    # Determine language for syntax hint
                    if poc_code_value.strip().startswith("<!DOCTYPE") or poc_code_value.strip().startswith("<html") or poc_code_value.strip().startswith("<!--"):
                        lang_label = "HTML"
                    elif poc_code_value.strip().startswith("#!/usr/bin/env python") or "import requests" in poc_code_value:
                        lang_label = "Python"
                    elif poc_code_value.strip().startswith("curl ") or poc_code_value.strip().startswith("#"):
                        lang_label = "Shell/curl"
                    else:
                        lang_label = "PoC Code"

                    poc_code_html = f"""
                    <div class="ohvr-section">
                        <h5>Exploitation Code ({lang_label})</h5>
                        <div class="code-block"><pre>{self._escape_html(poc_code_value[:5000])}</pre></div>
                    </div>"""

                poc_section = f"""
                <div class="poc-section">
                    <h4>Proof of Concept</h4>
                    <div class="ohvr-section">
                        <h5>Observation</h5>
                        <p>{self._escape_html(vuln.description or 'Security-relevant behavior detected at the affected endpoint.')}</p>
                    </div>
                    <div class="ohvr-section">
                        <h5>Hypothesis</h5>
                        <p>The endpoint may be vulnerable to {self._escape_html(vuln.vulnerability_type or 'the identified attack vector')} based on observed behavior.</p>
                    </div>
                    <div class="ohvr-section">
                        <h5>Validation</h5>
                        {f'<div class="code-block"><pre>{self._escape_html(vuln.poc_payload or "")}</pre></div>' if vuln.poc_payload else ''}
                        {f'<div class="code-block"><pre>{self._escape_html(vuln.poc_request[:1000] if vuln.poc_request else "")}</pre></div>' if vuln.poc_request else ''}
                        {screenshots_html}
                    </div>
                    {poc_code_html}
                    <div class="ohvr-section">
                        <h5>Result</h5>
                        <p>{self._escape_html(vuln.impact or 'Vulnerability confirmed through the validation steps above.')}</p>
                    </div>
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
        .ohvr-section {{
            margin: 1rem 0;
            padding: 1rem;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
        }}
        .ohvr-section h5 {{
            color: var(--accent);
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
        }}
        .screenshot-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }}
        .screenshot-card {{
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }}
        .screenshot-card img {{
            width: 100%;
            height: auto;
            display: block;
        }}
        .screenshot-caption {{
            padding: 0.5rem;
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-align: center;
        }}
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
            <h2>Vulnerability Findings ({total} Confirmed)</h2>
            {vuln_cards if vuln_cards else '<p>No confirmed vulnerabilities found.</p>'}
        </div>

        {self._build_rejected_findings_section(rejected_vulns)}

        {self._build_screenshots_gallery(confirmed_vulns)}

        {self._build_tools_section()}

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
            "vulnerabilities": [v.to_dict() for v in vulnerabilities if getattr(v, 'validation_status', 'ai_confirmed') != 'ai_rejected'],
            "rejected_findings": [v.to_dict() for v in vulnerabilities if getattr(v, 'validation_status', 'ai_confirmed') == 'ai_rejected'],
            "tool_executions": self._tool_executions
        }
        return json.dumps(report, indent=2, default=str)

    def _build_screenshots_html(self, vuln) -> str:
        """Build screenshot grid HTML for a vulnerability.

        Sources (in order of priority):
        1. vuln.screenshots list with base64 data URIs (from agent capture)
        2. Filesystem lookup in reports/screenshots/{finding_id}/ (from BrowserValidator)
        """
        data_uris = []

        # Source 1: base64 screenshots embedded in the vulnerability object
        inline_screenshots = getattr(vuln, 'screenshots', None) or []
        for ss in inline_screenshots:
            if isinstance(ss, str) and ss.startswith("data:image/"):
                data_uris.append(ss)

        # Source 2: filesystem screenshots (finding_id = md5(vuln_type+url+param)[:8])
        # Check scan-scoped path first, then legacy flat path
        if not data_uris:
            import hashlib
            screenshots_base = settings.BASE_DIR / "reports" / "screenshots"
            vuln_type = getattr(vuln, 'vulnerability_type', '') or ''
            vuln_url = getattr(vuln, 'url', '') or getattr(vuln, 'affected_endpoint', '') or ''
            vuln_param = getattr(vuln, 'parameter', '') or getattr(vuln, 'poc_parameter', '') or ''
            finding_id = hashlib.md5(f"{vuln_type}{vuln_url}{vuln_param}".encode()).hexdigest()[:8]

            # Scan-scoped path: reports/screenshots/{scan_id}/{finding_id}/
            finding_dir = None
            if self._scan_id:
                scan_dir = screenshots_base / self._scan_id / finding_id
                if scan_dir.exists():
                    finding_dir = scan_dir
            # Fallback: legacy flat path reports/screenshots/{finding_id}/
            if not finding_dir:
                legacy_dir = screenshots_base / finding_id
                if legacy_dir.exists():
                    finding_dir = legacy_dir

            if finding_dir:
                for ss_file in sorted(finding_dir.glob("*.png"))[:5]:
                    data_uri = self._embed_screenshot(str(ss_file))
                    if data_uri:
                        data_uris.append(data_uri)

        if not data_uris:
            return ""

        cards = ""
        for i, data_uri in enumerate(data_uris[:5]):
            caption = "Evidence Capture" if i == 0 else f"Screenshot {i + 1}"
            cards += f"""
                <div class="screenshot-card">
                    <img src="{data_uri}" alt="{caption}" />
                    <div class="screenshot-caption">{caption}</div>
                </div>"""

        return f'<div class="screenshot-grid">{cards}</div>'

    def _embed_screenshot(self, filepath: str) -> str:
        """Convert a screenshot file to a base64 data URI."""
        path = Path(filepath)
        if not path.exists():
            return ""
        try:
            with open(path, 'rb') as f:
                data = base64.b64encode(f.read()).decode('ascii')
            return f"data:image/png;base64,{data}"
        except Exception:
            return ""

    def _copy_screenshots_to_report(self, vulnerabilities: List[Vulnerability], report_dir: Path):
        """Copy vulnerability screenshots into the per-report folder."""
        import shutil
        import hashlib
        screenshots_base = settings.BASE_DIR / "reports" / "screenshots"
        screenshots_dest = report_dir / "screenshots"

        for vuln in vulnerabilities:
            # Use same finding_id as agent: md5(vuln_type+url+param)[:8]
            vuln_type = getattr(vuln, 'vulnerability_type', '') or ''
            vuln_url = getattr(vuln, 'url', '') or getattr(vuln, 'affected_endpoint', '') or ''
            vuln_param = getattr(vuln, 'parameter', '') or getattr(vuln, 'poc_parameter', '') or ''
            finding_id = hashlib.md5(f"{vuln_type}{vuln_url}{vuln_param}".encode()).hexdigest()[:8]

            # Check scan-scoped path first, then legacy
            src_dir = None
            if self._scan_id:
                scan_src = screenshots_base / self._scan_id / finding_id
                if scan_src.exists():
                    src_dir = scan_src
            if not src_dir:
                legacy_src = screenshots_base / finding_id
                if legacy_src.exists():
                    src_dir = legacy_src

            if src_dir:
                dest_dir = screenshots_dest / finding_id
                dest_dir.mkdir(parents=True, exist_ok=True)
                for ss_file in src_dir.glob("*.png"):
                    shutil.copy2(ss_file, dest_dir / ss_file.name)

    def _build_screenshots_gallery(self, vulnerabilities: List[Vulnerability]) -> str:
        """Build a dedicated Screenshots & Evidence gallery section for the report."""
        import hashlib
        gallery_items = []

        for vuln in vulnerabilities:
            vuln_screenshots = []

            # Source 1: base64 from DB
            inline = getattr(vuln, 'screenshots', None) or []
            for ss in inline:
                if isinstance(ss, str) and ss.startswith("data:image/"):
                    vuln_screenshots.append(ss)

            # Source 2: filesystem (scan-scoped first, then legacy)
            if not vuln_screenshots:
                vuln_type = getattr(vuln, 'vulnerability_type', '') or ''
                vuln_url = getattr(vuln, 'url', '') or getattr(vuln, 'affected_endpoint', '') or ''
                vuln_param = getattr(vuln, 'parameter', '') or getattr(vuln, 'poc_parameter', '') or ''
                finding_id = hashlib.md5(f"{vuln_type}{vuln_url}{vuln_param}".encode()).hexdigest()[:8]
                screenshots_base = settings.BASE_DIR / "reports" / "screenshots"
                finding_dir = None
                if self._scan_id:
                    scan_dir = screenshots_base / self._scan_id / finding_id
                    if scan_dir.exists():
                        finding_dir = scan_dir
                if not finding_dir:
                    legacy_dir = screenshots_base / finding_id
                    if legacy_dir.exists():
                        finding_dir = legacy_dir
                if finding_dir:
                    for ss_file in sorted(finding_dir.glob("*.png"))[:5]:
                        data_uri = self._embed_screenshot(str(ss_file))
                        if data_uri:
                            vuln_screenshots.append(data_uri)

            if vuln_screenshots:
                title = self._escape_html(getattr(vuln, 'title', 'Unknown'))
                severity = getattr(vuln, 'severity', 'info')
                color = self.SEVERITY_COLORS.get(severity, '#6c757d')
                images_html = ""
                for i, data_uri in enumerate(vuln_screenshots[:5]):
                    images_html += f"""
                        <div class="screenshot-card">
                            <img src="{data_uri}" alt="Evidence {i+1}" />
                            <div class="screenshot-caption">Evidence {i+1}</div>
                        </div>"""
                gallery_items.append(f"""
                    <div style="margin-bottom: 1.5rem;">
                        <h4 style="color: {color}; margin-bottom: 0.5rem;">{title}</h4>
                        <div class="screenshot-grid">{images_html}</div>
                    </div>""")

        if not gallery_items:
            return ""

        return f"""
        <div class="section">
            <h2>Screenshots &amp; Evidence</h2>
            <p style="color: var(--text-secondary); margin-bottom: 1rem;">Visual evidence captured during vulnerability validation.</p>
            {''.join(gallery_items)}
        </div>"""

    def _build_rejected_findings_section(self, rejected_vulns: List) -> str:
        """Build an HTML section for AI-rejected findings that need manual review."""
        if not rejected_vulns:
            return ""

        items = ""
        for vuln in rejected_vulns:
            color = self.SEVERITY_COLORS.get(vuln.severity, "#6c757d")
            reason = self._escape_html(getattr(vuln, 'ai_rejection_reason', '') or 'No reason provided')
            items += f"""
            <div style="border: 1px solid #555; border-left: 3px solid {color}; border-radius: 8px; padding: 12px; margin-bottom: 8px; opacity: 0.7; background: rgba(255,165,0,0.05);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="background-color: {color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold;">{vuln.severity.upper()}</span>
                        <strong>{self._escape_html(vuln.title)}</strong>
                    </div>
                    <span style="background: rgba(255,165,0,0.2); color: #ffa500; padding: 2px 8px; border-radius: 12px; font-size: 0.7rem;">AI Rejected</span>
                </div>
                <p style="color: #aaa; font-size: 0.85rem; margin: 4px 0;"><strong>Endpoint:</strong> {self._escape_html(vuln.affected_endpoint or 'N/A')}</p>
                {f'<p style="color: #aaa; font-size: 0.85rem; margin: 4px 0;"><strong>Payload:</strong> <code>{self._escape_html(vuln.poc_payload or "")}</code></p>' if vuln.poc_payload else ''}
                <p style="color: #ffa500; font-size: 0.8rem; margin: 8px 0 0 0; padding: 8px; background: rgba(255,165,0,0.1); border-radius: 4px;"><strong>Rejection Reason:</strong> {reason}</p>
            </div>
            """

        return f"""
        <div class="section" style="border: 1px dashed #ffa500; border-radius: 12px; padding: 20px; margin-top: 20px;">
            <h2 style="color: #ffa500;">AI-Rejected Findings ({len(rejected_vulns)}) - Manual Review Required</h2>
            <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                The following potential findings were rejected by AI analysis as likely false positives.
                Manual pentester review is recommended to confirm or override these decisions.
            </p>
            {items}
        </div>"""

    def _build_tools_section(self) -> str:
        """Build an HTML section listing tools that were executed during the scan."""
        if not self._tool_executions:
            return ""

        rows = ""
        for te in self._tool_executions:
            tool = self._escape_html(te.get("tool", "unknown"))
            command = self._escape_html(te.get("command", ""))
            duration = te.get("duration", 0)
            findings = te.get("findings_count", 0)
            exit_code = te.get("exit_code", 0)
            stdout = self._escape_html(te.get("stdout_preview", "")[:500])

            status_color = "#28a745" if exit_code == 0 else "#dc3545"
            rows += f"""
                <div class="vuln-card" style="margin-bottom: 1rem;">
                    <div class="vuln-header" style="padding: 15px;">
                        <span class="severity-badge" style="background-color: #6c63ff; font-size: 0.75em;">{tool.upper()}</span>
                        <h3 style="font-size: 0.95em;">{command}</h3>
                    </div>
                    <div class="vuln-meta">
                        <span><strong>Duration:</strong> {duration}s</span>
                        <span><strong>Findings:</strong> {findings}</span>
                        <span style="color: {status_color};"><strong>Exit:</strong> {exit_code}</span>
                    </div>
                    {f'<div style="padding: 15px;"><div class="code-block"><pre>{stdout}</pre></div></div>' if stdout else ''}
                </div>"""

        return f"""
        <div class="section">
            <h2>Tools Executed</h2>
            <p style="color: var(--text-secondary); margin-bottom: 1rem;">Security tools executed during the automated assessment.</p>
            {rows}
        </div>"""

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
