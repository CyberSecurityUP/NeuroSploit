#!/usr/bin/env python3
"""
Professional Pentest Report Generator
Generates detailed reports with PoCs, CVSS scores, requests/responses
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
import html
import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates professional penetration testing reports"""

    def __init__(self, scan_results: Dict, llm_analysis: str = ""):
        self.scan_results = scan_results
        self.llm_analysis = llm_analysis
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d"
        }
        return colors.get(severity.lower(), "#6c757d")

    def _get_severity_badge(self, severity: str) -> str:
        """Get HTML badge for severity"""
        color = self._get_severity_color(severity)
        return f'<span class="badge" style="background-color: {color}; color: white; padding: 5px 10px; border-radius: 4px;">{severity.upper()}</span>'

    def _escape_html(self, text: str) -> str:
        """Escape HTML characters"""
        if not text:
            return ""
        return html.escape(str(text))

    def _format_code_block(self, code: str, language: str = "") -> str:
        """Format code block with syntax highlighting"""
        escaped = self._escape_html(code)
        return f'<pre><code class="language-{language}">{escaped}</code></pre>'

    def generate_executive_summary(self) -> str:
        """Generate executive summary section"""
        summary = self.scan_results.get("summary", {})
        severity = summary.get("severity_breakdown", {})

        total = summary.get("total_vulnerabilities", 0)
        critical = severity.get("Critical", 0)
        high = severity.get("High", 0)
        medium = severity.get("Medium", 0)
        low = severity.get("Low", 0)

        risk_level = "Critical" if critical > 0 else "High" if high > 0 else "Medium" if medium > 0 else "Low"

        return f"""
        <div class="card executive-summary">
            <div class="card-header">
                <h2>Executive Summary</h2>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h4>Assessment Overview</h4>
                        <table class="table">
                            <tr><td><strong>Target:</strong></td><td>{self._escape_html(self.scan_results.get('target', 'N/A'))}</td></tr>
                            <tr><td><strong>Scan Started:</strong></td><td>{self.scan_results.get('scan_started', 'N/A')}</td></tr>
                            <tr><td><strong>Scan Completed:</strong></td><td>{self.scan_results.get('scan_completed', 'N/A')}</td></tr>
                            <tr><td><strong>Overall Risk Level:</strong></td><td>{self._get_severity_badge(risk_level)}</td></tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h4>Findings Summary</h4>
                        <div class="severity-chart">
                            <div class="severity-bar critical" style="width: {critical * 20}%">{critical} Critical</div>
                            <div class="severity-bar high" style="width: {high * 20}%">{high} High</div>
                            <div class="severity-bar medium" style="width: {medium * 20}%">{medium} Medium</div>
                            <div class="severity-bar low" style="width: {low * 20}%">{low} Low</div>
                        </div>
                        <p class="mt-3"><strong>Total Vulnerabilities:</strong> {total}</p>
                        <p><strong>Open Ports Found:</strong> {summary.get('open_ports', 0)}</p>
                        <p><strong>Tools Executed:</strong> {summary.get('tools_executed', 0)}</p>
                    </div>
                </div>
            </div>
        </div>
        """

    def generate_vulnerability_card(self, vuln: Dict, index: int) -> str:
        """Generate HTML card for a single vulnerability"""
        severity = vuln.get("severity", "Unknown")
        color = self._get_severity_color(severity)

        # Build references list
        refs_html = ""
        if vuln.get("references"):
            refs_html = "<ul>"
            for ref in vuln.get("references", [])[:5]:
                refs_html += f'<li><a href="{self._escape_html(ref)}" target="_blank">{self._escape_html(ref)}</a></li>'
            refs_html += "</ul>"

        return f"""
        <div class="vulnerability-card" id="vuln-{index}">
            <div class="vuln-header" style="border-left: 5px solid {color};">
                <div class="vuln-title">
                    <h3>{self._escape_html(vuln.get('title', 'Unknown Vulnerability'))}</h3>
                    <div class="vuln-meta">
                        {self._get_severity_badge(severity)}
                        <span class="cvss-score">CVSS: {vuln.get('cvss_score', 'N/A')}</span>
                        {f'<span class="cwe-id">CWE: {vuln.get("cwe_id")}</span>' if vuln.get('cwe_id') else ''}
                    </div>
                </div>
            </div>

            <div class="vuln-body">
                <div class="vuln-section">
                    <h4>Description</h4>
                    <p>{self._escape_html(vuln.get('description', 'No description available'))}</p>
                </div>

                <div class="vuln-section">
                    <h4>Affected Endpoint</h4>
                    <code class="endpoint">{self._escape_html(vuln.get('affected_endpoint', 'N/A'))}</code>
                </div>

                <div class="vuln-section">
                    <h4>Impact</h4>
                    <p>{self._escape_html(vuln.get('impact', 'Impact not assessed'))}</p>
                </div>

                <div class="vuln-section poc-section">
                    <h4>Proof of Concept (PoC)</h4>

                    <div class="poc-item">
                        <h5>Request</h5>
                        {self._format_code_block(vuln.get('poc_request', 'N/A'), 'http')}
                    </div>

                    <div class="poc-item">
                        <h5>Payload</h5>
                        {self._format_code_block(vuln.get('poc_payload', 'N/A'), 'text')}
                    </div>

                    <div class="poc-item">
                        <h5>Response</h5>
                        {self._format_code_block(vuln.get('poc_response', 'N/A')[:1000], 'http')}
                    </div>
                </div>

                {f'''<div class="vuln-section">
                    <h4>CVSS Vector</h4>
                    <code>{self._escape_html(vuln.get('cvss_vector', 'N/A'))}</code>
                </div>''' if vuln.get('cvss_vector') else ''}

                <div class="vuln-section remediation">
                    <h4>Remediation</h4>
                    <p>{self._escape_html(vuln.get('remediation', 'Consult vendor documentation for patches'))}</p>
                </div>

                {f'''<div class="vuln-section">
                    <h4>References</h4>
                    {refs_html}
                </div>''' if refs_html else ''}

                {f'''<div class="vuln-section tool-output">
                    <h4>Raw Tool Output</h4>
                    {self._format_code_block(vuln.get('tool_output', '')[:2000], 'text')}
                </div>''' if vuln.get('tool_output') else ''}
            </div>
        </div>
        """

    def generate_open_ports_section(self) -> str:
        """Generate open ports section"""
        ports = self.scan_results.get("open_ports", [])
        if not ports:
            return ""

        rows = ""
        for port in ports:
            rows += f"""
            <tr>
                <td>{port.get('port', 'N/A')}</td>
                <td>{port.get('protocol', 'N/A')}</td>
                <td>{self._escape_html(port.get('service', 'N/A'))}</td>
                <td>{self._escape_html(port.get('version', 'N/A'))}</td>
            </tr>
            """

        return f"""
        <div class="card">
            <div class="card-header">
                <h2>Open Ports & Services</h2>
            </div>
            <div class="card-body">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Service</th>
                            <th>Version</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
        """

    def generate_tools_executed_section(self) -> str:
        """Generate tools executed section"""
        tools = self.scan_results.get("tools_executed", [])
        if not tools:
            return ""

        rows = ""
        for tool in tools:
            status = "Success" if tool.get("success") else "Failed"
            status_class = "text-success" if tool.get("success") else "text-danger"
            rows += f"""
            <tr>
                <td>{self._escape_html(tool.get('tool', 'N/A'))}</td>
                <td><code>{self._escape_html(tool.get('command', 'N/A')[:100])}</code></td>
                <td class="{status_class}">{status}</td>
                <td>{tool.get('timestamp', 'N/A')}</td>
            </tr>
            """

        return f"""
        <div class="card">
            <div class="card-header">
                <h2>Tools Executed</h2>
            </div>
            <div class="card-body">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Tool</th>
                            <th>Command</th>
                            <th>Status</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
        """

    def generate_llm_analysis_section(self) -> str:
        """Generate AI analysis section"""
        if not self.llm_analysis:
            return ""

        import mistune
        analysis_html = mistune.html(self.llm_analysis)

        return f"""
        <div class="card">
            <div class="card-header">
                <h2>AI Security Analysis</h2>
            </div>
            <div class="card-body llm-analysis">
                {analysis_html}
            </div>
        </div>
        """

    def generate_html_report(self) -> str:
        """Generate complete HTML report"""
        vulnerabilities = self.scan_results.get("vulnerabilities", [])

        # Sort vulnerabilities by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        vulnerabilities.sort(key=lambda x: severity_order.get(x.get("severity", "Info").capitalize(), 5))

        vuln_cards = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            vuln_cards += self.generate_vulnerability_card(vuln, i)

        # Table of contents
        toc_items = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get("severity", "Unknown")
            color = self._get_severity_color(severity)
            toc_items += f'<li><a href="#vuln-{i}" style="color: {color};">[{severity.upper()}] {self._escape_html(vuln.get("title", "Unknown")[:50])}</a></li>'

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NeuroSploitv2 - Penetration Test Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
    <style>
        :root {{
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-green: #00ff00;
            --critical-color: #dc3545;
            --high-color: #fd7e14;
            --medium-color: #ffc107;
            --low-color: #17a2b8;
        }}

        body {{
            background-color: var(--bg-dark);
            color: var(--text-primary);
            font-family: 'Segoe UI', system-ui, sans-serif;
        }}

        .container {{
            max-width: 1200px;
            padding: 20px;
        }}

        .report-header {{
            text-align: center;
            padding: 40px 0;
            border-bottom: 2px solid var(--accent-green);
            margin-bottom: 30px;
        }}

        .report-header h1 {{
            font-size: 2.5rem;
            color: var(--accent-green);
            text-shadow: 0 0 10px var(--accent-green);
            margin-bottom: 10px;
        }}

        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
        }}

        .card-header {{
            background-color: rgba(0, 255, 0, 0.1);
            border-bottom: 1px solid var(--border-color);
            padding: 15px 20px;
        }}

        .card-header h2 {{
            margin: 0;
            color: var(--accent-green);
            font-size: 1.3rem;
        }}

        .card-body {{
            padding: 20px;
        }}

        .table {{
            color: var(--text-primary);
        }}

        .table th {{
            border-color: var(--border-color);
            color: var(--accent-green);
        }}

        .table td {{
            border-color: var(--border-color);
        }}

        .vulnerability-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 25px;
            overflow: hidden;
        }}

        .vuln-header {{
            padding: 20px;
            background-color: rgba(0, 0, 0, 0.3);
        }}

        .vuln-title h3 {{
            margin: 0 0 10px 0;
            font-size: 1.2rem;
        }}

        .vuln-meta {{
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }}

        .cvss-score {{
            background-color: #333;
            padding: 5px 10px;
            border-radius: 4px;
            font-family: monospace;
        }}

        .cwe-id {{
            background-color: #1a365d;
            padding: 5px 10px;
            border-radius: 4px;
            font-family: monospace;
        }}

        .vuln-body {{
            padding: 20px;
        }}

        .vuln-section {{
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
        }}

        .vuln-section:last-child {{
            border-bottom: none;
            margin-bottom: 0;
        }}

        .vuln-section h4 {{
            color: var(--accent-green);
            font-size: 1rem;
            margin-bottom: 10px;
        }}

        .vuln-section h5 {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin: 10px 0 5px 0;
        }}

        .poc-section {{
            background-color: rgba(0, 0, 0, 0.2);
            padding: 15px;
            border-radius: 8px;
        }}

        .poc-item {{
            margin-bottom: 15px;
        }}

        pre {{
            background-color: #1e1e1e;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            margin: 0;
        }}

        code {{
            font-family: 'Fira Code', 'Consolas', monospace;
            font-size: 0.85rem;
        }}

        .endpoint {{
            background-color: #333;
            padding: 8px 12px;
            border-radius: 4px;
            display: inline-block;
            word-break: break-all;
        }}

        .remediation {{
            background-color: rgba(0, 255, 0, 0.05);
            border-left: 3px solid var(--accent-green);
            padding-left: 15px;
        }}

        .severity-chart {{
            display: flex;
            flex-direction: column;
            gap: 5px;
        }}

        .severity-bar {{
            padding: 8px 15px;
            border-radius: 4px;
            font-weight: bold;
            min-width: 100px;
        }}

        .severity-bar.critical {{ background-color: var(--critical-color); }}
        .severity-bar.high {{ background-color: var(--high-color); color: #000; }}
        .severity-bar.medium {{ background-color: var(--medium-color); color: #000; }}
        .severity-bar.low {{ background-color: var(--low-color); }}

        .toc {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }}

        .toc h3 {{
            color: var(--accent-green);
            margin-bottom: 15px;
        }}

        .toc ul {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}

        .toc li {{
            padding: 5px 0;
        }}

        .toc a {{
            text-decoration: none;
        }}

        .toc a:hover {{
            text-decoration: underline;
        }}

        .llm-analysis {{
            line-height: 1.8;
        }}

        .llm-analysis h2 {{
            color: var(--accent-green);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }}

        .footer {{
            text-align: center;
            padding: 30px;
            border-top: 1px solid var(--border-color);
            margin-top: 30px;
            color: var(--text-secondary);
        }}

        @media print {{
            body {{
                background-color: white;
                color: black;
            }}
            .vulnerability-card {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>NeuroSploitv2</h1>
            <p class="lead">Penetration Test Report</p>
            <p class="text-muted">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        {self.generate_executive_summary()}

        <div class="toc">
            <h3>Table of Contents - Vulnerabilities ({len(vulnerabilities)})</h3>
            <ul>
                {toc_items}
            </ul>
        </div>

        {self.generate_open_ports_section()}

        {self.generate_tools_executed_section()}

        <div class="card">
            <div class="card-header">
                <h2>Vulnerability Details</h2>
            </div>
            <div class="card-body">
                {vuln_cards if vuln_cards else '<p class="text-muted">No vulnerabilities found during the assessment.</p>'}
            </div>
        </div>

        {self.generate_llm_analysis_section()}

        <div class="footer">
            <p>Report generated by <strong>NeuroSploitv2</strong> - AI-Powered Penetration Testing Framework</p>
            <p class="small">This report is confidential and intended for authorized personnel only.</p>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script>hljs.highlightAll();</script>
</body>
</html>
        """

        return html

    def save_report(self, output_dir: str = "reports") -> str:
        """Save HTML report to file"""
        os.makedirs(output_dir, exist_ok=True)

        filename = f"pentest_report_{self.timestamp}.html"
        filepath = os.path.join(output_dir, filename)

        html_content = self.generate_html_report()

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"Report saved to: {filepath}")
        return filepath

    def save_json_report(self, output_dir: str = "results") -> str:
        """Save JSON report to file"""
        os.makedirs(output_dir, exist_ok=True)

        filename = f"pentest_results_{self.timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, indent=2, default=str)

        logger.info(f"JSON results saved to: {filepath}")
        return filepath
