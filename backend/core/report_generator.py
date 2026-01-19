"""
NeuroSploit v3 - Professional HTML Report Generator
Generates beautiful, comprehensive security assessment reports
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import html
import base64


@dataclass
class ReportConfig:
    """Report generation configuration"""
    company_name: str = "NeuroSploit Security"
    logo_base64: Optional[str] = None
    include_executive_summary: bool = True
    include_methodology: bool = True
    include_recommendations: bool = True
    theme: str = "dark"  # "dark" or "light"


class HTMLReportGenerator:
    """Generate professional HTML security reports"""

    SEVERITY_COLORS = {
        "critical": {"bg": "#dc2626", "text": "#ffffff", "border": "#991b1b"},
        "high": {"bg": "#ea580c", "text": "#ffffff", "border": "#c2410c"},
        "medium": {"bg": "#ca8a04", "text": "#ffffff", "border": "#a16207"},
        "low": {"bg": "#2563eb", "text": "#ffffff", "border": "#1d4ed8"},
        "info": {"bg": "#6b7280", "text": "#ffffff", "border": "#4b5563"}
    }

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()

    def generate_report(
        self,
        session_data: Dict,
        findings: List[Dict],
        scan_results: Optional[List[Dict]] = None
    ) -> str:
        """Generate complete HTML report"""

        # Sort findings by severity
        sorted_findings = sorted(
            findings,
            key=lambda x: self.SEVERITY_ORDER.get(x.get('severity', 'info'), 4)
        )

        # Calculate statistics
        stats = self._calculate_stats(sorted_findings)

        # Generate report sections
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {html.escape(session_data.get('name', 'Unknown'))}</title>
    {self._get_styles()}
</head>
<body>
    <div class="report-container">
        {self._generate_header(session_data)}
        {self._generate_executive_summary(session_data, stats, sorted_findings)}
        {self._generate_scope_section(session_data)}
        {self._generate_findings_summary(stats)}
        {self._generate_findings_detail(sorted_findings)}
        {self._generate_scan_results(scan_results) if scan_results else ''}
        {self._generate_recommendations(sorted_findings)}
        {self._generate_methodology()}
        {self._generate_footer(session_data)}
    </div>
    {self._get_scripts()}
</body>
</html>"""

        return html_content

    def _get_styles(self) -> str:
        """Get CSS styles for the report"""
        is_dark = self.config.theme == "dark"

        bg_color = "#0f172a" if is_dark else "#ffffff"
        card_bg = "#1e293b" if is_dark else "#f8fafc"
        text_color = "#e2e8f0" if is_dark else "#1e293b"
        text_muted = "#94a3b8" if is_dark else "#64748b"
        border_color = "#334155" if is_dark else "#e2e8f0"
        accent = "#3b82f6"

        return f"""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: {bg_color};
            color: {text_color};
            line-height: 1.6;
            font-size: 14px;
        }}

        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}

        /* Header */
        .report-header {{
            text-align: center;
            padding: 60px 40px;
            background: linear-gradient(135deg, #1e40af 0%, #7c3aed 100%);
            border-radius: 16px;
            margin-bottom: 40px;
            position: relative;
            overflow: hidden;
        }}

        .report-header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            opacity: 0.5;
        }}

        .report-header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            color: white;
            margin-bottom: 8px;
            position: relative;
        }}

        .report-header .subtitle {{
            font-size: 1.1rem;
            color: rgba(255,255,255,0.9);
            position: relative;
        }}

        .report-header .meta {{
            margin-top: 24px;
            display: flex;
            justify-content: center;
            gap: 40px;
            color: rgba(255,255,255,0.8);
            font-size: 0.9rem;
            position: relative;
        }}

        .report-header .meta-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        /* Cards */
        .card {{
            background: {card_bg};
            border: 1px solid {border_color};
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }}

        .card-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid {border_color};
        }}

        .card-header h2 {{
            font-size: 1.25rem;
            font-weight: 600;
            color: {text_color};
        }}

        .card-header .icon {{
            width: 32px;
            height: 32px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: {accent};
            color: white;
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}

        .stat-card {{
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            transition: transform 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-2px);
        }}

        .stat-card .number {{
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1;
        }}

        .stat-card .label {{
            font-size: 0.875rem;
            margin-top: 8px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .stat-critical {{ background: linear-gradient(135deg, #dc2626, #991b1b); color: white; }}
        .stat-high {{ background: linear-gradient(135deg, #ea580c, #c2410c); color: white; }}
        .stat-medium {{ background: linear-gradient(135deg, #ca8a04, #a16207); color: white; }}
        .stat-low {{ background: linear-gradient(135deg, #2563eb, #1d4ed8); color: white; }}
        .stat-info {{ background: linear-gradient(135deg, #6b7280, #4b5563); color: white; }}
        .stat-total {{ background: linear-gradient(135deg, #7c3aed, #5b21b6); color: white; }}

        /* Findings */
        .finding {{
            border: 1px solid {border_color};
            border-radius: 12px;
            margin-bottom: 16px;
            overflow: hidden;
            transition: box-shadow 0.2s;
        }}

        .finding:hover {{
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }}

        .finding-header {{
            padding: 16px 20px;
            display: flex;
            align-items: center;
            gap: 16px;
            cursor: pointer;
            background: {card_bg};
        }}

        .finding-header:hover {{
            background: {'#293548' if is_dark else '#f1f5f9'};
        }}

        .severity-badge {{
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            min-width: 80px;
            text-align: center;
        }}

        .finding-title {{
            flex: 1;
            font-weight: 500;
            color: {text_color};
        }}

        .finding-endpoint {{
            font-size: 0.875rem;
            color: {text_muted};
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .finding-content {{
            padding: 20px;
            background: {'#151f2e' if is_dark else '#ffffff'};
            display: none;
        }}

        .finding-content.active {{
            display: block;
        }}

        .finding-section {{
            margin-bottom: 16px;
        }}

        .finding-section:last-child {{
            margin-bottom: 0;
        }}

        .finding-section h4 {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: {text_muted};
            margin-bottom: 8px;
        }}

        .finding-section p {{
            color: {text_color};
        }}

        .evidence-box {{
            background: {'#0f172a' if is_dark else '#f1f5f9'};
            border: 1px solid {border_color};
            border-radius: 8px;
            padding: 12px 16px;
            font-family: 'Fira Code', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        .remediation-box {{
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            border-radius: 8px;
            padding: 12px 16px;
            color: #22c55e;
        }}

        /* Executive Summary */
        .exec-summary {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 24px;
        }}

        .risk-meter {{
            height: 12px;
            background: {border_color};
            border-radius: 6px;
            overflow: hidden;
            margin: 16px 0;
        }}

        .risk-meter-fill {{
            height: 100%;
            border-radius: 6px;
            transition: width 0.5s ease;
        }}

        .risk-high {{ background: linear-gradient(90deg, #dc2626, #ea580c); }}
        .risk-medium {{ background: linear-gradient(90deg, #ea580c, #ca8a04); }}
        .risk-low {{ background: linear-gradient(90deg, #ca8a04, #22c55e); }}

        /* Table */
        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid {border_color};
        }}

        th {{
            font-weight: 600;
            color: {text_muted};
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }}

        /* Footer */
        .report-footer {{
            text-align: center;
            padding: 40px;
            color: {text_muted};
            border-top: 1px solid {border_color};
            margin-top: 40px;
        }}

        .report-footer .logo {{
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }}

        /* Print styles */
        @media print {{
            body {{
                background: white;
                color: black;
            }}

            .card {{
                break-inside: avoid;
            }}

            .finding {{
                break-inside: avoid;
            }}

            .report-header {{
                background: #1e40af !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }}
        }}

        /* Responsive */
        @media (max-width: 768px) {{
            .exec-summary {{
                grid-template-columns: 1fr;
            }}

            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}

            .report-header .meta {{
                flex-direction: column;
                gap: 12px;
            }}
        }}

        /* Animations */
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        .card {{
            animation: fadeIn 0.3s ease;
        }}
    </style>"""

    def _get_scripts(self) -> str:
        """Get JavaScript for interactivity"""
        return """
    <script>
        document.querySelectorAll('.finding-header').forEach(header => {
            header.addEventListener('click', () => {
                const content = header.nextElementSibling;
                const isActive = content.classList.contains('active');

                // Close all others
                document.querySelectorAll('.finding-content').forEach(c => {
                    c.classList.remove('active');
                });

                // Toggle current
                if (!isActive) {
                    content.classList.add('active');
                }
            });
        });

        // Expand all button functionality
        function expandAll() {
            document.querySelectorAll('.finding-content').forEach(c => {
                c.classList.add('active');
            });
        }

        function collapseAll() {
            document.querySelectorAll('.finding-content').forEach(c => {
                c.classList.remove('active');
            });
        }

        // Print functionality
        function printReport() {
            window.print();
        }
    </script>"""

    def _generate_header(self, session_data: Dict) -> str:
        """Generate report header"""
        target = session_data.get('target', 'Unknown Target')
        name = session_data.get('name', 'Security Assessment')
        created = session_data.get('created_at', datetime.utcnow().isoformat())

        try:
            created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
            created_str = created_dt.strftime('%B %d, %Y')
        except:
            created_str = created

        return f"""
        <header class="report-header">
            <h1>🛡️ Security Assessment Report</h1>
            <p class="subtitle">{html.escape(name)}</p>
            <div class="meta">
                <div class="meta-item">
                    <span>🎯</span>
                    <span>{html.escape(target)}</span>
                </div>
                <div class="meta-item">
                    <span>📅</span>
                    <span>{created_str}</span>
                </div>
                <div class="meta-item">
                    <span>🔬</span>
                    <span>NeuroSploit AI Scanner</span>
                </div>
            </div>
        </header>"""

    def _calculate_stats(self, findings: List[Dict]) -> Dict:
        """Calculate finding statistics"""
        stats = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in stats:
                stats[severity] += 1

        # Calculate risk score (0-100)
        risk_score = (
            stats['critical'] * 25 +
            stats['high'] * 15 +
            stats['medium'] * 8 +
            stats['low'] * 3 +
            stats['info'] * 1
        )
        stats['risk_score'] = min(100, risk_score)

        # Risk level
        if stats['risk_score'] >= 70 or stats['critical'] > 0:
            stats['risk_level'] = 'HIGH'
            stats['risk_class'] = 'risk-high'
        elif stats['risk_score'] >= 40 or stats['high'] > 1:
            stats['risk_level'] = 'MEDIUM'
            stats['risk_class'] = 'risk-medium'
        else:
            stats['risk_level'] = 'LOW'
            stats['risk_class'] = 'risk-low'

        return stats

    def _generate_executive_summary(self, session_data: Dict, stats: Dict, findings: List[Dict]) -> str:
        """Generate executive summary section"""
        target = session_data.get('target', 'the target')

        # Generate summary text based on findings
        if stats['critical'] > 0:
            summary = f"The security assessment of {html.escape(target)} revealed <strong>{stats['critical']} critical</strong> vulnerabilities that require immediate attention. These findings pose significant risk to the application's security posture and could lead to severe data breaches or system compromise."
        elif stats['high'] > 0:
            summary = f"The security assessment identified <strong>{stats['high']} high-severity</strong> issues that should be addressed promptly. While no critical vulnerabilities were found, the identified issues could be exploited by attackers to gain unauthorized access or compromise sensitive data."
        elif stats['medium'] > 0:
            summary = f"The assessment found <strong>{stats['medium']} medium-severity</strong> findings that represent moderate risk. These issues should be included in the remediation roadmap and addressed according to priority."
        else:
            summary = f"The security assessment completed with <strong>{stats['total']} findings</strong>, primarily informational in nature. The overall security posture appears reasonable, though continuous monitoring is recommended."

        return f"""
        <section class="card">
            <div class="card-header">
                <div class="icon">📊</div>
                <h2>Executive Summary</h2>
            </div>
            <div class="exec-summary">
                <div>
                    <p style="margin-bottom: 16px;">{summary}</p>
                    <div class="risk-meter">
                        <div class="risk-meter-fill {stats['risk_class']}" style="width: {stats['risk_score']}%"></div>
                    </div>
                    <p style="font-size: 0.875rem; color: var(--text-muted);">
                        Overall Risk Score: <strong>{stats['risk_score']}/100</strong> ({stats['risk_level']})
                    </p>
                </div>
                <div style="text-align: center; padding: 20px; background: rgba(59, 130, 246, 0.1); border-radius: 12px;">
                    <div style="font-size: 3rem; font-weight: 700; color: #3b82f6;">{stats['total']}</div>
                    <div style="text-transform: uppercase; letter-spacing: 0.1em; font-size: 0.75rem; color: #94a3b8;">Total Findings</div>
                </div>
            </div>
        </section>"""

    def _generate_scope_section(self, session_data: Dict) -> str:
        """Generate scope section"""
        target = session_data.get('target', 'Unknown')
        recon = session_data.get('recon_data', {})
        technologies = recon.get('technologies', [])
        endpoints = recon.get('endpoints', [])

        tech_html = ""
        if technologies:
            tech_html = f"""
            <div style="margin-top: 16px;">
                <h4 style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; color: #94a3b8; margin-bottom: 8px;">Detected Technologies</h4>
                <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                    {"".join(f'<span style="background: rgba(59,130,246,0.2); color: #60a5fa; padding: 4px 12px; border-radius: 20px; font-size: 0.875rem;">{html.escape(t)}</span>' for t in technologies[:15])}
                </div>
            </div>"""

        return f"""
        <section class="card">
            <div class="card-header">
                <div class="icon">🎯</div>
                <h2>Assessment Scope</h2>
            </div>
            <table>
                <tr>
                    <td style="width: 150px; font-weight: 500;">Target URL</td>
                    <td><a href="{html.escape(target)}" style="color: #3b82f6;">{html.escape(target)}</a></td>
                </tr>
                <tr>
                    <td style="font-weight: 500;">Endpoints Tested</td>
                    <td>{len(endpoints)}</td>
                </tr>
                <tr>
                    <td style="font-weight: 500;">Assessment Type</td>
                    <td>Automated Security Scan + AI Analysis</td>
                </tr>
            </table>
            {tech_html}
        </section>"""

    def _generate_findings_summary(self, stats: Dict) -> str:
        """Generate findings summary with stats cards"""
        return f"""
        <section class="card">
            <div class="card-header">
                <div class="icon">📈</div>
                <h2>Findings Overview</h2>
            </div>
            <div class="stats-grid">
                <div class="stat-card stat-critical">
                    <div class="number">{stats['critical']}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card stat-high">
                    <div class="number">{stats['high']}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card stat-medium">
                    <div class="number">{stats['medium']}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card stat-low">
                    <div class="number">{stats['low']}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat-card stat-info">
                    <div class="number">{stats['info']}</div>
                    <div class="label">Info</div>
                </div>
                <div class="stat-card stat-total">
                    <div class="number">{stats['total']}</div>
                    <div class="label">Total</div>
                </div>
            </div>
        </section>"""

    def _generate_findings_detail(self, findings: List[Dict]) -> str:
        """Generate detailed findings section with CVSS, CWE, and OWASP data"""
        if not findings:
            return """
            <section class="card">
                <div class="card-header">
                    <div class="icon">🔍</div>
                    <h2>Detailed Findings</h2>
                </div>
                <p style="text-align: center; padding: 40px; color: #94a3b8;">
                    No vulnerabilities were identified during this assessment.
                </p>
            </section>"""

        findings_html = ""
        for i, finding in enumerate(findings):
            severity = finding.get('severity', 'info').lower()
            colors = self.SEVERITY_COLORS.get(severity, self.SEVERITY_COLORS['info'])

            # Get CVSS, CWE, and OWASP data
            cvss_score = finding.get('cvss_score', self._get_default_cvss(severity))
            cvss_vector = finding.get('cvss_vector', '')
            cwe_id = finding.get('cwe_id', '')
            owasp = finding.get('owasp', '')

            # Generate technical info section
            tech_info_html = ""
            if cvss_score or cwe_id or owasp:
                tech_items = []
                if cvss_score:
                    cvss_color = self._get_cvss_color(cvss_score)
                    tech_items.append(f'''
                        <div style="flex: 1; min-width: 150px;">
                            <div style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; margin-bottom: 4px;">CVSS Score</div>
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="font-size: 1.5rem; font-weight: 700; color: {cvss_color};">{cvss_score}</span>
                                <span style="font-size: 0.75rem; color: #94a3b8;">{self._get_cvss_rating(cvss_score)}</span>
                            </div>
                            {f'<div style="font-size: 0.7rem; color: #64748b; margin-top: 2px; font-family: monospace;">{html.escape(cvss_vector)}</div>' if cvss_vector else ''}
                        </div>''')
                if cwe_id:
                    cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html" if cwe_id.startswith('CWE-') else '#'
                    tech_items.append(f'''
                        <div style="flex: 1; min-width: 150px;">
                            <div style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; margin-bottom: 4px;">CWE Reference</div>
                            <a href="{cwe_link}" target="_blank" style="color: #60a5fa; text-decoration: none; font-weight: 500;">
                                {html.escape(cwe_id)}
                            </a>
                        </div>''')
                if owasp:
                    tech_items.append(f'''
                        <div style="flex: 1; min-width: 150px;">
                            <div style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; margin-bottom: 4px;">OWASP Top 10</div>
                            <span style="color: #fbbf24; font-weight: 500;">{html.escape(owasp)}</span>
                        </div>''')

                tech_info_html = f'''
                    <div style="display: flex; flex-wrap: wrap; gap: 24px; padding: 16px; background: rgba(59, 130, 246, 0.05); border: 1px solid rgba(59, 130, 246, 0.1); border-radius: 8px; margin-bottom: 16px;">
                        {''.join(tech_items)}
                    </div>'''

            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="severity-badge" style="background: {colors['bg']}; color: {colors['text']};">
                        {severity.upper()}
                    </span>
                    <span class="finding-title">{html.escape(finding.get('title', 'Unknown'))}</span>
                    <span class="finding-endpoint">{html.escape(finding.get('affected_endpoint', ''))}</span>
                    <span style="color: #94a3b8;">▼</span>
                </div>
                <div class="finding-content">
                    {tech_info_html}
                    <div class="finding-section">
                        <h4>Vulnerability Type</h4>
                        <p>{html.escape(finding.get('vulnerability_type', 'Unknown'))}</p>
                    </div>
                    <div class="finding-section">
                        <h4>Description</h4>
                        <p>{html.escape(finding.get('description', 'No description available'))}</p>
                    </div>
                    {f'''<div class="finding-section">
                        <h4>Affected Endpoint</h4>
                        <div class="evidence-box">{html.escape(finding.get('affected_endpoint', ''))}</div>
                    </div>''' if finding.get('affected_endpoint') else ''}
                    {f'''<div class="finding-section">
                        <h4>Evidence / Proof of Concept</h4>
                        <div class="evidence-box">{html.escape(finding.get('evidence', ''))}</div>
                    </div>''' if finding.get('evidence') else ''}
                    {f'''<div class="finding-section">
                        <h4>Impact</h4>
                        <p>{html.escape(finding.get('impact', ''))}</p>
                    </div>''' if finding.get('impact') else ''}
                    <div class="finding-section">
                        <h4>Remediation</h4>
                        <div class="remediation-box">{html.escape(finding.get('remediation', 'Review and address this finding'))}</div>
                    </div>
                    {self._generate_references_html(finding.get('references', []))}
                </div>
            </div>"""

        return f"""
        <section class="card">
            <div class="card-header">
                <div class="icon">🔍</div>
                <h2>Detailed Findings</h2>
                <div style="margin-left: auto; display: flex; gap: 8px;">
                    <button onclick="expandAll()" style="padding: 6px 12px; border-radius: 6px; border: 1px solid #334155; background: transparent; color: #94a3b8; cursor: pointer; font-size: 0.75rem;">Expand All</button>
                    <button onclick="collapseAll()" style="padding: 6px 12px; border-radius: 6px; border: 1px solid #334155; background: transparent; color: #94a3b8; cursor: pointer; font-size: 0.75rem;">Collapse All</button>
                </div>
            </div>
            {findings_html}
        </section>"""

    def _get_default_cvss(self, severity: str) -> float:
        """Get default CVSS score based on severity"""
        defaults = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0,
            'info': 0.0
        }
        return defaults.get(severity.lower(), 5.0)

    def _get_cvss_color(self, score: float) -> str:
        """Get color based on CVSS score"""
        if score >= 9.0:
            return '#dc2626'  # Critical - Red
        elif score >= 7.0:
            return '#ea580c'  # High - Orange
        elif score >= 4.0:
            return '#ca8a04'  # Medium - Yellow
        elif score > 0:
            return '#2563eb'  # Low - Blue
        else:
            return '#6b7280'  # Info - Gray

    def _get_cvss_rating(self, score: float) -> str:
        """Get CVSS rating text"""
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        elif score > 0:
            return 'Low'
        else:
            return 'None'

    def _generate_references_html(self, references: List[str]) -> str:
        """Generate references section HTML"""
        if not references:
            return ''

        refs_html = ''
        for ref in references[:5]:  # Limit to 5 references
            if ref.startswith('http'):
                refs_html += f'<li><a href="{html.escape(ref)}" target="_blank" style="color: #60a5fa; text-decoration: none;">{html.escape(ref[:60])}{"..." if len(ref) > 60 else ""}</a></li>'
            else:
                refs_html += f'<li>{html.escape(ref)}</li>'

        return f'''
            <div class="finding-section">
                <h4>References</h4>
                <ul style="margin-left: 16px; color: #94a3b8; font-size: 0.875rem;">
                    {refs_html}
                </ul>
            </div>'''

    def _generate_scan_results(self, scan_results: List[Dict]) -> str:
        """Generate tool scan results section"""
        if not scan_results:
            return ""

        results_html = ""
        for result in scan_results:
            tool = result.get('tool', 'Unknown')
            status = result.get('status', 'unknown')
            output = result.get('output', '')[:2000]  # Limit output size

            status_color = "#22c55e" if status == "completed" else "#ef4444"

            results_html += f"""
            <div style="margin-bottom: 16px;">
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                    <strong>{html.escape(tool)}</strong>
                    <span style="color: {status_color}; font-size: 0.75rem; text-transform: uppercase;">{status}</span>
                </div>
                <div class="evidence-box" style="max-height: 200px; overflow-y: auto;">
{html.escape(output)}
                </div>
            </div>"""

        return f"""
        <section class="card">
            <div class="card-header">
                <div class="icon">🔧</div>
                <h2>Tool Scan Results</h2>
            </div>
            {results_html}
        </section>"""

    def _generate_recommendations(self, findings: List[Dict]) -> str:
        """Generate prioritized recommendations"""
        recommendations = []

        # Group findings by severity
        critical = [f for f in findings if f.get('severity') == 'critical']
        high = [f for f in findings if f.get('severity') == 'high']
        medium = [f for f in findings if f.get('severity') == 'medium']

        if critical:
            recommendations.append({
                "priority": "Immediate",
                "color": "#dc2626",
                "items": [f"Fix: {f.get('title', 'Unknown')} - {f.get('remediation', 'Review and fix')}" for f in critical]
            })

        if high:
            recommendations.append({
                "priority": "Short-term (1-2 weeks)",
                "color": "#ea580c",
                "items": [f"Address: {f.get('title', 'Unknown')}" for f in high]
            })

        if medium:
            recommendations.append({
                "priority": "Medium-term (1 month)",
                "color": "#ca8a04",
                "items": [f"Plan fix for: {f.get('title', 'Unknown')}" for f in medium[:5]]
            })

        # Always add general recommendations
        recommendations.append({
            "priority": "Ongoing",
            "color": "#3b82f6",
            "items": [
                "Implement regular security scanning",
                "Keep all software and dependencies updated",
                "Review and strengthen authentication mechanisms",
                "Implement proper logging and monitoring",
                "Conduct periodic penetration testing"
            ]
        })

        rec_html = ""
        for rec in recommendations:
            items_html = "".join(f"<li>{html.escape(item)}</li>" for item in rec['items'])
            rec_html += f"""
            <div style="margin-bottom: 24px;">
                <h4 style="color: {rec['color']}; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                    <span style="width: 8px; height: 8px; background: {rec['color']}; border-radius: 50%;"></span>
                    {rec['priority']}
                </h4>
                <ul style="margin-left: 24px; color: #94a3b8;">
                    {items_html}
                </ul>
            </div>"""

        return f"""
        <section class="card">
            <div class="card-header">
                <div class="icon">✅</div>
                <h2>Recommendations</h2>
            </div>
            {rec_html}
        </section>"""

    def _generate_methodology(self) -> str:
        """Generate methodology section"""
        return """
        <section class="card">
            <div class="card-header">
                <div class="icon">📋</div>
                <h2>Methodology</h2>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px;">
                <div>
                    <h4 style="color: #3b82f6; margin-bottom: 8px;">1. Reconnaissance</h4>
                    <p style="color: #94a3b8; font-size: 0.875rem;">Technology fingerprinting, endpoint discovery, and information gathering</p>
                </div>
                <div>
                    <h4 style="color: #8b5cf6; margin-bottom: 8px;">2. Vulnerability Scanning</h4>
                    <p style="color: #94a3b8; font-size: 0.875rem;">Automated scanning for known vulnerabilities and misconfigurations</p>
                </div>
                <div>
                    <h4 style="color: #ec4899; margin-bottom: 8px;">3. AI Analysis</h4>
                    <p style="color: #94a3b8; font-size: 0.875rem;">LLM-powered analysis of findings for context and remediation</p>
                </div>
                <div>
                    <h4 style="color: #22c55e; margin-bottom: 8px;">4. Verification</h4>
                    <p style="color: #94a3b8; font-size: 0.875rem;">Manual verification of critical findings to eliminate false positives</p>
                </div>
            </div>
        </section>"""

    def _generate_footer(self, session_data: Dict) -> str:
        """Generate report footer"""
        return f"""
        <footer class="report-footer">
            <div class="logo">⚡ NeuroSploit</div>
            <p>AI-Powered Security Assessment Platform</p>
            <p style="margin-top: 16px; font-size: 0.75rem;">
                Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
            </p>
            <p style="margin-top: 8px; font-size: 0.75rem;">
                This report contains confidential security information. Handle with care.
            </p>
        </footer>"""
