#!/usr/bin/env python3
"""
NeuroSploitv2 - AI-Powered Penetration Testing Framework
Author: Security Research Team
License: MIT
Version: 2.0.0
"""

import os
import sys
import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
import logging
from datetime import datetime
import readline
import mistune

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/neurosploit.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

from core.llm_manager import LLMManager
from core.tool_installer import ToolInstaller, run_installer_menu, PENTEST_TOOLS
from core.pentest_executor import PentestExecutor
from core.report_generator import ReportGenerator
from agents.base_agent import BaseAgent

class Completer:
    def __init__(self, neurosploit):
        self.neurosploit = neurosploit
        self.commands = [
            "help", "run_agent", "config", "list_roles", "list_profiles",
            "set_profile", "set_agent", "discover_ollama", "install_tools",
            "scan", "quick_scan", "check_tools", "exit", "quit"
        ]
        self.agent_roles = list(self.neurosploit.config.get('agent_roles', {}).keys())
        self.llm_profiles = list(self.neurosploit.config.get('llm', {}).get('profiles', {}).keys())

    def complete(self, text, state):
        line = readline.get_line_buffer()
        parts = line.split()

        options = []
        if state == 0:
            if not parts or (len(parts) == 1 and not line.endswith(' ')):
                options = [c + ' ' for c in self.commands if c.startswith(text)]
            elif len(parts) > 0:
                if parts[0] == 'run_agent':
                    if len(parts) == 1 and line.endswith(' '):
                        options = [a + ' ' for a in self.agent_roles]
                    elif len(parts) == 2 and not line.endswith(' '):
                        options = [a + ' ' for a in self.agent_roles if a.startswith(parts[1])]
                elif parts[0] == 'set_agent':
                    if len(parts) == 1 and line.endswith(' '):
                        options = [a + ' ' for a in self.agent_roles]
                    elif len(parts) == 2 and not line.endswith(' '):
                        options = [a + ' ' for a in self.agent_roles if a.startswith(parts[1])]
                elif parts[0] == 'set_profile':
                    if len(parts) == 1 and line.endswith(' '):
                        options = [p + ' ' for p in self.llm_profiles]
                    elif len(parts) == 2 and not line.endswith(' '):
                        options = [p + ' ' for p in self.llm_profiles if p.startswith(parts[1])]

        if state < len(options):
            return options[state]
        else:
            return None


class NeuroSploitv2:
    """Main framework class for NeuroSploitv2"""
    
    def __init__(self, config_path: str = "config/config.json"):
        """Initialize the framework"""
        self.config_path = config_path
        self.config = self._load_config()
        # self.agents = {} # Removed as agents will be dynamically created per role
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._setup_directories()
        
        # LLMManager instance will be created dynamically per agent role to select specific profiles
        self.llm_manager_instance: Optional[LLMManager] = None
        self.selected_agent_role: Optional[str] = None

        # Initialize tool installer
        self.tool_installer = ToolInstaller()

        logger.info(f"NeuroSploitv2 initialized - Session: {self.session_id}")
        
    def _setup_directories(self):
        """Create necessary directories"""
        dirs = ['logs', 'reports', 'data', 'custom_agents', 'results']
        for d in dirs:
            Path(d).mkdir(exist_ok=True)
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        if not os.path.exists(self.config_path):
            if os.path.exists("config/config-example.json"):
                import shutil
                shutil.copy("config/config-example.json", self.config_path)
                logger.info(f"Created default configuration at {self.config_path}")
            else:
                logger.error("config-example.json not found. Cannot create default configuration.")
                return {}
        
        with open(self.config_path, 'r') as f:
            return json.load(f)
    
    def _initialize_llm_manager(self, agent_llm_profile: Optional[str] = None):
        """Initializes LLMManager with a specific profile or default."""
        llm_config = self.config.get('llm', {})
        if agent_llm_profile:
            # Temporarily modify config to set the default profile for LLMManager init
            original_default = llm_config.get('default_profile')
            llm_config['default_profile'] = agent_llm_profile
            self.llm_manager_instance = LLMManager({"llm": llm_config})
            llm_config['default_profile'] = original_default # Restore original default
        else:
            self.llm_manager_instance = LLMManager({"llm": llm_config})

    def execute_agent_role(self, agent_role_name: str, user_input: str, additional_context: Optional[Dict] = None, llm_profile_override: Optional[str] = None):
        """Execute a specific agent role with a given input."""
        logger.info(f"Starting execution for agent role: {agent_role_name}")

        agent_roles_config = self.config.get('agent_roles', {})
        role_config = agent_roles_config.get(agent_role_name)

        # If role not in config, create a default config (allows dynamic roles from .md files)
        if not role_config:
            logger.info(f"Agent role '{agent_role_name}' not in config.json, using dynamic mode with prompt file.")
            role_config = {
                "enabled": True,
                "tools_allowed": [],
                "description": f"Dynamic agent role loaded from {agent_role_name}.md"
            }

        if not role_config.get('enabled', True):
            logger.warning(f"Agent role '{agent_role_name}' is disabled in configuration.")
            return {"warning": f"Agent role '{agent_role_name}' is disabled."}

        llm_profile_name = llm_profile_override or role_config.get('llm_profile', self.config['llm']['default_profile'])
        self._initialize_llm_manager(llm_profile_name)

        if not self.llm_manager_instance:
            logger.error("LLM Manager could not be initialized.")
            return {"error": "LLM Manager initialization failed."}
        
        # Get the prompts for the selected agent role
        # Assuming agent_role_name directly maps to the .md filename
        agent_prompts = self.llm_manager_instance.prompts.get("md_prompts", {}).get(agent_role_name)
        if not agent_prompts:
            logger.error(f"Prompts for agent role '{agent_role_name}' not found in MD library.")
            return {"error": f"Prompts for agent role '{agent_role_name}' not found."}

        # Instantiate and execute the BaseAgent
        agent_instance = BaseAgent(agent_role_name, self.config, self.llm_manager_instance, agent_prompts)
        
        results = agent_instance.execute(user_input, additional_context)
        
        # Save results
        campaign_results = {
            "session_id": self.session_id,
            "agent_role": agent_role_name,
            "input": user_input,
            "timestamp": datetime.now().isoformat(),
            "results": results
        }
        self._save_results(campaign_results)
        return campaign_results
    
    def _save_results(self, results: Dict):
        """Save campaign results"""
        output_file = f"results/campaign_{self.session_id}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results saved to {output_file}")
        
        # Generate report
        self._generate_report(results)
    
    def _generate_report(self, results: Dict):
        """Generate professional HTML report with charts and modern CSS"""
        report_file = f"reports/report_{self.session_id}.html"

        # Get data
        llm_response = results.get('results', {}).get('llm_response', '')
        if isinstance(llm_response, dict):
            llm_response = json.dumps(llm_response, indent=2)

        report_content = mistune.html(llm_response)

        # Extract metrics from report
        targets = results.get('results', {}).get('targets', [results.get('input', 'N/A')])
        if isinstance(targets, str):
            targets = [targets]
        tools_executed = results.get('results', {}).get('tools_executed', 0)

        # Count severities from report text
        critical = len(re.findall(r'\[?Critical\]?', llm_response, re.IGNORECASE))
        high = len(re.findall(r'\[?High\]?', llm_response, re.IGNORECASE))
        medium = len(re.findall(r'\[?Medium\]?', llm_response, re.IGNORECASE))
        low = len(re.findall(r'\[?Low\]?', llm_response, re.IGNORECASE))
        info = len(re.findall(r'\[?Info\]?', llm_response, re.IGNORECASE))
        total_vulns = critical + high + medium + low

        # Risk score calculation
        risk_score = min(100, (critical * 25) + (high * 15) + (medium * 8) + (low * 3))
        risk_level = "Critical" if risk_score >= 70 else "High" if risk_score >= 50 else "Medium" if risk_score >= 25 else "Low"
        risk_color = "#e74c3c" if risk_score >= 70 else "#e67e22" if risk_score >= 50 else "#f1c40f" if risk_score >= 25 else "#27ae60"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {self.session_id}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1a1f2e;
            --border-color: #2d3748;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #6366f1;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}

        /* Header */
        .header {{
            background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
            padding: 3rem 2rem;
            border-radius: 16px;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }}
        .header-content {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }}
        .logo {{ font-size: 2rem; font-weight: 800; background: linear-gradient(90deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .report-meta {{ text-align: right; color: var(--text-secondary); font-size: 0.9rem; }}

        /* Stats Grid */
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
        .stat-card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--border-color);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }}
        .stat-value {{ font-size: 2.5rem; font-weight: 700; }}
        .stat-label {{ color: var(--text-secondary); font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.5px; }}
        .stat-critical .stat-value {{ color: var(--critical); }}
        .stat-high .stat-value {{ color: var(--high); }}
        .stat-medium .stat-value {{ color: var(--medium); }}
        .stat-low .stat-value {{ color: var(--low); }}

        /* Risk Score */
        .risk-section {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 2rem; }}
        @media (max-width: 900px) {{ .risk-section {{ grid-template-columns: 1fr; }} }}
        .risk-card {{
            background: var(--bg-card);
            border-radius: 16px;
            padding: 2rem;
            border: 1px solid var(--border-color);
        }}
        .risk-score-circle {{
            width: 180px; height: 180px;
            border-radius: 50%;
            background: conic-gradient({risk_color} 0deg, {risk_color} {risk_score * 3.6}deg, #2d3748 {risk_score * 3.6}deg);
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 1rem;
        }}
        .risk-score-inner {{
            width: 140px; height: 140px;
            border-radius: 50%;
            background: var(--bg-card);
            display: flex; flex-direction: column; align-items: center; justify-content: center;
        }}
        .risk-score-value {{ font-size: 3rem; font-weight: 800; color: {risk_color}; }}
        .risk-score-label {{ color: var(--text-secondary); font-size: 0.875rem; }}
        .chart-container {{ height: 250px; }}

        /* Targets */
        .targets-list {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 1rem; }}
        .target-tag {{
            background: rgba(59, 130, 246, 0.2);
            border: 1px solid var(--accent);
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-family: monospace;
        }}

        /* Main Report */
        .report-section {{
            background: var(--bg-card);
            border-radius: 16px;
            padding: 2rem;
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
        }}
        .section-title {{
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid var(--accent);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .section-title::before {{
            content: '';
            width: 4px;
            height: 24px;
            background: var(--accent);
            border-radius: 2px;
        }}

        /* Vulnerability Cards */
        .report-content h2 {{
            background: linear-gradient(90deg, var(--bg-secondary), transparent);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            margin: 2rem 0 1rem;
            border-left: 4px solid var(--accent);
            font-size: 1.25rem;
        }}
        .report-content h2:has-text("Critical"), .report-content h2:contains("CRITICAL") {{ border-left-color: var(--critical); }}
        .report-content h3 {{ color: var(--accent); margin: 1.5rem 0 0.75rem; font-size: 1.1rem; }}
        .report-content table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }}
        .report-content th, .report-content td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        .report-content th {{ background: rgba(59, 130, 246, 0.1); color: var(--accent); font-weight: 600; }}
        .report-content pre {{
            background: #0d1117;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            overflow-x: auto;
            margin: 1rem 0;
        }}
        .report-content code {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.875rem;
        }}
        .report-content p {{ margin: 0.75rem 0; }}
        .report-content hr {{ border: none; border-top: 1px solid var(--border-color); margin: 2rem 0; }}
        .report-content ul, .report-content ol {{ margin: 1rem 0; padding-left: 1.5rem; }}
        .report-content li {{ margin: 0.5rem 0; }}

        /* Severity Badges */
        .report-content h2 {{ position: relative; }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
            border-top: 1px solid var(--border-color);
            margin-top: 3rem;
        }}

        /* Print Styles */
        @media print {{
            body {{ background: white; color: black; }}
            .stat-card, .risk-card, .report-section {{ border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div>
                    <div class="logo">NeuroSploit</div>
                    <p style="color: var(--text-secondary); margin-top: 0.5rem;">AI-Powered Security Assessment Report</p>
                </div>
                <div class="report-meta">
                    <div><strong>Report ID:</strong> {self.session_id}</div>
                    <div><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
                    <div><strong>Agent:</strong> {results.get('agent_role', 'Security Analyst')}</div>
                </div>
            </div>
            <div class="targets-list">
                {''.join(f'<span class="target-tag">{t}</span>' for t in targets[:5])}
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card stat-critical">
                <div class="stat-value">{critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card stat-high">
                <div class="stat-value">{high}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card stat-medium">
                <div class="stat-value">{medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card stat-low">
                <div class="stat-value">{low}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--accent);">{tools_executed}</div>
                <div class="stat-label">Tests Run</div>
            </div>
        </div>

        <div class="risk-section">
            <div class="risk-card">
                <h3 style="text-align: center; margin-bottom: 1rem; color: var(--text-secondary);">Risk Score</h3>
                <div class="risk-score-circle">
                    <div class="risk-score-inner">
                        <div class="risk-score-value">{risk_score}</div>
                        <div class="risk-score-label">{risk_level}</div>
                    </div>
                </div>
            </div>
            <div class="risk-card">
                <h3 style="margin-bottom: 1rem; color: var(--text-secondary);">Severity Distribution</h3>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
        </div>

        <div class="report-section">
            <div class="section-title">Vulnerability Report</div>
            <div class="report-content">
                {report_content}
            </div>
        </div>

        <div class="footer">
            <p>Generated by <strong>NeuroSploit</strong> - AI-Powered Penetration Testing Framework</p>
            <p style="margin-top: 0.5rem;">Confidential - For authorized personnel only</p>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script>
        hljs.highlightAll();

        // Severity Chart
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [{critical}, {high}, {medium}, {low}, {info}],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#6366f1'],
                    borderWidth: 0,
                    hoverOffset: 10
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{ color: '#94a3b8', padding: 15, font: {{ size: 12 }} }}
                    }}
                }},
                cutout: '60%'
            }}
        }});
    </script>
</body>
</html>"""
        
        with open(report_file, 'w') as f:
            f.write(html)
        
        logger.info(f"Report generated: {report_file}")

    def execute_real_scan(self, target: str, scan_type: str = "full", agent_role: str = None) -> Dict:
        """
        Execute a real penetration test with actual tools and generate professional report.

        Args:
            target: The target URL or IP to scan
            scan_type: "full" for comprehensive scan, "quick" for essential checks
            agent_role: Optional agent role for AI analysis of results
        """
        print(f"\n{'='*70}")
        print("    NeuroSploitv2 - Real Penetration Test Execution")
        print(f"{'='*70}")
        print(f"\n[*] Target: {target}")
        print(f"[*] Scan Type: {scan_type}")
        print(f"[*] Session ID: {self.session_id}\n")

        # Check for required tools
        print("[*] Checking required tools...")
        missing_tools = []
        essential_tools = ["nmap", "curl"]
        for tool in essential_tools:
            installed, path = self.tool_installer.check_tool_installed(tool)
            if not installed:
                missing_tools.append(tool)
                print(f"    [-] {tool}: NOT INSTALLED")
            else:
                print(f"    [+] {tool}: {path}")

        if missing_tools:
            print(f"\n[!] Missing required tools: {', '.join(missing_tools)}")
            print("[!] Run 'install_tools' to install required tools.")
            return {"error": f"Missing tools: {missing_tools}"}

        # Execute the scan
        executor = PentestExecutor(target, self.config)

        if scan_type == "quick":
            scan_result = executor.run_quick_scan()
        else:
            scan_result = executor.run_full_scan()

        # Get results as dictionary
        results_dict = executor.to_dict()

        # Get AI analysis if agent role specified
        llm_analysis = ""
        if agent_role:
            print(f"\n[*] Running AI analysis with {agent_role}...")
            llm_profile = self.config.get('agent_roles', {}).get(agent_role, {}).get('llm_profile')
            self._initialize_llm_manager(llm_profile)

            if self.llm_manager_instance:
                agent_prompts = self.llm_manager_instance.prompts.get("md_prompts", {}).get(agent_role, {})
                if agent_prompts:
                    agent = BaseAgent(agent_role, self.config, self.llm_manager_instance, agent_prompts)
                    analysis_input = f"""
Analyze the following penetration test results and provide a detailed security assessment:

Target: {target}
Scan Type: {scan_type}

SCAN RESULTS:
{json.dumps(results_dict, indent=2)}

Provide:
1. Executive summary of findings
2. Risk assessment
3. Detailed analysis of each vulnerability
4. Prioritized remediation recommendations
5. Additional attack vectors to explore
"""
                    analysis_result = agent.execute(analysis_input, results_dict)
                    llm_analysis = analysis_result.get("llm_response", "")

        # Generate professional report
        print("\n[*] Generating professional report...")
        report_gen = ReportGenerator(results_dict, llm_analysis)
        html_report = report_gen.save_report("reports")
        json_report = report_gen.save_json_report("results")

        print(f"\n{'='*70}")
        print("[+] Scan Complete!")
        print(f"    - Vulnerabilities Found: {len(results_dict.get('vulnerabilities', []))}")
        print(f"    - HTML Report: {html_report}")
        print(f"    - JSON Results: {json_report}")
        print(f"{'='*70}\n")

        return {
            "session_id": self.session_id,
            "target": target,
            "scan_type": scan_type,
            "results": results_dict,
            "html_report": html_report,
            "json_report": json_report
        }

    def check_tools_status(self):
        """Check and display status of all pentest tools"""
        print("\n" + "="*60)
        print("    PENTEST TOOLS STATUS")
        print("="*60 + "\n")

        status = self.tool_installer.get_tools_status()
        installed_count = 0
        missing_count = 0

        for tool_name, info in status.items():
            if info["installed"]:
                print(f"  [+] {tool_name:15} - INSTALLED ({info['path']})")
                installed_count += 1
            else:
                print(f"  [-] {tool_name:15} - NOT INSTALLED")
                missing_count += 1

        print("\n" + "-"*60)
        print(f"  Total: {installed_count} installed, {missing_count} missing")
        print("-"*60)

        if missing_count > 0:
            print("\n  [!] Run 'install_tools' to install missing tools")

        return status

    def update_tools_config(self):
        """Update config with found tool paths"""
        status = self.tool_installer.get_tools_status()

        for tool_name, info in status.items():
            if info["installed"] and info["path"]:
                self.config['tools'][tool_name] = info["path"]

        # Save updated config
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=4)

        logger.info("Tools configuration updated")

    def list_agent_roles(self):
        """List all available agent roles."""
        print("\nAvailable Agent Roles:")
        for role_name, role_details in self.config.get('agent_roles', {}).items():
            status = "Enabled" if role_details.get("enabled") else "Disabled"
            print(f"  - {role_name} ({status}): {role_details.get('description', 'No description.')}")

    def list_llm_profiles(self):
        """List all available LLM profiles."""
        print("\nAvailable LLM Profiles:")
        for profile_name in self.config.get('llm', {}).get('profiles', {}).keys():
            print(f"  - {profile_name}")
    
    def interactive_mode(self):
        """Start interactive mode"""
        
        completer = Completer(self)
        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")

        print("""
        ╔═══════════════════════════════════════════════════════════╗
        ║         NeuroSploitv2 - AI Offensive Security             ║
        ║                  Interactive Mode                         ║
        ╚═══════════════════════════════════════════════════════════╝
        """)
        
        while True:
            try:
                cmd = input("\nNeuroSploit> ").strip()
                
                if cmd.lower() in ['exit', 'quit']:
                    break
                elif cmd.lower() == 'help':
                    self._show_help()
                elif cmd.startswith('run_agent'):
                    parts = cmd.split(maxsplit=2) # e.g., run_agent red_team_agent "scan example.com"
                    if len(parts) >= 2:
                        if len(parts) == 2:
                            if self.selected_agent_role:
                                user_input = parts[1].strip('"')
                                self.execute_agent_role(self.selected_agent_role, user_input)
                            else:
                                print("No agent selected. Use 'set_agent <agent_name>' or 'run_agent <agent_name> \"<user_input>\"'")
                        else:
                            agent_role_name = parts[1]
                            user_input = parts[2].strip('"')
                            self.execute_agent_role(agent_role_name, user_input)
                    else:
                        print("Usage: run_agent <agent_role_name> \"<user_input>\"")

                elif cmd.startswith('config'):
                    print(json.dumps(self.config, indent=2))
                elif cmd.lower() == 'list_roles':
                    print("\nAvailable Agent Roles:")
                    for role_name, role_details in self.config.get('agent_roles', {}).items():
                        status = "Enabled" if role_details.get("enabled") else "Disabled"
                        marker = "*" if role_name == self.selected_agent_role else " "
                        print(f"  {marker} {role_name} ({status}): {role_details.get('description', 'No description.')}")
                elif cmd.lower() == 'list_profiles':
                    print("\nAvailable LLM Profiles:")
                    default_profile = self.config['llm']['default_profile']
                    for profile_name in self.config.get('llm', {}).get('profiles', {}).keys():
                        marker = "*" if profile_name == default_profile else " "
                        print(f"  {marker} {profile_name}")
                elif cmd.startswith('set_profile'):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        profile_name = parts[1].strip()
                        if profile_name in self.config.get('llm', {}).get('profiles', {}):
                            self.config['llm']['default_profile'] = profile_name
                            print(f"Default LLM profile set to: {profile_name}")
                        else:
                            print(f"Profile '{profile_name}' not found.")
                    else:
                        print("Usage: set_profile <profile_name>")
                elif cmd.startswith('set_agent'):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        agent_name = parts[1].strip()
                        if agent_name in self.config.get('agent_roles', {}):
                            self.selected_agent_role = agent_name
                            print(f"Default agent set to: {agent_name}")
                        else:
                            print(f"Agent '{agent_name}' not found.")
                    else:
                        print("Usage: set_agent <agent_name>")
                elif cmd.lower() == 'discover_ollama':
                    self.discover_ollama_models()
                elif cmd.lower() == 'install_tools':
                    run_installer_menu()
                    self.update_tools_config()
                elif cmd.lower() == 'check_tools':
                    self.check_tools_status()
                elif cmd.startswith('scan '):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        target = parts[1].strip().strip('"')
                        agent_role = self.selected_agent_role or "bug_bounty_hunter"
                        self.execute_real_scan(target, scan_type="full", agent_role=agent_role)
                    else:
                        print("Usage: scan <target_url>")
                elif cmd.startswith('quick_scan '):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        target = parts[1].strip().strip('"')
                        agent_role = self.selected_agent_role or "bug_bounty_hunter"
                        self.execute_real_scan(target, scan_type="quick", agent_role=agent_role)
                    else:
                        print("Usage: quick_scan <target_url>")
                else:
                    print("Unknown command. Type 'help' for available commands.")
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                continue
            except Exception as e:
                logger.error(f"Error: {e}")

    def discover_ollama_models(self):
        """Discover local Ollama models and add them to the configuration."""
        try:
            import requests
        except ImportError:
            print("The 'requests' library is not installed. Please install it with 'pip3 install requests'")
            return

        try:
            response = requests.get("http://localhost:11434/api/tags")
            response.raise_for_status()
            models = response.json().get("models", [])
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError):
            print("Ollama server not found. Please make sure Ollama is running.")
            return

        if not models:
            print("No Ollama models found.")
            return

        print("Available Ollama models:")
        for i, model in enumerate(models):
            print(f"  {i+1}. {model['name']}")

        try:
            selections = input("Enter the numbers of the models to add (e.g., 1,3,4): ")
            selected_indices = [int(s.strip()) - 1 for s in selections.split(',')]
        except ValueError:
            print("Invalid input. Please enter a comma-separated list of numbers.")
            return

        for i in selected_indices:
            if 0 <= i < len(models):
                model_name = models[i]['name']
                profile_name = f"ollama_{model_name.replace(':', '_').replace('-', '_')}"
                self.config['llm']['profiles'][profile_name] = {
                    "provider": "ollama",
                    "model": model_name,
                    "api_key": "",
                    "temperature": 0.7,
                    "max_tokens": 4096,
                    "input_token_limit": 8000,
                    "output_token_limit": 4000,
                    "cache_enabled": True,
                    "search_context_level": "medium",
                    "pdf_support_enabled": False,
                    "guardrails_enabled": True,
                    "hallucination_mitigation_strategy": None
                }
                print(f"Added profile '{profile_name}' for model '{model_name}'.")

        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=4)
        print("Configuration updated.")
    
    def _show_help(self):
        """Show help menu"""
        print("""
=======================================================================
                    NeuroSploitv2 - Command Reference
=======================================================================

SCANNING COMMANDS (Execute Real Tools):
  scan <target>            - Run FULL pentest scan with real tools (nmap, nuclei, nikto, etc.)
  quick_scan <target>      - Run QUICK scan (essential checks only)

TOOL MANAGEMENT:
  install_tools            - Install required pentest tools (nmap, sqlmap, nuclei, etc.)
  check_tools              - Check which tools are installed

AGENT COMMANDS (AI Analysis):
  run_agent <role> "<input>" - Execute AI agent with input
  set_agent <agent_name>     - Set default agent for AI analysis

CONFIGURATION:
  list_roles               - List all available agent roles
  list_profiles            - List all LLM profiles
  set_profile <name>       - Set the default LLM profile
  discover_ollama          - Discover and configure local Ollama models
  config                   - Show current configuration

GENERAL:
  help                     - Show this help menu
  exit/quit                - Exit the framework

EXAMPLES:
  scan https://example.com           - Full pentest scan
  quick_scan 192.168.1.1             - Quick vulnerability check
  install_tools                      - Install nmap, sqlmap, nuclei, etc.
  run_agent bug_bounty_hunter "Analyze https://target.com"
=======================================================================
        """)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='NeuroSploitv2 - AI-Powered Penetration Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run real pentest scan
  python neurosploit.py --scan https://example.com
  python neurosploit.py --quick-scan 192.168.1.1

  # Install required tools
  python neurosploit.py --install-tools

  # AI-powered analysis
  python neurosploit.py --agent-role red_team_agent --input "Analyze target.com"

  # Interactive mode
  python neurosploit.py -i
        """
    )

    # Scanning options
    parser.add_argument('--scan', metavar='TARGET',
                       help='Run FULL pentest scan on target (executes real tools)')
    parser.add_argument('--quick-scan', metavar='TARGET',
                       help='Run QUICK pentest scan on target')

    # Tool management
    parser.add_argument('--install-tools', action='store_true',
                       help='Install required pentest tools (nmap, sqlmap, nuclei, etc.)')
    parser.add_argument('--check-tools', action='store_true',
                       help='Check status of installed tools')

    # Agent options
    parser.add_argument('-r', '--agent-role',
                       help='Name of the agent role to execute')
    parser.add_argument('-i', '--interactive', action='store_true',
                       help='Start in interactive mode')
    parser.add_argument('--input', help='Input prompt/task for the agent role')
    parser.add_argument('--llm-profile', help='LLM profile to use for the execution')

    # Configuration
    parser.add_argument('-c', '--config', default='config/config.json',
                       help='Configuration file path')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--list-agents', action='store_true',
                       help='List all available agent roles and exit')
    parser.add_argument('--list-profiles', action='store_true',
                       help='List all available LLM profiles and exit')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize framework
    framework = NeuroSploitv2(config_path=args.config)

    # Handle tool installation
    if args.install_tools:
        run_installer_menu()
        framework.update_tools_config()

    # Handle tool check
    elif args.check_tools:
        framework.check_tools_status()

    # Handle full scan
    elif args.scan:
        agent_role = args.agent_role or "bug_bounty_hunter"
        framework.execute_real_scan(args.scan, scan_type="full", agent_role=agent_role)

    # Handle quick scan
    elif args.quick_scan:
        agent_role = args.agent_role or "bug_bounty_hunter"
        framework.execute_real_scan(args.quick_scan, scan_type="quick", agent_role=agent_role)

    # Handle list commands
    elif args.list_agents:
        framework.list_agent_roles()
    elif args.list_profiles:
        framework.list_llm_profiles()

    # Handle interactive mode
    elif args.interactive:
        framework.interactive_mode()

    # Handle agent execution
    elif args.agent_role and args.input:
        framework.execute_agent_role(args.agent_role, args.input, llm_profile_override=args.llm_profile)

    else:
        parser.print_help()
        print("\n" + "="*70)
        print("QUICK START:")
        print("  1. Install tools:  python neurosploit.py --install-tools")
        print("  2. Run scan:       python neurosploit.py --scan https://target.com")
        print("  3. Interactive:    python neurosploit.py -i")
        print("="*70)



if __name__ == "__main__":
    main()
