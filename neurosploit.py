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
from pathlib import Path
from typing import Dict, List, Optional
import logging
from datetime import datetime

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
from agents.base_agent import BaseAgent

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
        
        logger.info(f"NeuroSploitv2 initialized - Session: {self.session_id}")
        
    def _setup_directories(self):
        """Create necessary directories"""
        dirs = ['logs', 'reports', 'data', 'custom_agents', 'results']
        for d in dirs:
            Path(d).mkdir(exist_ok=True)
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return self._create_default_config()
    
    def _create_default_config(self) -> Dict:
        """Create default configuration"""
        config = {
            "llm": {
                "provider": "gemini",
                "model": "gemini-pro",
                "api_key": "",
                "temperature": 0.7,
                "max_tokens": 4096
            },
            "agent_roles": {
                "bug_bounty_hunter": {
                    "enabled": True,
                    "llm_profile": "gemini_pro_default",
                    "tools_allowed": ["subfinder", "nuclei", "burpsuite", "sqlmap"],
                    "description": "Focuses on web application vulnerabilities, leveraging recon and exploitation tools."
                },
                "blue_team_agent": {
                    "enabled": True,
                    "llm_profile": "claude_opus_default",
                    "tools_allowed": [],
                    "description": "Analyzes logs and telemetry for threats, provides defensive strategies."
                },
                "exploit_expert": {
                    "enabled": True,
                    "llm_profile": "gpt_4o_default",
                    "tools_allowed": ["metasploit", "nmap"],
                    "description": "Devises exploitation strategies and payloads for identified vulnerabilities."
                },
                "red_team_agent": {
                    "enabled": True,
                    "llm_profile": "gemini_pro_default",
                    "tools_allowed": ["nmap", "metasploit", "hydra"],
                    "description": "Plans and executes simulated attacks to test an organization's defenses."
                },
                "replay_attack_specialist": {
                    "enabled": True,
                    "llm_profile": "ollama_llama3_default",
                    "tools_allowed": ["burpsuite"],
                    "description": "Identifies and leverages replay attack vectors in network traffic or authentication."
                },
                "pentest_generalist": {
                    "enabled": True,
                    "llm_profile": "gemini_pro_default",
                    "tools_allowed": ["nmap", "subfinder", "nuclei", "metasploit", "burpsuite", "sqlmap", "hydra"],
                    "description": "Performs comprehensive penetration tests across various domains."
                },
                "owasp_expert": {
                    "enabled": True,
                    "llm_profile": "gemini_pro_default",
                    "tools_allowed": ["burpsuite", "sqlmap"],
                    "description": "Specializes in assessing web applications against OWASP Top 10 vulnerabilities."
                },
                "cwe_expert": {
                    "enabled": True,
                    "llm_profile": "claude_opus_default",
                    "tools_allowed": [],
                    "description": "Analyzes code and reports for weaknesses based on MITRE CWE Top 25."
                },
                "malware_analyst": {
                    "enabled": True,
                    "llm_profile": "gpt_4o_default",
                    "tools_allowed": [],
                    "description": "Examines malware samples to understand functionality and identify IOCs."
                }
            },
            "methodologies": {
                "owasp_top10": True,
                "cwe_top25": True,
                "network_pentest": True,
                "ad_pentest": True,
                "web_security": True
            },
            "tools": {
                "nmap": "/usr/bin/nmap",
                "metasploit": "/usr/bin/msfconsole",
                "burpsuite": "/usr/bin/burpsuite",
                "sqlmap": "/usr/bin/sqlmap",
                "hydra": "/usr/bin/hydra"
            },
            "output": {
                "format": "json",
                "verbose": True,
                "save_artifacts": True
            }
        }
        
        # Save default config
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=4)
        
        logger.info(f"Created default configuration at {self.config_path}")
        return config
    

    
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

    def execute_agent_role(self, agent_role_name: str, user_input: str, additional_context: Optional[Dict] = None):
        """Execute a specific agent role with a given input."""
        logger.info(f"Starting execution for agent role: {agent_role_name}")

        agent_roles_config = self.config.get('agent_roles', {})
        role_config = agent_roles_config.get(agent_role_name)

        if not role_config:
            logger.error(f"Agent role '{agent_role_name}' not found in configuration.")
            return {"error": f"Agent role '{agent_role_name}' not found."}
        
        if not role_config.get('enabled', False):
            logger.warning(f"Agent role '{agent_role_name}' is disabled in configuration.")
            return {"warning": f"Agent role '{agent_role_name}' is disabled."}

        llm_profile_name = role_config.get('llm_profile', self.config['llm']['default_profile'])
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
        """Generate HTML report for agent role execution"""
        report_file = f"reports/report_{self.session_id}.html"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NeuroSploitv2 Report - {results['session_id']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #fff; }}
                h1 {{ color: #00ff00; }}
                h2 {{ color: #00ccff; border-bottom: 2px solid #00ccff; }}
                .phase {{ background: #2d2d2d; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .finding {{ background: #3d3d3d; padding: 10px; margin: 5px 0; border-left: 3px solid #ff6600; }}
                .success {{ color: #00ff00; }}
                .warning {{ color: #ffaa00; }}
                .error {{ color: #ff0000; }}
            </style>
        </head>
        <body>
            <h1>NeuroSploitv2 Agent Role Execution Report</h1>
            <p><strong>Agent Role:</strong> {results.get('agent_role', 'N/A')}</p>
            <p><strong>Input:</strong> {results.get('input', 'N/A')}</p>
            <p><strong>Session:</strong> {results['session_id']}</p>
            <p><strong>Timestamp:</strong> {results['timestamp']}</p>
            <hr>
        """
        
        html += f"<h2>Agent Results: {results.get('agent_role', 'N/A').replace('_', ' ').title()}</h2>"
        html += f"<div class='phase'><pre>{json.dumps(results.get('results', {}), indent=2)}</pre></div>"
        
        html += "</body></html>"
        
        with open(report_file, 'w') as f:
            f.write(html)
        
        logger.info(f"Report generated: {report_file}")
    
    def interactive_mode(self):
        """Start interactive mode"""
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
                    if len(parts) >= 3:
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
                        print(f"  - {role_name} ({status}): {role_details.get('description', 'No description.')}")
                        print(f"    LLM Profile: {role_details.get('llm_profile', 'default')}")
                        print(f"    Tools Allowed: {', '.join(role_details.get('tools_allowed', [])) or 'None'}")
                else:
                    print("Unknown command. Type 'help' for available commands.")
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                logger.error(f"Error: {e}")
    
    def _show_help(self):
        """Show help menu"""
        print("""
Available Commands:
  run_agent <role> "<input>"- Execute a specific agent role (e.g., run_agent red_team_agent "scan target.com")
  list_roles         - List all configured agent roles and their details
  config             - Show current configuration
  help               - Show this help menu
  exit/quit          - Exit the framework
        """)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='NeuroSploitv2 - AI-Powered Penetration Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python neurosploit.py --agent-role red_team_agent --input "Scan example.com for vulnerabilities"
  python neurosploit.py -i
        """
    )
    
    parser.add_argument('-r', '--agent-role', help='Name of the agent role to execute')
    parser.add_argument('-i', '--interactive', action='store_true',
                       help='Start in interactive mode')
    parser.add_argument('--input', help='Input prompt/task for the agent role')
    parser.add_argument('-c', '--config', default='config/config.json',
                       help='Configuration file path')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize framework
    framework = NeuroSploitv2(config_path=args.config)
    
    if args.interactive:
        framework.interactive_mode()
    elif args.agent_role and args.input:
        framework.execute_agent_role(args.agent_role, args.input)
    else:
        parser.print_help()
        print("\n[!] Please specify an agent role and input or use interactive mode (-i)")


if __name__ == "__main__":
    main()
