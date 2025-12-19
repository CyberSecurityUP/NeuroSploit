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
from agents.base_agent import BaseAgent

class Completer:
    def __init__(self, neurosploit):
        self.neurosploit = neurosploit
        self.commands = ["help", "run_agent", "config", "list_roles", "list_profiles", "set_profile", "set_agent", "discover_ollama", "exit", "quit"]
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

        if not role_config:
            logger.error(f"Agent role '{agent_role_name}' not found in configuration.")
            return {"error": f"Agent role '{agent_role_name}' not found."}
        
        if not role_config.get('enabled', False):
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
        """Generate HTML report for agent role execution"""
        report_file = f"reports/report_{self.session_id}.html"
        
        llm_response = results.get('results', {}).get('llm_response', '')
        if isinstance(llm_response, dict):
            llm_response = json.dumps(llm_response, indent=2)
            
        report_content = mistune.html(llm_response)

        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>NeuroSploitv2 Report - {results['session_id']}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
            <style>
                body {{
                    background-color: #121212;
                    color: #e0e0e0;
                }}
                .card {{
                    background-color: #1e1e1e;
                    border: 1px solid #333;
                }}
                .card-header {{
                    background-color: #333;
                    color: #00ff00;
                    font-weight: bold;
                }}
                pre {{
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }}
                .logo {{
                    font-size: 2rem;
                    font-weight: bold;
                    color: #00ff00;
                    text-shadow: 0 0 10px #00ff00;
                }}
                .report-content h2 {{
                    border-bottom: 2px solid #00ff00;
                    padding-bottom: 10px;
                    margin-top: 30px;
                }}
            </style>
        </head>
        <body>
            <div class="container mt-5">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h1 class="logo">NeuroSploitv2</h1>
                    <span class="text-muted">Report ID: {results['session_id']}</span>
                </div>

                <div class="card mb-4">
                    <div class="card-header">
                        Execution Summary
                    </div>
                    <div class="card-body">
                        <p><strong>Agent Role:</strong> {results.get('agent_role', 'N/A')}</p>
                        <p><strong>Input:</strong> {results.get('input', 'N/A')}</p>
                        <p><strong>Timestamp:</strong> {results['timestamp']}</p>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        Vulnerability Report
                    </div>
                    <div class="card-body report-content">
                        {report_content}
                    </div>
                </div>
            </div>

            <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
            <script>hljs.highlightAll();</script>
        </body>
        </html>
        """
        
        with open(report_file, 'w') as f:
            f.write(html)
        
        logger.info(f"Report generated: {report_file}")

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
Available Commands:
  run_agent <role> "<input>"- Execute a specific agent role (e.g., run_agent red_team_agent "scan target.com")
  set_agent <agent_name>   - Set the default agent for the session
  list_roles               - List all configured agent roles and their details
  list_profiles            - List all available LLM profiles
  set_profile <name>       - Set the default LLM profile for the session
  discover_ollama          - Discover and configure local Ollama models
  config                   - Show current configuration
  help                     - Show this help menu
  exit/quit                - Exit the framework
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
  python neurosploit.py --list-agents
        """
    )
    
    parser.add_argument('-r', '--agent-role', help='Name of the agent role to execute')
    parser.add_argument('-i', '--interactive', action='store_true',
                       help='Start in interactive mode')
    parser.add_argument('--input', help='Input prompt/task for the agent role')
    parser.add_argument('--llm-profile', help='LLM profile to use for the execution')
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
    
    if args.list_agents:
        framework.list_agent_roles()
    elif args.list_profiles:
        framework.list_llm_profiles()
    elif args.interactive:
        framework.interactive_mode()
    elif args.agent_role and args.input:
        framework.execute_agent_role(args.agent_role, args.input, llm_profile_override=args.llm_profile)
    else:
        parser.print_help()
        print("\n[!] Please specify an agent role and input, use --list-agents to see available agents, or use interactive mode (-i)")



if __name__ == "__main__":
    main()
