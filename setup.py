#!/usr/bin/env python3
"""
NeuroSploitv2 Setup and Installation Script
Automatically sets up the framework with all dependencies
"""

import os
import sys
import subprocess
import json
from pathlib import Path

BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║         ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗         ║
║         ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗        ║
║         ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║        ║
║         ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║        ║
║         ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝        ║
║         ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝         ║
║                                                               ║
║            ███████╗██████╗ ██╗      ██████╗ ██╗████████╗     ║
║            ██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝     ║
║            ███████╗██████╔╝██║     ██║   ██║██║   ██║        ║
║            ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║        ║
║            ███████║██║     ███████╗╚██████╔╝██║   ██║        ║
║            ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝        ║
║                            v2.0.0                             ║
║                                                               ║
║      AI-Powered Penetration Testing Framework                ║
║      Author: Security Research Team                          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""


class NeuroSploitSetup:
    """Setup and installation manager"""
    
    def __init__(self):
        self.base_dir = Path.cwd()
        self.required_dirs = [
            'agents',
            'tools/recon',
            'tools/exploitation',
            'tools/privesc',
            'tools/persistence',
            'tools/lateral_movement',
            'core',
            'config',
            'prompts',
            'custom_agents',
            'logs',
            'reports',
            'data',
            'results'
        ]
        
        self.required_packages = [
            'requests',
            'dnspython',
            'anthropic',
            'openai',
            'google-generativeai'
        ]
    
    def run(self):
        """Run complete setup"""
        print(BANNER)
        print("[*] Starting NeuroSploitv2 setup...")
        
        # Check Python version
        if not self.check_python_version():
            print("[!] Python 3.8+ required")
            sys.exit(1)
        
        # Create directory structure
        self.create_directories()
        
        # Install Python packages
        self.install_packages()
        
        # Create configuration files
        self.create_config()
        
        # Create __init__ files
        self.create_init_files()
        
        # Create example custom agent
        self.create_example_agent()
        
        # Create prompts library
        self.create_prompts()
        
        # Final instructions
        self.show_final_instructions()
        
        print("\n[+] Setup completed successfully!")
    
    def check_python_version(self) -> bool:
        """Check Python version"""
        version = sys.version_info
        return version.major == 3 and version.minor >= 8
    
    def create_directories(self):
        """Create directory structure"""
        print("\n[*] Creating directory structure...")
        
        for directory in self.required_dirs:
            path = self.base_dir / directory
            path.mkdir(parents=True, exist_ok=True)
            print(f"    [+] Created: {directory}")
    
    def install_packages(self):
        """Install required Python packages"""
        print("\n[*] Installing Python packages...")
        
        for package in self.required_packages:
            print(f"    [*] Installing {package}...")
            try:
                subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', package, '-q'],
                    check=True
                )
                print(f"    [+] {package} installed")
            except subprocess.CalledProcessError:
                print(f"    [!] Failed to install {package}")
    
    def create_config(self):
        """Create configuration files"""
        print("\n[*] Creating configuration files...")
        
        config = {
            "llm": {
                "default_profile": "gemini_pro_default",
                "profiles": {
                    "gemini_pro_default": {
                        "provider": "gemini",
                        "model": "gemini-pro",
                        "api_key": "${GEMINI_API_KEY}",
                        "temperature": 0.7,
                        "max_tokens": 4096,
                        "input_token_limit": 30720,
                        "output_token_limit": 2048,
                        "cache_enabled": True,
                        "search_context_level": "medium",
                        "pdf_support_enabled": True,
                        "guardrails_enabled": True,
                        "hallucination_mitigation_strategy": "consistency_check"
                    }
                }
            },
            "agent_roles": {
                "pentest_generalist": {
                    "enabled": True,
                    "tools_allowed": ["nmap", "metasploit", "burpsuite", "sqlmap", "hydra"],
                    "description": "Performs comprehensive penetration tests across various domains."
                },
                "bug_bounty_hunter": {
                    "enabled": True,
                    "tools_allowed": ["subfinder", "nuclei", "burpsuite", "sqlmap"],
                    "description": "Focuses on web application vulnerabilities."
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
        
        config_path = self.base_dir / 'config' / 'config.json'
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        
        print(f"    [+] Created config file: {config_path}")
        print("    [!] Please edit config/config.json and add your API keys")
    
    def create_init_files(self):
        """Create __init__.py files"""
        print("\n[*] Creating __init__ files...")
        
        init_dirs = ['agents', 'tools', 'core', 'custom_agents']
        
        for directory in init_dirs:
            init_file = self.base_dir / directory / '__init__.py'
            init_file.touch()
            print(f"    [+] Created: {directory}/__init__.py")
    
    def create_example_agent(self):
        """Create example custom agent"""
        print("\n[*] Creating example custom agent...")
        
        example_agent = '''#!/usr/bin/env python3
"""
Example Custom Agent for NeuroSploitv2
This demonstrates how to create custom agents for specific tasks
"""

import logging
from typing import Dict
from core.llm_manager import LLMManager

logger = logging.getLogger(__name__)


class CustomAgent:
    """Example custom agent - Web API Security Scanner"""
    
    def __init__(self, config: Dict):
        """Initialize custom agent"""
        self.config = config
        self.llm = LLMManager(config)
        self.name = "WebAPIScanner"
        logger.info(f"{self.name} initialized")
    
    def execute(self, target: str, context: Dict) -> Dict:
        """Execute custom agent logic"""
        logger.info(f"Running {self.name} on {target}")
        
        results = {
            "agent": self.name,
            "target": target,
            "status": "running",
            "findings": []
        }
        
        try:
            # Your custom logic here
            # Example: API endpoint testing
            results["findings"] = self._scan_api_endpoints(target)
            
            # Use AI for analysis
            ai_analysis = self._ai_analyze(results["findings"])
            results["ai_analysis"] = ai_analysis
            
            results["status"] = "completed"
            
        except Exception as e:
            logger.error(f"Error in {self.name}: {e}")
            results["status"] = "error"
            results["error"] = str(e)
        
        return results
    
    def _scan_api_endpoints(self, target: str) -> list:
        """Custom scanning logic"""
        # Implement your custom scanning logic
        return [
            {"endpoint": "/api/users", "method": "GET", "auth": "required"},
            {"endpoint": "/api/admin", "method": "POST", "auth": "weak"}
        ]
    
    def _ai_analyze(self, findings: list) -> Dict:
        """Use AI to analyze findings"""
        prompt = f"""
Analyze the following API security findings:

{findings}

Provide:
1. Security assessment
2. Risk prioritization
3. Exploitation recommendations
4. Remediation advice

Response in JSON format.
"""
        
        system_prompt = "You are an API security expert."
        
        try:
            response = self.llm.generate(prompt, system_prompt)
            return {"analysis": response}
        except Exception as e:
            return {"error": str(e)}
'''
        
        agent_file = self.base_dir / 'custom_agents' / 'example_agent.py'
        with open(agent_file, 'w') as f:
            f.write(example_agent)
        
        print(f"    [+] Created: {agent_file}")
    
    def create_prompts(self):
        """Create prompts library"""
        print("\n[*] Creating prompts library...")
        
        prompts = {
            "recon": {
                "network_scan": "Analyze network scan results and identify attack vectors",
                "web_enum": "Enumerate web application for vulnerabilities",
                "osint": "Perform OSINT analysis on target organization"
            },
            "exploitation": {
                "web_vuln": "Generate exploit for identified web vulnerability",
                "network_exploit": "Create network service exploitation strategy",
                "payload_generation": "Generate obfuscated payload for target system"
            },
            "privesc": {
                "linux": "Analyze Linux system for privilege escalation paths",
                "windows": "Identify Windows privilege escalation opportunities",
                "kernel": "Recommend kernel exploits for target version"
            },
            "persistence": {
                "backdoor": "Design stealthy persistence mechanism",
                "scheduled_task": "Create covert scheduled task for persistence"
            },
            "lateral_movement": {
                "ad_attack": "Plan Active Directory attack path",
                "credential_reuse": "Strategy for credential reuse across network"
            }
        }
        
        prompts_file = self.base_dir / 'prompts' / 'library.json'
        with open(prompts_file, 'w') as f:
            json.dump(prompts, f, indent=4)
        
        print(f"    [+] Created: {prompts_file}")
    
    def show_final_instructions(self):
        """Show final setup instructions"""
        print("\n" + "="*60)
        print("SETUP COMPLETED - Next Steps:")
        print("="*60)
        print("""
1. Configure API Keys:
   - Edit config/config.json
   - Add your LLM provider API keys (Claude, GPT, Gemini, etc.)

2. Verify Tool Installation:
   - Ensure nmap, metasploit, sqlmap are installed
   - Update tool paths in config/config.json if needed

3. Test Installation:
   - Run: python neurosploit.py -i (interactive mode)
   - Run: python neurosploit.py -t <target> -m full

4. Create Custom Agents:
   - Check custom_agents/example_agent.py for template
   - Add your custom agents to custom_agents/ directory

5. Configure Gemini CLI (if using):
   - Install: pip install google-generativeai
   - Or use the gemini CLI tool

6. Review Documentation:
   - Check prompts/library.json for prompt templates
   - Explore agents/ directory for core agents

Example Usage:
  # Interactive mode
  python neurosploit.py -i

  # Scan target
  python neurosploit.py -t 192.168.1.0/24 -m network

  # Web application test
  python neurosploit.py -t https://example.com -m web

  # Active Directory test
  python neurosploit.py -t domain.local -m ad

For help: python neurosploit.py --help
""")


if __name__ == "__main__":
    setup = NeuroSploitSetup()
    setup.run()
