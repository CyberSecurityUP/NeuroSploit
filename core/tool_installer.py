#!/usr/bin/env python3
"""
Tool Installer - Installs required pentest tools for NeuroSploitv2
"""

import subprocess
import shutil
import os
import sys
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

# Tool definitions with installation commands for different package managers
PENTEST_TOOLS = {
    "nmap": {
        "description": "Network scanner and port mapper",
        "check_cmd": "nmap --version",
        "install": {
            "apt": "sudo apt-get install -y nmap",
            "yum": "sudo yum install -y nmap",
            "dnf": "sudo dnf install -y nmap",
            "brew": "brew install nmap",
            "pacman": "sudo pacman -S --noconfirm nmap"
        },
        "binary": "nmap"
    },
    "sqlmap": {
        "description": "SQL injection detection and exploitation",
        "check_cmd": "sqlmap --version",
        "install": {
            "apt": "sudo apt-get install -y sqlmap",
            "yum": "sudo pip3 install sqlmap",
            "dnf": "sudo dnf install -y sqlmap",
            "brew": "brew install sqlmap",
            "pacman": "sudo pacman -S --noconfirm sqlmap",
            "pip": "pip3 install sqlmap"
        },
        "binary": "sqlmap"
    },
    "nikto": {
        "description": "Web server vulnerability scanner",
        "check_cmd": "nikto -Version",
        "install": {
            "apt": "sudo apt-get install -y nikto",
            "yum": "sudo yum install -y nikto",
            "dnf": "sudo dnf install -y nikto",
            "brew": "brew install nikto",
            "pacman": "sudo pacman -S --noconfirm nikto"
        },
        "binary": "nikto"
    },
    "gobuster": {
        "description": "Directory/file & DNS busting tool",
        "check_cmd": "gobuster version",
        "install": {
            "apt": "sudo apt-get install -y gobuster",
            "brew": "brew install gobuster",
            "go": "go install github.com/OJ/gobuster/v3@latest"
        },
        "binary": "gobuster"
    },
    "nuclei": {
        "description": "Fast vulnerability scanner based on templates",
        "check_cmd": "nuclei -version",
        "install": {
            "go": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "brew": "brew install nuclei"
        },
        "binary": "nuclei"
    },
    "subfinder": {
        "description": "Subdomain discovery tool",
        "check_cmd": "subfinder -version",
        "install": {
            "go": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "brew": "brew install subfinder"
        },
        "binary": "subfinder"
    },
    "httpx": {
        "description": "HTTP toolkit for probing",
        "check_cmd": "httpx -version",
        "install": {
            "go": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "brew": "brew install httpx"
        },
        "binary": "httpx"
    },
    "ffuf": {
        "description": "Fast web fuzzer",
        "check_cmd": "ffuf -V",
        "install": {
            "apt": "sudo apt-get install -y ffuf",
            "go": "go install github.com/ffuf/ffuf/v2@latest",
            "brew": "brew install ffuf"
        },
        "binary": "ffuf"
    },
    "hydra": {
        "description": "Network login cracker",
        "check_cmd": "hydra -h",
        "install": {
            "apt": "sudo apt-get install -y hydra",
            "yum": "sudo yum install -y hydra",
            "dnf": "sudo dnf install -y hydra",
            "brew": "brew install hydra",
            "pacman": "sudo pacman -S --noconfirm hydra"
        },
        "binary": "hydra"
    },
    "whatweb": {
        "description": "Web technology identifier",
        "check_cmd": "whatweb --version",
        "install": {
            "apt": "sudo apt-get install -y whatweb",
            "brew": "brew install whatweb",
            "gem": "sudo gem install whatweb"
        },
        "binary": "whatweb"
    },
    "wpscan": {
        "description": "WordPress vulnerability scanner",
        "check_cmd": "wpscan --version",
        "install": {
            "apt": "sudo apt-get install -y wpscan",
            "brew": "brew install wpscan",
            "gem": "sudo gem install wpscan"
        },
        "binary": "wpscan"
    },
    "curl": {
        "description": "HTTP client for requests",
        "check_cmd": "curl --version",
        "install": {
            "apt": "sudo apt-get install -y curl",
            "yum": "sudo yum install -y curl",
            "dnf": "sudo dnf install -y curl",
            "brew": "brew install curl",
            "pacman": "sudo pacman -S --noconfirm curl"
        },
        "binary": "curl"
    },
    "jq": {
        "description": "JSON processor for parsing outputs",
        "check_cmd": "jq --version",
        "install": {
            "apt": "sudo apt-get install -y jq",
            "yum": "sudo yum install -y jq",
            "dnf": "sudo dnf install -y jq",
            "brew": "brew install jq",
            "pacman": "sudo pacman -S --noconfirm jq"
        },
        "binary": "jq"
    },
    "dirsearch": {
        "description": "Web path discovery tool",
        "check_cmd": "dirsearch --version",
        "install": {
            "pip": "pip3 install dirsearch"
        },
        "binary": "dirsearch"
    },
    "wafw00f": {
        "description": "Web Application Firewall detection",
        "check_cmd": "wafw00f -h",
        "install": {
            "pip": "pip3 install wafw00f"
        },
        "binary": "wafw00f"
    }
}


class ToolInstaller:
    """Manages installation of pentest tools"""

    def __init__(self):
        self.package_manager = self._detect_package_manager()

    def _detect_package_manager(self) -> str:
        """Detect the system's package manager"""
        managers = [
            ("apt-get", "apt"),
            ("dnf", "dnf"),
            ("yum", "yum"),
            ("pacman", "pacman"),
            ("brew", "brew")
        ]

        for cmd, name in managers:
            if shutil.which(cmd):
                return name

        # Fallback to pip for Python tools
        return "pip"

    def check_tool_installed(self, tool_name: str) -> Tuple[bool, str]:
        """Check if a tool is installed and return its path"""
        tool_info = PENTEST_TOOLS.get(tool_name)
        if not tool_info:
            return False, ""

        binary = tool_info.get("binary", tool_name)
        path = shutil.which(binary)

        if path:
            return True, path

        # Check common paths
        common_paths = [
            f"/usr/bin/{binary}",
            f"/usr/local/bin/{binary}",
            f"/opt/{binary}/{binary}",
            os.path.expanduser(f"~/go/bin/{binary}"),
            f"/snap/bin/{binary}"
        ]

        for p in common_paths:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return True, p

        return False, ""

    def get_tools_status(self) -> Dict[str, Dict]:
        """Get installation status of all tools"""
        status = {}
        for tool_name, tool_info in PENTEST_TOOLS.items():
            installed, path = self.check_tool_installed(tool_name)
            status[tool_name] = {
                "installed": installed,
                "path": path,
                "description": tool_info["description"]
            }
        return status

    def install_tool(self, tool_name: str) -> Tuple[bool, str]:
        """Install a specific tool"""
        if tool_name not in PENTEST_TOOLS:
            return False, f"Unknown tool: {tool_name}"

        tool_info = PENTEST_TOOLS[tool_name]
        install_cmds = tool_info.get("install", {})

        # Try package manager first
        if self.package_manager in install_cmds:
            cmd = install_cmds[self.package_manager]
        elif "pip" in install_cmds:
            cmd = install_cmds["pip"]
        elif "go" in install_cmds and shutil.which("go"):
            cmd = install_cmds["go"]
        elif "gem" in install_cmds and shutil.which("gem"):
            cmd = install_cmds["gem"]
        else:
            return False, f"No installation method available for {tool_name} on this system"

        print(f"[*] Installing {tool_name}...")
        print(f"    Command: {cmd}")

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                # Verify installation
                installed, path = self.check_tool_installed(tool_name)
                if installed:
                    return True, f"Successfully installed {tool_name} at {path}"
                else:
                    return True, f"Installation completed but binary not found in PATH"
            else:
                return False, f"Installation failed: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, "Installation timed out"
        except Exception as e:
            return False, f"Installation error: {str(e)}"

    def install_all_tools(self) -> Dict[str, Tuple[bool, str]]:
        """Install all pentest tools"""
        results = {}
        for tool_name in PENTEST_TOOLS:
            installed, path = self.check_tool_installed(tool_name)
            if installed:
                results[tool_name] = (True, f"Already installed at {path}")
            else:
                results[tool_name] = self.install_tool(tool_name)
        return results

    def install_essential_tools(self) -> Dict[str, Tuple[bool, str]]:
        """Install only essential tools for basic pentesting"""
        essential = ["nmap", "sqlmap", "nikto", "nuclei", "curl", "jq", "httpx", "ffuf"]
        results = {}
        for tool_name in essential:
            installed, path = self.check_tool_installed(tool_name)
            if installed:
                results[tool_name] = (True, f"Already installed at {path}")
            else:
                results[tool_name] = self.install_tool(tool_name)
        return results


def print_tools_menu():
    """Print the tools installation menu"""
    installer = ToolInstaller()
    status = installer.get_tools_status()

    print("\n" + "="*70)
    print("           PENTEST TOOLS INSTALLATION MANAGER")
    print("="*70)
    print(f"\nDetected Package Manager: {installer.package_manager}")
    print("\nAvailable Tools:")
    print("-"*70)

    for i, (tool_name, info) in enumerate(status.items(), 1):
        status_icon = "[+]" if info["installed"] else "[-]"
        status_text = "Installed" if info["installed"] else "Not Installed"
        print(f"  {i:2}. {status_icon} {tool_name:15} - {info['description'][:40]}")

    print("-"*70)
    print("\nOptions:")
    print("  A  - Install ALL tools")
    print("  E  - Install ESSENTIAL tools only (nmap, sqlmap, nikto, nuclei, etc.)")
    print("  1-N - Install specific tool by number")
    print("  Q  - Return to main menu")
    print("-"*70)

    return installer, list(status.keys())


def run_installer_menu():
    """Run the interactive installer menu"""
    while True:
        installer, tool_list = print_tools_menu()

        choice = input("\nSelect option: ").strip().upper()

        if choice == 'Q':
            break
        elif choice == 'A':
            print("\n[*] Installing all tools...")
            results = installer.install_all_tools()
            for tool, (success, msg) in results.items():
                icon = "[+]" if success else "[!]"
                print(f"  {icon} {tool}: {msg}")
            input("\nPress Enter to continue...")
        elif choice == 'E':
            print("\n[*] Installing essential tools...")
            results = installer.install_essential_tools()
            for tool, (success, msg) in results.items():
                icon = "[+]" if success else "[!]"
                print(f"  {icon} {tool}: {msg}")
            input("\nPress Enter to continue...")
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(tool_list):
                    tool_name = tool_list[idx]
                    success, msg = installer.install_tool(tool_name)
                    icon = "[+]" if success else "[!]"
                    print(f"\n  {icon} {msg}")
                    input("\nPress Enter to continue...")
                else:
                    print("[!] Invalid selection")
            except ValueError:
                print("[!] Invalid input")


if __name__ == "__main__":
    run_installer_menu()
