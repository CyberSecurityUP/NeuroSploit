"""
NeuroSploit v3 - Tool Installation Registry for Kali Containers

Maps tool names to installation commands that work inside kalilinux/kali-rolling.
Tools grouped by method: pre-installed (base image), apt (Kali repos), go install, pip.
"""

from typing import Optional, Dict


class ToolRegistry:
    """Registry of tool installation recipes for Kali sandbox containers."""

    # Tools pre-installed in Dockerfile.kali (no install needed)
    PRE_INSTALLED = {
        # Go tools (pre-compiled in builder stage)
        "nuclei", "naabu", "httpx", "subfinder", "katana", "dnsx",
        "uncover", "ffuf", "gobuster", "dalfox", "waybackurls",
        # APT tools (pre-installed in runtime stage)
        "nmap", "nikto", "sqlmap", "masscan", "whatweb",
        # System tools
        "curl", "wget", "git", "python3", "pip3", "go",
        "jq", "dig", "whois", "openssl", "netcat", "bash",
    }

    # APT packages available in Kali repos (on-demand, not pre-installed)
    APT_TOOLS: Dict[str, str] = {
        "wpscan":      "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wpscan",
        "dirb":        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dirb",
        "hydra":       "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq hydra",
        "john":        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq john",
        "hashcat":     "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq hashcat",
        "testssl":     "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq testssl.sh",
        "testssl.sh":  "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq testssl.sh",
        "sslscan":     "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sslscan",
        "enum4linux":  "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq enum4linux",
        "nbtscan":     "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nbtscan",
        "dnsrecon":    "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dnsrecon",
        "fierce":      "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fierce",
        "amass":       "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq amass",
        "responder":   "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq responder",
        "medusa":      "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq medusa",
        "crackmapexec":"apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crackmapexec",
    }

    # Go tools installed via `go install` (on-demand, not pre-compiled)
    GO_TOOLS: Dict[str, str] = {
        "gau":          "github.com/lc/gau/v2/cmd/gau@latest",
        "gitleaks":     "github.com/gitleaks/gitleaks/v8@latest",
        "anew":         "github.com/tomnomnom/anew@latest",
        "httprobe":     "github.com/tomnomnom/httprobe@latest",
    }

    # Python tools via pip
    PIP_TOOLS: Dict[str, str] = {
        "dirsearch": "pip3 install --no-cache-dir --break-system-packages dirsearch",
        "wfuzz":     "pip3 install --no-cache-dir --break-system-packages wfuzz",
        "arjun":     "pip3 install --no-cache-dir --break-system-packages arjun",
        "wafw00f":   "pip3 install --no-cache-dir --break-system-packages wafw00f",
        "sslyze":    "pip3 install --no-cache-dir --break-system-packages sslyze",
        "commix":    "pip3 install --no-cache-dir --break-system-packages commix",
        "trufflehog":"pip3 install --no-cache-dir --break-system-packages trufflehog",
        "retire":    "pip3 install --no-cache-dir --break-system-packages retirejs",
    }

    def get_install_command(self, tool: str) -> Optional[str]:
        """Get the install command for a tool inside a Kali container.

        Returns None if the tool is pre-installed or unknown.
        """
        if tool in self.PRE_INSTALLED:
            return None  # Already available

        if tool in self.APT_TOOLS:
            return self.APT_TOOLS[tool]

        if tool in self.GO_TOOLS:
            go_pkg = self.GO_TOOLS[tool]
            return (
                f"export GOPATH=/root/go && export PATH=$PATH:/root/go/bin && "
                f"go install -v {go_pkg} && "
                f"cp /root/go/bin/{tool} /usr/local/bin/ 2>/dev/null || true"
            )

        if tool in self.PIP_TOOLS:
            return self.PIP_TOOLS[tool]

        return None

    def is_known(self, tool: str) -> bool:
        """Check if we have a recipe for this tool."""
        return (
            tool in self.PRE_INSTALLED
            or tool in self.APT_TOOLS
            or tool in self.GO_TOOLS
            or tool in self.PIP_TOOLS
        )

    def all_tools(self) -> Dict[str, str]:
        """Return all known tools and their install method."""
        result = {}
        for t in self.PRE_INSTALLED:
            result[t] = "pre-installed"
        for t in self.APT_TOOLS:
            result[t] = "apt"
        for t in self.GO_TOOLS:
            result[t] = "go"
        for t in self.PIP_TOOLS:
            result[t] = "pip"
        return result
