#!/usr/bin/env python3
"""
NeuroSploit Security Sandbox Manager

Manages Docker-based security tool execution in an isolated container.
Provides high-level API for running Nuclei, Naabu, and other tools.

Architecture:
  - Persistent sandbox container (neurosploit-sandbox) stays running
  - Tools executed via `docker exec` for sub-second startup
  - Output collected from container stdout + output files
  - Resource limits enforced (2GB RAM, 2 CPU)
  - Network isolation with controlled egress
"""

import asyncio
import json
import logging
import os
import re
import shlex
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)

# Guard Docker SDK import
try:
    import docker
    from docker.errors import DockerException, NotFound, APIError
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False
    logger.warning("Docker SDK not installed. Install with: pip install docker")


@dataclass
class SandboxResult:
    """Result from a sandboxed tool execution."""
    tool: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    findings: List[Dict] = field(default_factory=list)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Nuclei output parser
# ---------------------------------------------------------------------------
def parse_nuclei_jsonl(output: str) -> List[Dict]:
    """Parse Nuclei JSONL output into structured findings."""
    findings = []
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }

    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            info = data.get("info", {})
            tags = info.get("tags", [])
            findings.append({
                "title": info.get("name", "Unknown"),
                "severity": severity_map.get(info.get("severity", "info"), "info"),
                "vulnerability_type": tags[0] if tags else "vulnerability",
                "description": info.get("description", ""),
                "affected_endpoint": data.get("matched-at", ""),
                "evidence": data.get("matcher-name", ""),
                "template_id": data.get("template-id", ""),
                "curl_command": data.get("curl-command", ""),
                "remediation": info.get("remediation", "Review and fix the vulnerability"),
                "references": info.get("reference", []),
                "cwe": info.get("classification", {}).get("cwe-id", []),
                "cvss_score": info.get("classification", {}).get("cvss-score", 0),
            })
        except (json.JSONDecodeError, KeyError):
            continue

    return findings


# ---------------------------------------------------------------------------
# Naabu output parser
# ---------------------------------------------------------------------------
def parse_naabu_output(output: str) -> List[Dict]:
    """Parse Naabu output into structured port findings."""
    findings = []
    seen = set()

    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Naabu JSON mode: {"host":"x","ip":"y","port":80}
        try:
            data = json.loads(line)
            host = data.get("host", data.get("ip", ""))
            port = data.get("port", 0)
            key = f"{host}:{port}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "host": host,
                    "port": port,
                    "protocol": "tcp",
                })
            continue
        except (json.JSONDecodeError, KeyError):
            pass

        # Text mode: host:port
        match = re.match(r"^(.+?):(\d+)$", line)
        if match:
            host, port = match.group(1), int(match.group(2))
            key = f"{host}:{port}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "host": host,
                    "port": port,
                    "protocol": "tcp",
                })

    return findings


class BaseSandbox(ABC):
    """Abstract interface for sandbox implementations (legacy shared + per-scan Kali)."""

    @abstractmethod
    async def initialize(self) -> Tuple[bool, str]: ...

    @property
    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    async def stop(self): ...

    @abstractmethod
    async def health_check(self) -> Dict: ...

    @abstractmethod
    async def run_nuclei(self, target, templates=None, severity=None,
                         tags=None, rate_limit=150, timeout=600) -> "SandboxResult": ...

    @abstractmethod
    async def run_naabu(self, target, ports=None, top_ports=None,
                        scan_type="s", rate=1000, timeout=300) -> "SandboxResult": ...

    @abstractmethod
    async def run_httpx(self, targets, timeout=120) -> "SandboxResult": ...

    @abstractmethod
    async def run_subfinder(self, domain, timeout=120) -> "SandboxResult": ...

    @abstractmethod
    async def run_nmap(self, target, ports=None, scripts=True, timeout=300) -> "SandboxResult": ...

    @abstractmethod
    async def run_tool(self, tool, args, timeout=300) -> "SandboxResult": ...

    @abstractmethod
    async def execute_raw(self, command, timeout=300) -> "SandboxResult": ...


class SandboxManager(BaseSandbox):
    """
    Legacy shared sandbox: persistent Docker container running security tools.

    Tools are executed via `docker exec` for fast invocation.
    Used by MCP server and terminal API (no scan_id context).
    """

    SANDBOX_IMAGE = "neurosploit-sandbox:latest"
    SANDBOX_CONTAINER = "neurosploit-sandbox"
    DEFAULT_TIMEOUT = 300  # 5 minutes
    MAX_OUTPUT = 2 * 1024 * 1024  # 2MB

    # Known install commands for tools not pre-installed in the sandbox
    KNOWN_INSTALLS = {
        "wpscan": "gem install wpscan 2>&1",
        "joomscan": "pip3 install joomscan 2>&1",
        "dirsearch": "pip3 install dirsearch 2>&1",
        "commix": "pip3 install commix 2>&1",
        "wfuzz": "pip3 install wfuzz 2>&1",
        "sslyze": "pip3 install sslyze 2>&1",
        "retire": "npm install -g retire 2>&1",
        "testssl": "apt-get update -qq && apt-get install -y -qq testssl.sh 2>&1",
        "trufflehog": "pip3 install trufflehog 2>&1",
        "gitleaks": "GO111MODULE=on go install github.com/gitleaks/gitleaks/v8@latest 2>&1",
    }

    def __init__(self):
        self._client: Optional[Any] = None
        self._container: Optional[Any] = None
        self._available = False
        self._temp_installed: set = set()  # Tools temporarily installed for cleanup

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> Tuple[bool, str]:
        """Initialize Docker client and ensure sandbox is running."""
        if not HAS_DOCKER:
            return False, "Docker SDK not installed"

        try:
            self._client = docker.from_env()
            self._client.ping()
        except Exception as e:
            return False, f"Docker not available: {e}"

        # Check if sandbox container already running
        try:
            container = self._client.containers.get(self.SANDBOX_CONTAINER)
            if container.status == "running":
                self._container = container
                self._available = True
                return True, "Sandbox already running"
            else:
                container.remove(force=True)
        except NotFound:
            pass

        # Check if image exists
        try:
            self._client.images.get(self.SANDBOX_IMAGE)
        except NotFound:
            return False, (
                f"Sandbox image '{self.SANDBOX_IMAGE}' not found. "
                "Build with: cd docker && docker compose -f docker-compose.sandbox.yml build"
            )

        # Start sandbox container
        try:
            self._container = self._client.containers.run(
                self.SANDBOX_IMAGE,
                command="sleep infinity",
                name=self.SANDBOX_CONTAINER,
                detach=True,
                restart_policy={"Name": "unless-stopped"},
                network_mode="bridge",
                mem_limit="2g",
                cpu_period=100000,
                cpu_quota=200000,  # 2 CPUs
                cap_add=["NET_RAW", "NET_ADMIN"],
                security_opt=["no-new-privileges:true"],
            )
            self._available = True
            return True, "Sandbox started"
        except Exception as e:
            return False, f"Failed to start sandbox: {e}"

    @property
    def is_available(self) -> bool:
        """Check if sandbox is ready for tool execution."""
        return self._available and self._container is not None

    async def stop(self):
        """Stop and remove the sandbox container."""
        if self._container:
            try:
                self._container.stop(timeout=10)
                self._container.remove(force=True)
            except Exception:
                pass
            self._container = None
            self._available = False

    async def health_check(self) -> Dict:
        """Run health check on the sandbox container."""
        if not self.is_available:
            return {"status": "unavailable", "tools": []}

        result = await self._exec("nuclei -version 2>&1 && naabu -version 2>&1 && nmap --version 2>&1 | head -1")
        tools = []
        if "nuclei" in result.stdout.lower():
            tools.append("nuclei")
        if "naabu" in result.stdout.lower():
            tools.append("naabu")
        if "nmap" in result.stdout.lower():
            tools.append("nmap")

        return {
            "status": "healthy" if tools else "degraded",
            "tools": tools,
            "container": self.SANDBOX_CONTAINER,
            "uptime": self._container.attrs.get("State", {}).get("StartedAt", "") if self._container else "",
        }

    # ------------------------------------------------------------------
    # Low-level execution
    # ------------------------------------------------------------------

    async def _exec(
        self, command: str, timeout: int = DEFAULT_TIMEOUT
    ) -> SandboxResult:
        """Execute a command inside the sandbox container."""
        if not self.is_available:
            return SandboxResult(
                tool="sandbox", command=command, exit_code=-1,
                stdout="", stderr="", duration_seconds=0,
                error="Sandbox not available",
            )

        started = datetime.utcnow()

        try:
            exec_result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._container.exec_run(
                    cmd=["bash", "-c", command],
                    stdout=True,
                    stderr=True,
                    demux=True,
                ),
            )

            duration = (datetime.utcnow() - started).total_seconds()

            stdout_raw, stderr_raw = exec_result.output
            stdout = (stdout_raw or b"").decode("utf-8", errors="replace")
            stderr = (stderr_raw or b"").decode("utf-8", errors="replace")

            # Truncate oversized output
            if len(stdout) > self.MAX_OUTPUT:
                stdout = stdout[: self.MAX_OUTPUT] + "\n... [truncated]"
            if len(stderr) > self.MAX_OUTPUT:
                stderr = stderr[: self.MAX_OUTPUT] + "\n... [truncated]"

            return SandboxResult(
                tool="sandbox",
                command=command,
                exit_code=exec_result.exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
            )

        except Exception as e:
            duration = (datetime.utcnow() - started).total_seconds()
            return SandboxResult(
                tool="sandbox", command=command, exit_code=-1,
                stdout="", stderr="", duration_seconds=duration,
                error=str(e),
            )

    # ------------------------------------------------------------------
    # High-level tool APIs
    # ------------------------------------------------------------------

    async def run_nuclei(
        self,
        target: str,
        templates: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[str] = None,
        rate_limit: int = 150,
        timeout: int = 600,
    ) -> SandboxResult:
        """
        Run Nuclei vulnerability scanner against a target.

        Args:
            target: URL or host to scan
            templates: Specific template path/ID (e.g., "cves/2024/")
            severity: Filter by severity (critical,high,medium,low,info)
            tags: Filter by tags (e.g., "xss,sqli,lfi")
            rate_limit: Requests per second (default 150)
            timeout: Max execution time in seconds
        """
        cmd_parts = [
            "nuclei",
            "-u", shlex.quote(target),
            "-jsonl",
            "-rate-limit", str(rate_limit),
            "-silent",
            "-no-color",
        ]

        if templates:
            cmd_parts.extend(["-t", shlex.quote(templates)])
        if severity:
            cmd_parts.extend(["-severity", shlex.quote(severity)])
        if tags:
            cmd_parts.extend(["-tags", shlex.quote(tags)])

        command = " ".join(cmd_parts) + " 2>/dev/null"
        result = await self._exec(command, timeout=timeout)
        result.tool = "nuclei"

        # Parse findings
        if result.stdout:
            result.findings = parse_nuclei_jsonl(result.stdout)

        return result

    async def run_naabu(
        self,
        target: str,
        ports: Optional[str] = None,
        top_ports: Optional[int] = None,
        scan_type: str = "s",
        rate: int = 1000,
        timeout: int = 300,
    ) -> SandboxResult:
        """
        Run Naabu port scanner against a target.

        Args:
            target: IP address or hostname to scan
            ports: Specific ports (e.g., "80,443,8080" or "1-65535")
            top_ports: Use top N ports (e.g., 100, 1000)
            scan_type: SYN (s), CONNECT (c)
            rate: Packets per second
            timeout: Max execution time in seconds
        """
        cmd_parts = [
            "naabu",
            "-host", shlex.quote(target),
            "-json",
            "-rate", str(rate),
            "-silent",
            "-no-color",
        ]

        if ports:
            cmd_parts.extend(["-p", shlex.quote(ports)])
        elif top_ports:
            cmd_parts.extend(["-top-ports", str(top_ports)])
        else:
            cmd_parts.extend(["-top-ports", "1000"])

        if scan_type:
            cmd_parts.extend(["-scan-type", scan_type])

        command = " ".join(cmd_parts) + " 2>/dev/null"
        result = await self._exec(command, timeout=timeout)
        result.tool = "naabu"

        # Parse port findings
        if result.stdout:
            result.findings = parse_naabu_output(result.stdout)

        return result

    async def run_httpx(
        self,
        targets: List[str],
        timeout: int = 120,
    ) -> SandboxResult:
        """
        Run HTTPX for HTTP probing and tech detection.

        Args:
            targets: List of URLs/hosts to probe
            timeout: Max execution time
        """
        target_str = "\\n".join(shlex.quote(t) for t in targets)
        command = (
            f'echo -e "{target_str}" | httpx -silent -json '
            f'-title -tech-detect -status-code -content-length '
            f'-follow-redirects -no-color 2>/dev/null'
        )

        result = await self._exec(command, timeout=timeout)
        result.tool = "httpx"

        # Parse JSON lines
        if result.stdout:
            findings = []
            for line in result.stdout.strip().split("\n"):
                try:
                    data = json.loads(line)
                    findings.append({
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "technologies": data.get("tech", []),
                        "content_length": data.get("content_length", 0),
                        "webserver": data.get("webserver", ""),
                    })
                except json.JSONDecodeError:
                    continue
            result.findings = findings

        return result

    async def run_subfinder(
        self,
        domain: str,
        timeout: int = 120,
    ) -> SandboxResult:
        """
        Run Subfinder for subdomain enumeration.

        Args:
            domain: Base domain to enumerate
            timeout: Max execution time
        """
        command = f"subfinder -d {shlex.quote(domain)} -silent -no-color 2>/dev/null"
        result = await self._exec(command, timeout=timeout)
        result.tool = "subfinder"

        if result.stdout:
            subdomains = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
            result.findings = [{"subdomain": s} for s in subdomains]

        return result

    async def run_nmap(
        self,
        target: str,
        ports: Optional[str] = None,
        scripts: bool = True,
        timeout: int = 300,
    ) -> SandboxResult:
        """
        Run Nmap network scanner.

        Args:
            target: IP/hostname to scan
            ports: Port specification
            scripts: Enable default scripts (-sC)
            timeout: Max execution time
        """
        cmd_parts = ["nmap", "-sV"]
        if scripts:
            cmd_parts.append("-sC")
        if ports:
            cmd_parts.extend(["-p", shlex.quote(ports)])
        cmd_parts.extend(["-oN", "/dev/stdout", shlex.quote(target)])

        command = " ".join(cmd_parts) + " 2>/dev/null"
        result = await self._exec(command, timeout=timeout)
        result.tool = "nmap"

        return result

    async def execute_raw(
        self,
        command: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> SandboxResult:
        """
        Execute an arbitrary shell command inside the sandbox container.

        Used by the Terminal Agent for interactive infrastructure testing.
        Returns raw stdout/stderr/exit_code.

        Args:
            command: Shell command to execute (passed to sh -c)
            timeout: Max execution time in seconds
        """
        result = await self._exec(f"sh -c {shlex.quote(command)}", timeout=timeout)
        result.tool = "raw"
        return result

    async def run_tool(
        self,
        tool: str,
        args: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> SandboxResult:
        """
        Run any tool available in the sandbox.

        Args:
            tool: Tool name (nuclei, naabu, nmap, httpx, etc.)
            args: Command-line arguments as string
            timeout: Max execution time
        """
        # Validate tool is available
        allowed_tools = {
            "nuclei", "naabu", "nmap", "httpx", "subfinder", "katana",
            "dnsx", "ffuf", "gobuster", "dalfox", "nikto", "sqlmap",
            "whatweb", "curl", "dig", "whois", "masscan", "dirsearch",
            "wfuzz", "arjun", "wafw00f", "waybackurls",
        }

        if tool not in allowed_tools:
            return SandboxResult(
                tool=tool, command=f"{tool} {args}", exit_code=-1,
                stdout="", stderr="", duration_seconds=0,
                error=f"Tool '{tool}' not in allowed list: {sorted(allowed_tools)}",
            )

        command = f"{tool} {args} 2>&1"
        result = await self._exec(command, timeout=timeout)
        result.tool = tool

        return result

    # ------------------------------------------------------------------
    # Dynamic tool install / run / cleanup
    # ------------------------------------------------------------------

    async def install_tool(
        self, tool: str, install_cmd: str = ""
    ) -> Tuple[bool, str]:
        """
        Temporarily install a tool in the sandbox container.

        Args:
            tool: Tool name (must be in KNOWN_INSTALLS or provide install_cmd)
            install_cmd: Custom install command (overrides KNOWN_INSTALLS)

        Returns:
            (success, message) tuple
        """
        if not self.is_available:
            return False, "Sandbox not available"

        cmd = install_cmd or self.KNOWN_INSTALLS.get(tool, "")
        if not cmd:
            return False, f"No install command for '{tool}'"

        logger.info(f"Installing tool '{tool}' in sandbox...")
        result = await self._exec(cmd, timeout=120)
        success = result.exit_code == 0

        if success:
            self._temp_installed.add(tool)
            logger.info(f"Tool '{tool}' installed successfully")
        else:
            logger.warning(f"Tool '{tool}' install failed: {result.stderr[:200]}")

        msg = result.stdout[:500] if success else result.stderr[:500]
        return success, msg

    async def run_and_cleanup(
        self,
        tool: str,
        args: str,
        cleanup: bool = True,
        timeout: int = 180,
    ) -> SandboxResult:
        """
        Install tool if needed, run it, collect output, then cleanup.

        This is the primary method for dynamic tool execution:
        1. Check if tool exists in sandbox
        2. Install if missing (from KNOWN_INSTALLS)
        3. Run the tool with given arguments
        4. Cleanup the installation if it was temporary

        Args:
            tool: Tool name
            args: Command-line arguments
            cleanup: Whether to remove temporarily installed tools
            timeout: Max execution time in seconds

        Returns:
            SandboxResult with stdout, stderr, findings
        """
        if not self.is_available:
            return SandboxResult(
                tool=tool, command=f"{tool} {args}", exit_code=-1,
                stdout="", stderr="", duration_seconds=0,
                error="Sandbox not available",
            )

        # Check if tool exists
        check = await self._exec(f"which {tool} 2>/dev/null")
        if check.exit_code != 0:
            # Try to install
            ok, msg = await self.install_tool(tool)
            if not ok:
                return SandboxResult(
                    tool=tool, command=f"{tool} {args}", exit_code=-1,
                    stdout="", stderr=msg, duration_seconds=0,
                    error=f"Install failed: {msg}",
                )

        # Run tool
        result = await self.run_tool(tool, args, timeout=timeout)

        # Cleanup if temporarily installed
        if cleanup and tool in self._temp_installed:
            logger.info(f"Cleaning up temporarily installed tool: {tool}")
            await self._exec(
                f"pip3 uninstall -y {shlex.quote(tool)} 2>/dev/null; "
                f"gem uninstall -x {shlex.quote(tool)} 2>/dev/null; "
                f"npm uninstall -g {shlex.quote(tool)} 2>/dev/null; "
                f"rm -f $(which {shlex.quote(tool)}) 2>/dev/null",
                timeout=30,
            )
            self._temp_installed.discard(tool)

        return result

    async def cleanup_temp_tools(self):
        """Remove all temporarily installed tools."""
        if not self._temp_installed:
            return
        for tool in list(self._temp_installed):
            logger.info(f"Cleaning up temp tool: {tool}")
            await self._exec(
                f"pip3 uninstall -y {shlex.quote(tool)} 2>/dev/null; "
                f"gem uninstall -x {shlex.quote(tool)} 2>/dev/null; "
                f"npm uninstall -g {shlex.quote(tool)} 2>/dev/null; "
                f"rm -f $(which {shlex.quote(tool)}) 2>/dev/null",
                timeout=30,
            )
            self._temp_installed.discard(tool)


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_manager: Optional[SandboxManager] = None

# Alias for backward compatibility
LegacySandboxManager = SandboxManager


async def get_sandbox(scan_id: Optional[str] = None) -> BaseSandbox:
    """Get a sandbox instance.

    Args:
        scan_id: If provided, returns a per-scan KaliSandbox from the container pool.
                 If None, returns the legacy shared SandboxManager.

    Backward compatible: all existing callers use get_sandbox() with no args.
    Agent passes scan_id for per-scan container isolation.
    """
    if scan_id is not None:
        try:
            from core.container_pool import get_pool
            pool = get_pool()
            return await pool.get_or_create(scan_id)
        except Exception as e:
            logger.warning(f"Per-scan sandbox failed ({e}), falling back to shared")
            # Fall through to legacy

    # Legacy path: shared persistent container
    global _manager
    if _manager is None:
        _manager = SandboxManager()
        ok, msg = await _manager.initialize()
        if not ok:
            logger.warning(f"Sandbox initialization: {msg}")
    return _manager
