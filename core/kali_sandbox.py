"""
NeuroSploit v3 - Kali Linux Per-Scan Sandbox

Each scan gets its own Docker container based on kalilinux/kali-rolling.
Tools installed on-demand the first time they are requested.
Container destroyed when scan completes.
"""

import asyncio
import json
import logging
import shlex
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple, Set

logger = logging.getLogger(__name__)

try:
    import docker
    from docker.errors import DockerException, NotFound, APIError
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False

from core.sandbox_manager import (
    BaseSandbox, SandboxResult,
    parse_nuclei_jsonl, parse_naabu_output,
)
from core.tool_registry import ToolRegistry


class KaliSandbox(BaseSandbox):
    """Per-scan Docker container based on Kali Linux.
    
    Lifecycle: create -> install tools on demand -> execute -> destroy.
    Each instance owns exactly one container named 'neurosploit-{scan_id}'.
    """

    DEFAULT_TIMEOUT = 300
    MAX_OUTPUT = 2 * 1024 * 1024  # 2MB

    def __init__(
        self,
        scan_id: str,
        image: str = "neurosploit-kali:latest",
        memory_limit: str = "2g",
        cpu_limit: float = 2.0,
        network_mode: str = "bridge",
    ):
        self.scan_id = scan_id
        self.container_name = f"neurosploit-{scan_id}"
        self.image = image
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.network_mode = network_mode

        self._client = None
        self._container = None
        self._available = False
        self._installed_tools: Set[str] = set()
        self._tool_registry = ToolRegistry()
        self._created_at: Optional[datetime] = None

    async def initialize(self) -> Tuple[bool, str]:
        """Create and start a new Kali container for this scan."""
        if not HAS_DOCKER:
            return False, "Docker SDK not installed"

        try:
            self._client = docker.from_env()
            self._client.ping()
        except Exception as e:
            return False, f"Docker not available: {e}"

        # Check if container already exists (resume after crash)
        try:
            existing = self._client.containers.get(self.container_name)
            if existing.status == "running":
                self._container = existing
                self._available = True
                self._created_at = datetime.utcnow()
                return True, f"Resumed existing container {self.container_name}"
            else:
                existing.remove(force=True)
        except NotFound:
            pass

        # Check image exists
        try:
            self._client.images.get(self.image)
        except NotFound:
            return False, (
                f"Kali sandbox image '{self.image}' not found. "
                "Build with: docker build -f docker/Dockerfile.kali -t neurosploit-kali:latest docker/"
            )

        # Create container
        try:
            cpu_quota = int(self.cpu_limit * 100000)
            self._container = self._client.containers.run(
                self.image,
                command="sleep infinity",
                name=self.container_name,
                detach=True,
                network_mode=self.network_mode,
                mem_limit=self.memory_limit,
                cpu_period=100000,
                cpu_quota=cpu_quota,
                cap_add=["NET_RAW", "NET_ADMIN"],
                security_opt=["no-new-privileges:true"],
                labels={
                    "neurosploit.scan_id": self.scan_id,
                    "neurosploit.type": "kali-sandbox",
                },
            )
            self._available = True
            self._created_at = datetime.utcnow()
            logger.info(f"Created Kali container {self.container_name} for scan {self.scan_id}")
            return True, f"Container {self.container_name} started"
        except Exception as e:
            return False, f"Failed to create container: {e}"

    @property
    def is_available(self) -> bool:
        return self._available and self._container is not None

    async def stop(self):
        """Stop and remove this scan's container."""
        if self._container:
            try:
                self._container.stop(timeout=10)
            except Exception:
                pass
            try:
                self._container.remove(force=True)
                logger.info(f"Destroyed container {self.container_name}")
            except Exception as e:
                logger.warning(f"Error removing {self.container_name}: {e}")
            self._container = None
            self._available = False

    async def health_check(self) -> Dict:
        """Run health check on this container."""
        if not self.is_available:
            return {"status": "unavailable", "scan_id": self.scan_id, "tools": []}

        result = await self._exec(
            "nuclei -version 2>&1; naabu -version 2>&1; nmap --version 2>&1 | head -1",
            timeout=15,
        )
        tools = []
        output = (result.stdout or "").lower()
        for tool in ["nuclei", "naabu", "nmap"]:
            if tool in output:
                tools.append(tool)

        uptime = 0.0
        if self._created_at:
            uptime = (datetime.utcnow() - self._created_at).total_seconds()

        return {
            "status": "healthy" if tools else "degraded",
            "scan_id": self.scan_id,
            "container": self.container_name,
            "tools": tools,
            "installed_tools": sorted(self._installed_tools),
            "uptime_seconds": uptime,
        }

    # ------------------------------------------------------------------
    # Low-level execution
    # ------------------------------------------------------------------
    async def _exec(self, command: str, timeout: int = DEFAULT_TIMEOUT) -> SandboxResult:
        """Execute command inside this container via docker exec."""
        if not self.is_available:
            return SandboxResult(
                tool="kali", command=command, exit_code=-1,
                stdout="", stderr="", duration_seconds=0,
                error="Container not available",
            )

        started = time.time()
        try:
            exec_result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._container.exec_run(
                    cmd=["bash", "-c", command],
                    stdout=True, stderr=True, demux=True,
                ),
            )

            duration = time.time() - started
            stdout_raw, stderr_raw = exec_result.output
            stdout = (stdout_raw or b"").decode("utf-8", errors="replace")
            stderr = (stderr_raw or b"").decode("utf-8", errors="replace")

            if len(stdout) > self.MAX_OUTPUT:
                stdout = stdout[: self.MAX_OUTPUT] + "\n... [truncated]"
            if len(stderr) > self.MAX_OUTPUT:
                stderr = stderr[: self.MAX_OUTPUT] + "\n... [truncated]"

            return SandboxResult(
                tool="kali", command=command,
                exit_code=exec_result.exit_code,
                stdout=stdout, stderr=stderr,
                duration_seconds=round(duration, 2),
            )
        except Exception as e:
            duration = time.time() - started
            return SandboxResult(
                tool="kali", command=command, exit_code=-1,
                stdout="", stderr="", duration_seconds=round(duration, 2),
                error=str(e),
            )

    # ------------------------------------------------------------------
    # On-demand tool installation
    # ------------------------------------------------------------------
    async def _ensure_tool(self, tool: str) -> bool:
        """Ensure a tool is installed in this container. Returns True if available."""
        if tool in self._installed_tools:
            return True

        # Check if already present in the base image
        check = await self._exec(f"which {shlex.quote(tool)} 2>/dev/null", timeout=10)
        if check.exit_code == 0 and check.stdout.strip():
            self._installed_tools.add(tool)
            return True

        # Get install recipe from registry
        recipe = self._tool_registry.get_install_command(tool)
        if not recipe:
            logger.warning(f"No install recipe for '{tool}' in Kali container")
            return False

        logger.info(f"[{self.container_name}] Installing {tool}...")
        result = await self._exec(recipe, timeout=300)
        if result.exit_code == 0:
            self._installed_tools.add(tool)
            logger.info(f"[{self.container_name}] Installed {tool} successfully")
            return True
        else:
            logger.warning(
                f"[{self.container_name}] Failed to install {tool}: "
                f"{(result.stderr or result.stdout or '')[:300]}"
            )
            return False

    # ------------------------------------------------------------------
    # High-level tool APIs (same signatures as SandboxManager)
    # ------------------------------------------------------------------
    async def run_nuclei(
        self, target, templates=None, severity=None,
        tags=None, rate_limit=150, timeout=600,
    ) -> SandboxResult:
        await self._ensure_tool("nuclei")
        cmd_parts = [
            "nuclei", "-u", shlex.quote(target),
            "-jsonl", "-rate-limit", str(rate_limit),
            "-silent", "-no-color",
        ]
        if templates:
            cmd_parts.extend(["-t", shlex.quote(templates)])
        if severity:
            cmd_parts.extend(["-severity", shlex.quote(severity)])
        if tags:
            cmd_parts.extend(["-tags", shlex.quote(tags)])

        result = await self._exec(" ".join(cmd_parts) + " 2>/dev/null", timeout=timeout)
        result.tool = "nuclei"
        if result.stdout:
            result.findings = parse_nuclei_jsonl(result.stdout)
        return result

    async def run_naabu(
        self, target, ports=None, top_ports=None,
        scan_type="s", rate=1000, timeout=300,
    ) -> SandboxResult:
        await self._ensure_tool("naabu")
        cmd_parts = [
            "naabu", "-host", shlex.quote(target),
            "-json", "-rate", str(rate), "-silent", "-no-color",
        ]
        if ports:
            cmd_parts.extend(["-p", shlex.quote(str(ports))])
        elif top_ports:
            cmd_parts.extend(["-top-ports", str(top_ports)])
        else:
            cmd_parts.extend(["-top-ports", "1000"])
        if scan_type:
            cmd_parts.extend(["-scan-type", scan_type])

        result = await self._exec(" ".join(cmd_parts) + " 2>/dev/null", timeout=timeout)
        result.tool = "naabu"
        if result.stdout:
            result.findings = parse_naabu_output(result.stdout)
        return result

    async def run_httpx(self, targets, timeout=120) -> SandboxResult:
        await self._ensure_tool("httpx")
        if isinstance(targets, str):
            targets = [targets]
        target_str = "\\n".join(shlex.quote(t) for t in targets)
        command = (
            f'echo -e "{target_str}" | httpx -silent -json '
            f'-title -tech-detect -status-code -content-length '
            f'-follow-redirects -no-color 2>/dev/null'
        )
        result = await self._exec(command, timeout=timeout)
        result.tool = "httpx"
        if result.stdout:
            findings = []
            for line in result.stdout.strip().split("\\n"):
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
                except (json.JSONDecodeError, ValueError):
                    continue
            result.findings = findings
        return result

    async def run_subfinder(self, domain, timeout=120) -> SandboxResult:
        await self._ensure_tool("subfinder")
        command = f"subfinder -d {shlex.quote(domain)} -silent -no-color 2>/dev/null"
        result = await self._exec(command, timeout=timeout)
        result.tool = "subfinder"
        if result.stdout:
            subs = [s.strip() for s in result.stdout.strip().split("\\n") if s.strip()]
            result.findings = [{"subdomain": s} for s in subs]
        return result

    async def run_nmap(self, target, ports=None, scripts=True, timeout=300) -> SandboxResult:
        await self._ensure_tool("nmap")
        cmd_parts = ["nmap", "-sV"]
        if scripts:
            cmd_parts.append("-sC")
        if ports:
            cmd_parts.extend(["-p", shlex.quote(str(ports))])
        cmd_parts.extend(["-oN", "/dev/stdout", shlex.quote(target)])
        result = await self._exec(" ".join(cmd_parts) + " 2>/dev/null", timeout=timeout)
        result.tool = "nmap"
        return result

    async def run_tool(self, tool, args, timeout=300) -> SandboxResult:
        """Run any tool (validates whitelist, installs on demand)."""
        # Load whitelist from config
        allowed_tools = set()
        try:
            with open("config/config.json") as f:
                cfg = json.load(f)
            allowed_tools = set(cfg.get("sandbox", {}).get("tools", []))
        except Exception:
            pass

        if not allowed_tools:
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
                error=f"Tool '{tool}' not in allowed list",
            )

        if not await self._ensure_tool(tool):
            return SandboxResult(
                tool=tool, command=f"{tool} {args}", exit_code=-1,
                stdout="", stderr="", duration_seconds=0,
                error=f"Could not install '{tool}' in Kali container",
            )

        result = await self._exec(f"{shlex.quote(tool)} {args} 2>&1", timeout=timeout)
        result.tool = tool
        return result

    async def execute_raw(self, command, timeout=300) -> SandboxResult:
        result = await self._exec(command, timeout=timeout)
        result.tool = "raw"
        return result
