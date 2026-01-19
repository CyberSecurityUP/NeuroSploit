"""
NeuroSploit v3 - Docker Tool Executor
Executes security tools in isolated Docker containers
"""

import asyncio
import docker
import json
import os
import re
import tempfile
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ToolResult:
    """Result from a tool execution"""
    tool: str
    command: str
    status: ToolStatus
    output: str
    error: str = ""
    findings: List[Dict] = field(default_factory=list)
    duration_seconds: float = 0
    started_at: str = ""
    completed_at: str = ""


class SecurityTool:
    """Definition of a security tool"""

    TOOLS = {
        "dirb": {
            "name": "Dirb",
            "description": "Web content scanner",
            "command": "dirb {target} /opt/wordlists/common.txt -o /opt/output/dirb.txt -w",
            "output_file": "/opt/output/dirb.txt",
            "parser": "parse_dirb_output"
        },
        "feroxbuster": {
            "name": "Feroxbuster",
            "description": "Fast content discovery tool",
            "command": "feroxbuster -u {target} -w /opt/wordlists/common.txt -o /opt/output/ferox.txt --json -q",
            "output_file": "/opt/output/ferox.txt",
            "parser": "parse_feroxbuster_output"
        },
        "ffuf": {
            "name": "FFUF",
            "description": "Fast web fuzzer",
            "command": "ffuf -u {target}/FUZZ -w /opt/wordlists/common.txt -o /opt/output/ffuf.json -of json -mc 200,204,301,302,307,401,403",
            "output_file": "/opt/output/ffuf.json",
            "parser": "parse_ffuf_output"
        },
        "gobuster": {
            "name": "Gobuster",
            "description": "Directory/file brute-forcer",
            "command": "gobuster dir -u {target} -w /opt/wordlists/common.txt -o /opt/output/gobuster.txt -q",
            "output_file": "/opt/output/gobuster.txt",
            "parser": "parse_gobuster_output"
        },
        "nmap": {
            "name": "Nmap",
            "description": "Network scanner",
            "command": "nmap -sV -sC -oN /opt/output/nmap.txt {host}",
            "output_file": "/opt/output/nmap.txt",
            "parser": "parse_nmap_output"
        },
        "nuclei": {
            "name": "Nuclei",
            "description": "Vulnerability scanner",
            "command": "nuclei -u {target} -o /opt/output/nuclei.txt -jsonl",
            "output_file": "/opt/output/nuclei.txt",
            "parser": "parse_nuclei_output"
        },
        "nikto": {
            "name": "Nikto",
            "description": "Web server scanner",
            "command": "nikto -h {target} -o /opt/output/nikto.txt -Format txt",
            "output_file": "/opt/output/nikto.txt",
            "parser": "parse_nikto_output"
        },
        "sqlmap": {
            "name": "SQLMap",
            "description": "SQL injection scanner",
            "command": "sqlmap -u {target} --batch --output-dir=/opt/output/sqlmap",
            "output_file": "/opt/output/sqlmap",
            "parser": "parse_sqlmap_output"
        },
        "whatweb": {
            "name": "WhatWeb",
            "description": "Web technology fingerprinting",
            "command": "whatweb {target} -a 3 --log-json=/opt/output/whatweb.json",
            "output_file": "/opt/output/whatweb.json",
            "parser": "parse_whatweb_output"
        },
        "httpx": {
            "name": "HTTPX",
            "description": "HTTP toolkit",
            "command": "echo {target} | httpx -silent -json -o /opt/output/httpx.json -title -tech-detect -status-code",
            "output_file": "/opt/output/httpx.json",
            "parser": "parse_httpx_output"
        },
        "katana": {
            "name": "Katana",
            "description": "Web crawler",
            "command": "katana -u {target} -o /opt/output/katana.txt -jc -d 3",
            "output_file": "/opt/output/katana.txt",
            "parser": "parse_katana_output"
        },
        "subfinder": {
            "name": "Subfinder",
            "description": "Subdomain discovery",
            "command": "subfinder -d {domain} -o /opt/output/subfinder.txt -silent",
            "output_file": "/opt/output/subfinder.txt",
            "parser": "parse_subfinder_output"
        },
        "dalfox": {
            "name": "Dalfox",
            "description": "XSS scanner",
            "command": "dalfox url {target} -o /opt/output/dalfox.txt --silence",
            "output_file": "/opt/output/dalfox.txt",
            "parser": "parse_dalfox_output"
        }
    }


class DockerToolExecutor:
    """Execute security tools in Docker containers"""

    DOCKER_IMAGE = "neurosploit-tools:latest"
    DEFAULT_TIMEOUT = 300  # 5 minutes
    MAX_OUTPUT_SIZE = 1024 * 1024  # 1MB max output

    def __init__(self):
        self.client = None
        self.active_containers: Dict[str, Any] = {}
        self._initialized = False

    async def initialize(self) -> Tuple[bool, str]:
        """Initialize Docker client and ensure image exists"""
        try:
            self.client = docker.from_env()
            self.client.ping()

            # Check if tools image exists
            try:
                self.client.images.get(self.DOCKER_IMAGE)
                self._initialized = True
                return True, "Docker initialized with tools image"
            except docker.errors.ImageNotFound:
                # Try to build the image
                logger.info("Building security tools Docker image...")
                return await self._build_tools_image()

        except docker.errors.DockerException as e:
            return False, f"Docker not available: {str(e)}"
        except Exception as e:
            return False, f"Failed to initialize Docker: {str(e)}"

    async def _build_tools_image(self) -> Tuple[bool, str]:
        """Build the security tools Docker image"""
        try:
            dockerfile_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "docker", "Dockerfile.tools"
            )

            if not os.path.exists(dockerfile_path):
                return False, f"Dockerfile not found at {dockerfile_path}"

            # Build image
            build_path = os.path.dirname(dockerfile_path)
            image, logs = self.client.images.build(
                path=build_path,
                dockerfile="Dockerfile.tools",
                tag=self.DOCKER_IMAGE,
                rm=True
            )

            self._initialized = True
            return True, "Tools image built successfully"

        except Exception as e:
            return False, f"Failed to build tools image: {str(e)}"

    def is_available(self) -> bool:
        """Check if Docker executor is available"""
        return self._initialized and self.client is not None

    def get_available_tools(self) -> List[Dict]:
        """Get list of available security tools"""
        return [
            {
                "id": tool_id,
                "name": tool["name"],
                "description": tool["description"]
            }
            for tool_id, tool in SecurityTool.TOOLS.items()
        ]

    async def execute_tool(
        self,
        tool_name: str,
        target: str,
        options: Optional[Dict] = None,
        timeout: int = None
    ) -> ToolResult:
        """Execute a security tool against a target"""

        if not self.is_available():
            return ToolResult(
                tool=tool_name,
                command="",
                status=ToolStatus.FAILED,
                output="",
                error="Docker executor not initialized"
            )

        tool_config = SecurityTool.TOOLS.get(tool_name.lower())
        if not tool_config:
            return ToolResult(
                tool=tool_name,
                command="",
                status=ToolStatus.FAILED,
                output="",
                error=f"Unknown tool: {tool_name}"
            )

        # Parse target URL
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        domain = host.split(':')[0]

        # Build command
        command = tool_config["command"].format(
            target=target,
            host=host,
            domain=domain
        )

        # Add custom options
        if options:
            for key, value in options.items():
                command += f" {key} {value}"

        timeout = timeout or self.DEFAULT_TIMEOUT
        started_at = datetime.utcnow()

        result = ToolResult(
            tool=tool_name,
            command=command,
            status=ToolStatus.RUNNING,
            output="",
            started_at=started_at.isoformat()
        )

        container = None

        try:
            # Create and run container
            container = self.client.containers.run(
                self.DOCKER_IMAGE,
                command=command,
                detach=True,
                remove=False,
                network_mode="bridge",
                mem_limit="512m",
                cpu_period=100000,
                cpu_quota=50000,  # 50% CPU
                volumes={},
                environment={
                    "TERM": "xterm"
                }
            )

            container_id = container.id[:12]
            self.active_containers[container_id] = container

            # Wait for container to finish
            try:
                exit_code = container.wait(timeout=timeout)

                # Get output
                logs = container.logs(stdout=True, stderr=True)
                output = logs.decode('utf-8', errors='replace')

                # Truncate if too large
                if len(output) > self.MAX_OUTPUT_SIZE:
                    output = output[:self.MAX_OUTPUT_SIZE] + "\n... [output truncated]"

                # Try to get output file
                try:
                    output_file = tool_config.get("output_file")
                    if output_file:
                        bits, stat = container.get_archive(output_file)
                        # Extract file content from tar
                        import tarfile
                        import io
                        tar_stream = io.BytesIO()
                        for chunk in bits:
                            tar_stream.write(chunk)
                        tar_stream.seek(0)
                        with tarfile.open(fileobj=tar_stream) as tar:
                            for member in tar.getmembers():
                                if member.isfile():
                                    f = tar.extractfile(member)
                                    if f:
                                        file_content = f.read().decode('utf-8', errors='replace')
                                        output = file_content
                except Exception:
                    pass  # Use container logs as output

                result.output = output
                result.status = ToolStatus.COMPLETED if exit_code.get('StatusCode', 1) == 0 else ToolStatus.FAILED

            except Exception as e:
                if "timeout" in str(e).lower() or "read timeout" in str(e).lower():
                    result.status = ToolStatus.TIMEOUT
                    result.error = f"Tool execution timed out after {timeout}s"
                    container.kill()
                else:
                    raise

        except Exception as e:
            result.status = ToolStatus.FAILED
            result.error = str(e)
            logger.error(f"Tool execution failed: {e}")

        finally:
            # Cleanup container
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
                self.active_containers.pop(container.id[:12], None)

        completed_at = datetime.utcnow()
        result.completed_at = completed_at.isoformat()
        result.duration_seconds = (completed_at - started_at).total_seconds()

        # Parse findings from output
        if result.status == ToolStatus.COMPLETED and result.output:
            parser_name = tool_config.get("parser")
            if parser_name and hasattr(self, parser_name):
                parser = getattr(self, parser_name)
                result.findings = parser(result.output, target)

        return result

    async def kill_container(self, container_id: str) -> bool:
        """Kill a running container"""
        container = self.active_containers.get(container_id)
        if container:
            try:
                container.kill()
                container.remove(force=True)
                del self.active_containers[container_id]
                return True
            except Exception:
                pass
        return False

    async def cleanup_all(self):
        """Cleanup all running containers"""
        for container_id in list(self.active_containers.keys()):
            await self.kill_container(container_id)

    # ==================== Output Parsers ====================

    def parse_dirb_output(self, output: str, target: str) -> List[Dict]:
        """Parse dirb output into findings"""
        findings = []

        # Match lines like: + http://example.com/admin (CODE:200|SIZE:1234)
        pattern = r'\+ (https?://[^\s]+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)'
        matches = re.findall(pattern, output)

        for url, code, size in matches:
            severity = "info"
            if "/admin" in url.lower() or "/panel" in url.lower():
                severity = "medium"
            elif ".env" in url or "config" in url.lower() or ".git" in url:
                severity = "high"

            findings.append({
                "title": f"Directory/File Found: {url.split('/')[-1] or url}",
                "severity": severity,
                "vulnerability_type": "Information Disclosure",
                "description": f"Accessible endpoint discovered at {url}",
                "affected_endpoint": url,
                "evidence": f"HTTP {code}, Size: {size} bytes",
                "remediation": "Review if this endpoint should be publicly accessible"
            })

        return findings

    def parse_feroxbuster_output(self, output: str, target: str) -> List[Dict]:
        """Parse feroxbuster JSON output"""
        findings = []

        for line in output.split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                url = data.get('url', '')
                status = data.get('status', 0)

                if status in [200, 301, 302, 403]:
                    severity = "info"
                    if "/admin" in url.lower() or status == 403:
                        severity = "medium"
                    elif ".env" in url or ".git" in url:
                        severity = "high"

                    findings.append({
                        "title": f"Endpoint: {url.split('/')[-1] or url}",
                        "severity": severity,
                        "vulnerability_type": "Information Disclosure",
                        "description": f"Discovered endpoint: {url}",
                        "affected_endpoint": url,
                        "evidence": f"HTTP {status}",
                        "remediation": "Review endpoint accessibility"
                    })
            except json.JSONDecodeError:
                continue

        return findings

    def parse_ffuf_output(self, output: str, target: str) -> List[Dict]:
        """Parse ffuf JSON output"""
        findings = []

        try:
            data = json.loads(output)
            results = data.get('results', [])

            for result in results:
                url = result.get('url', '')
                status = result.get('status', 0)
                length = result.get('length', 0)

                severity = "info"
                path = url.lower()
                if any(x in path for x in ['/admin', '/panel', '/dashboard']):
                    severity = "medium"
                elif any(x in path for x in ['.env', '.git', 'config', 'backup']):
                    severity = "high"

                findings.append({
                    "title": f"Found: {url.split('/')[-1]}",
                    "severity": severity,
                    "vulnerability_type": "Content Discovery",
                    "description": f"Discovered: {url}",
                    "affected_endpoint": url,
                    "evidence": f"HTTP {status}, Length: {length}",
                    "remediation": "Review if endpoint should be accessible"
                })
        except json.JSONDecodeError:
            # Fall back to text parsing
            pass

        return findings

    def parse_gobuster_output(self, output: str, target: str) -> List[Dict]:
        """Parse gobuster output"""
        findings = []

        for line in output.split('\n'):
            # Match: /admin (Status: 200) [Size: 1234]
            match = re.search(r'(/[^\s]+)\s+\(Status:\s*(\d+)\)', line)
            if match:
                path = match.group(1)
                status = match.group(2)
                url = target.rstrip('/') + path

                severity = "info"
                if any(x in path.lower() for x in ['/admin', '/panel']):
                    severity = "medium"
                elif any(x in path.lower() for x in ['.env', '.git', 'config']):
                    severity = "high"

                findings.append({
                    "title": f"Found: {path}",
                    "severity": severity,
                    "vulnerability_type": "Content Discovery",
                    "description": f"Discovered endpoint at {url}",
                    "affected_endpoint": url,
                    "evidence": f"HTTP {status}",
                    "remediation": "Review endpoint accessibility"
                })

        return findings

    def parse_nuclei_output(self, output: str, target: str) -> List[Dict]:
        """Parse nuclei JSONL output"""
        findings = []

        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info"
        }

        for line in output.split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)

                findings.append({
                    "title": data.get('info', {}).get('name', 'Unknown'),
                    "severity": severity_map.get(
                        data.get('info', {}).get('severity', 'info'),
                        'info'
                    ),
                    "vulnerability_type": data.get('info', {}).get('tags', ['vulnerability'])[0] if data.get('info', {}).get('tags') else 'vulnerability',
                    "description": data.get('info', {}).get('description', ''),
                    "affected_endpoint": data.get('matched-at', target),
                    "evidence": data.get('matcher-name', ''),
                    "remediation": data.get('info', {}).get('remediation', 'Review and fix the vulnerability'),
                    "references": data.get('info', {}).get('reference', [])
                })
            except json.JSONDecodeError:
                continue

        return findings

    def parse_nmap_output(self, output: str, target: str) -> List[Dict]:
        """Parse nmap output"""
        findings = []

        # Parse open ports
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)?'
        for match in re.finditer(port_pattern, output):
            port = match.group(1)
            service = match.group(2)
            version = match.group(3) or ''

            severity = "info"
            if service in ['telnet', 'ftp']:
                severity = "medium"
            elif 'vnc' in service.lower() or 'rdp' in service.lower():
                severity = "medium"

            findings.append({
                "title": f"Open Port: {port}/{service}",
                "severity": severity,
                "vulnerability_type": "Open Port",
                "description": f"Port {port} is open running {service} {version}".strip(),
                "affected_endpoint": f"{target}:{port}",
                "evidence": f"Service: {service}, Version: {version}",
                "remediation": "Review if this port should be exposed"
            })

        return findings

    def parse_nikto_output(self, output: str, target: str) -> List[Dict]:
        """Parse nikto output"""
        findings = []

        # Parse OSVDB entries and other findings
        vuln_pattern = r'\+\s+(\S+):\s+(.+)'
        for match in re.finditer(vuln_pattern, output):
            ref = match.group(1)
            desc = match.group(2)

            severity = "info"
            if any(x in desc.lower() for x in ['sql', 'injection', 'xss']):
                severity = "high"
            elif any(x in desc.lower() for x in ['outdated', 'vulnerable', 'dangerous']):
                severity = "medium"

            findings.append({
                "title": f"Nikto: {desc[:50]}...",
                "severity": severity,
                "vulnerability_type": "Web Vulnerability",
                "description": desc,
                "affected_endpoint": target,
                "evidence": ref,
                "remediation": "Review and address the finding"
            })

        return findings

    def parse_sqlmap_output(self, output: str, target: str) -> List[Dict]:
        """Parse sqlmap output"""
        findings = []

        if "is vulnerable" in output.lower() or "sql injection" in output.lower():
            # Extract vulnerable parameter
            param_match = re.search(r"Parameter:\s*(\S+)", output)
            param = param_match.group(1) if param_match else "unknown"

            findings.append({
                "title": f"SQL Injection: {param}",
                "severity": "critical",
                "vulnerability_type": "SQL Injection",
                "description": f"SQL injection vulnerability found in parameter: {param}",
                "affected_endpoint": target,
                "evidence": "SQLMap confirmed the vulnerability",
                "remediation": "Use parameterized queries and input validation"
            })

        return findings

    def parse_whatweb_output(self, output: str, target: str) -> List[Dict]:
        """Parse whatweb JSON output"""
        findings = []

        try:
            data = json.loads(output)
            if isinstance(data, list) and len(data) > 0:
                result = data[0]
                plugins = result.get('plugins', {})

                techs = []
                for name, info in plugins.items():
                    if name not in ['IP', 'Country']:
                        version = info.get('version', [''])[0] if info.get('version') else ''
                        techs.append(f"{name} {version}".strip())

                if techs:
                    findings.append({
                        "title": "Technology Stack Detected",
                        "severity": "info",
                        "vulnerability_type": "Information Disclosure",
                        "description": f"Detected technologies: {', '.join(techs)}",
                        "affected_endpoint": target,
                        "evidence": ", ".join(techs),
                        "remediation": "Consider hiding version information"
                    })
        except json.JSONDecodeError:
            pass

        return findings

    def parse_httpx_output(self, output: str, target: str) -> List[Dict]:
        """Parse httpx JSON output"""
        findings = []

        for line in output.split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)

                techs = data.get('tech', [])
                title = data.get('title', '')
                status = data.get('status_code', 0)

                if techs:
                    findings.append({
                        "title": f"Technologies: {', '.join(techs[:3])}",
                        "severity": "info",
                        "vulnerability_type": "Technology Detection",
                        "description": f"Page title: {title}. Technologies: {', '.join(techs)}",
                        "affected_endpoint": data.get('url', target),
                        "evidence": f"HTTP {status}",
                        "remediation": "Review exposed technology information"
                    })
            except json.JSONDecodeError:
                continue

        return findings

    def parse_katana_output(self, output: str, target: str) -> List[Dict]:
        """Parse katana output"""
        findings = []
        endpoints = set()

        for line in output.split('\n'):
            url = line.strip()
            if url and url.startswith('http'):
                endpoints.add(url)

        # Group interesting findings
        interesting = [u for u in endpoints if any(x in u.lower() for x in [
            'api', 'admin', 'login', 'upload', 'config', '.php', '.asp'
        ])]

        for url in interesting[:20]:  # Limit findings
            findings.append({
                "title": f"Interesting Endpoint: {url.split('/')[-1][:30]}",
                "severity": "info",
                "vulnerability_type": "Endpoint Discovery",
                "description": f"Crawled endpoint: {url}",
                "affected_endpoint": url,
                "evidence": "Discovered via web crawling",
                "remediation": "Review endpoint for security issues"
            })

        return findings

    def parse_subfinder_output(self, output: str, target: str) -> List[Dict]:
        """Parse subfinder output"""
        findings = []
        subdomains = [s.strip() for s in output.split('\n') if s.strip()]

        if subdomains:
            findings.append({
                "title": f"Subdomains Found: {len(subdomains)}",
                "severity": "info",
                "vulnerability_type": "Subdomain Enumeration",
                "description": f"Found {len(subdomains)} subdomains: {', '.join(subdomains[:10])}{'...' if len(subdomains) > 10 else ''}",
                "affected_endpoint": target,
                "evidence": "\n".join(subdomains[:20]),
                "remediation": "Review all subdomains for security"
            })

        return findings

    def parse_dalfox_output(self, output: str, target: str) -> List[Dict]:
        """Parse dalfox output"""
        findings = []

        # Look for XSS findings
        if "POC" in output or "Vulnerable" in output.lower():
            poc_match = re.search(r'POC:\s*(\S+)', output)
            poc = poc_match.group(1) if poc_match else "See output"

            findings.append({
                "title": "XSS Vulnerability Found",
                "severity": "high",
                "vulnerability_type": "Cross-Site Scripting (XSS)",
                "description": "Dalfox found a potential XSS vulnerability",
                "affected_endpoint": target,
                "evidence": poc,
                "remediation": "Implement proper output encoding and CSP"
            })

        return findings


# Global executor instance
_executor: Optional[DockerToolExecutor] = None


async def get_tool_executor() -> DockerToolExecutor:
    """Get or create the global tool executor instance"""
    global _executor
    if _executor is None:
        _executor = DockerToolExecutor()
        await _executor.initialize()
    return _executor
