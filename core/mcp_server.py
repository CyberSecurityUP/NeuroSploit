#!/usr/bin/env python3
"""
NeuroSploit MCP Server — Exposes pentest tools via Model Context Protocol.

Tools:
  - screenshot_capture: Playwright browser screenshots
  - payload_delivery: HTTP payload sending with full response capture
  - dns_lookup: DNS record enumeration
  - port_scan: TCP port scanning
  - technology_detect: HTTP header-based tech fingerprinting
  - subdomain_enumerate: Subdomain discovery via DNS brute-force
  - save_finding: Persist a finding to agent memory
  - get_vuln_prompt: Retrieve AI decision prompt for a vuln type
  - execute_nuclei: Run Nuclei scanner in Docker sandbox (8000+ templates)
  - execute_naabu: Run Naabu port scanner in Docker sandbox
  - sandbox_health: Check sandbox container status
  - sandbox_exec: Execute any allowed tool in the sandbox

Usage:
  python3 -m core.mcp_server          # stdio transport (default)
  MCP_TRANSPORT=sse python3 -m core.mcp_server  # SSE transport
"""

import asyncio
import json
import os
import socket
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Guard MCP import — server only works where mcp package is available
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    logger.warning("MCP package not installed. Install with: pip install 'mcp>=1.0.0'")

# Guard Playwright import
try:
    from core.browser_validator import BrowserValidator
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# AI prompts access
try:
    from backend.core.vuln_engine.ai_prompts import get_prompt, build_testing_prompt
    HAS_AI_PROMPTS = True
except ImportError:
    HAS_AI_PROMPTS = False

# Security sandbox access
try:
    from core.sandbox_manager import get_sandbox, SandboxManager
    HAS_SANDBOX = True
except ImportError:
    HAS_SANDBOX = False


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

async def _screenshot_capture(url: str, selector: Optional[str] = None) -> Dict:
    """Capture a screenshot of a URL using Playwright."""
    if not HAS_PLAYWRIGHT:
        return {"error": "Playwright not available", "screenshot": None}

    try:
        bv = BrowserValidator()
        result = await bv.capture_screenshot(url, selector=selector)
        return {"url": url, "screenshot_base64": result.get("screenshot", ""), "status": "ok"}
    except Exception as e:
        return {"error": str(e), "screenshot": None}


async def _payload_delivery(
    endpoint: str,
    method: str = "GET",
    payload: str = "",
    content_type: str = "application/x-www-form-urlencoded",
    headers: Optional[Dict] = None,
    param: str = "q",
) -> Dict:
    """Send an HTTP request with a payload and capture full response."""
    import aiohttp

    try:
        async with aiohttp.ClientSession() as session:
            req_headers = {"Content-Type": content_type}
            if headers:
                req_headers.update(headers)

            if method.upper() == "GET":
                async with session.get(endpoint, params={param: payload}, headers=req_headers, timeout=15, allow_redirects=False) as resp:
                    body = await resp.text()
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body[:5000],
                        "body_length": len(body),
                    }
            else:
                data = {param: payload} if content_type != "application/json" else None
                json_data = json.loads(payload) if content_type == "application/json" else None
                async with session.request(
                    method.upper(), endpoint, data=data, json=json_data,
                    headers=req_headers, timeout=15, allow_redirects=False
                ) as resp:
                    body = await resp.text()
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body[:5000],
                        "body_length": len(body),
                    }
    except Exception as e:
        return {"error": str(e)}


async def _dns_lookup(domain: str, record_type: str = "A") -> Dict:
    """Perform DNS lookups for a domain."""
    import subprocess

    try:
        result = subprocess.run(
            ["dig", "+short", domain, record_type],
            capture_output=True, text=True, timeout=10
        )
        records = [r.strip() for r in result.stdout.strip().split("\n") if r.strip()]
        return {"domain": domain, "type": record_type, "records": records}
    except FileNotFoundError:
        # Fallback to socket for A records
        if record_type.upper() == "A":
            try:
                ips = socket.getaddrinfo(domain, None, socket.AF_INET)
                records = list(set(ip[4][0] for ip in ips))
                return {"domain": domain, "type": "A", "records": records}
            except socket.gaierror as e:
                return {"domain": domain, "type": "A", "error": str(e)}
        return {"error": "dig command not available and only A records supported via fallback"}
    except Exception as e:
        return {"error": str(e)}


async def _port_scan(host: str, ports: str = "80,443,8080,8443,3000,5000") -> Dict:
    """Scan TCP ports on a host."""
    port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    results = {}

    async def check_port(port: int):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            writer.close()
            await writer.wait_closed()
            return port, "open"
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return port, "closed"

    tasks = [check_port(p) for p in port_list[:100]]
    for coro in asyncio.as_completed(tasks):
        port, state = await coro
        results[str(port)] = state

    open_ports = [p for p, s in results.items() if s == "open"]
    return {"host": host, "ports": results, "open_ports": open_ports}


async def _technology_detect(url: str) -> Dict:
    """Detect technologies from HTTP response headers."""
    import aiohttp

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10, allow_redirects=True) as resp:
                headers = dict(resp.headers)
                body = await resp.text()

                techs = []
                server = headers.get("Server", "")
                if server:
                    techs.append(f"Server: {server}")

                powered_by = headers.get("X-Powered-By", "")
                if powered_by:
                    techs.append(f"X-Powered-By: {powered_by}")

                # Framework detection from body
                framework_markers = {
                    "React": ["react", "_next/static", "__NEXT_DATA__"],
                    "Vue.js": ["vue.js", "__vue__", "v-cloak"],
                    "Angular": ["ng-version", "angular"],
                    "jQuery": ["jquery"],
                    "WordPress": ["wp-content", "wp-includes"],
                    "Laravel": ["laravel_session", "csrf-token"],
                    "Django": ["csrfmiddlewaretoken", "django"],
                    "Rails": ["csrf-param", "action_dispatch"],
                    "Spring": ["jsessionid"],
                    "Express": ["connect.sid"],
                }

                body_lower = body.lower()
                for tech, markers in framework_markers.items():
                    if any(m.lower() in body_lower for m in markers):
                        techs.append(tech)

                return {"url": url, "technologies": techs, "headers": {
                    k: v for k, v in headers.items()
                    if k.lower() in ("server", "x-powered-by", "x-aspnet-version",
                                     "x-generator", "x-drupal-cache", "x-framework")
                }}
    except Exception as e:
        return {"error": str(e)}


async def _subdomain_enumerate(domain: str) -> Dict:
    """Enumerate subdomains via common prefixes."""
    prefixes = [
        "www", "api", "admin", "app", "dev", "staging", "test", "mail",
        "ftp", "cdn", "blog", "shop", "docs", "status", "dashboard",
        "portal", "m", "mobile", "beta", "demo", "v2", "internal",
    ]

    found = []

    async def check_subdomain(prefix: str):
        subdomain = f"{prefix}.{domain}"
        try:
            socket.getaddrinfo(subdomain, None, socket.AF_INET)
            return subdomain
        except socket.gaierror:
            return None

    tasks = [check_subdomain(p) for p in prefixes]
    results = await asyncio.gather(*tasks)
    found = [r for r in results if r]

    return {"domain": domain, "subdomains": found, "count": len(found)}


async def _save_finding(finding_json: str) -> Dict:
    """Persist a finding (JSON string). Returns confirmation."""
    try:
        finding = json.loads(finding_json)
        # Validate required fields
        required = ["title", "severity", "vulnerability_type", "affected_endpoint"]
        missing = [f for f in required if f not in finding]
        if missing:
            return {"error": f"Missing required fields: {missing}"}
        return {"status": "saved", "finding_id": finding.get("id", "unknown"), "title": finding["title"]}
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}


async def _get_vuln_prompt(vuln_type: str, target: str = "", endpoint: str = "", param: str = "", tech: str = "") -> Dict:
    """Retrieve the AI decision prompt for a vulnerability type."""
    if not HAS_AI_PROMPTS:
        return {"error": "AI prompts module not available"}

    try:
        prompt_data = get_prompt(vuln_type, {
            "TARGET_URL": target,
            "ENDPOINT": endpoint,
            "PARAMETER": param,
            "TECHNOLOGY": tech,
        })
        if not prompt_data:
            return {"error": f"No prompt found for vuln type: {vuln_type}"}
        full_prompt = build_testing_prompt(vuln_type, target, endpoint, param, tech)
        return {"vuln_type": vuln_type, "prompt": prompt_data, "full_prompt": full_prompt}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Sandbox tool implementations (Docker-based real tools)
# ---------------------------------------------------------------------------

async def _execute_nuclei(
    target: str,
    templates: Optional[str] = None,
    severity: Optional[str] = None,
    tags: Optional[str] = None,
    rate_limit: int = 150,
) -> Dict:
    """Run Nuclei vulnerability scanner in the Docker sandbox."""
    if not HAS_SANDBOX:
        return {"error": "Sandbox module not available. Install docker SDK: pip install docker"}

    try:
        sandbox = await get_sandbox()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running. Build with: cd docker && docker compose -f docker-compose.sandbox.yml up -d"}

        result = await sandbox.run_nuclei(
            target=target,
            templates=templates,
            severity=severity,
            tags=tags,
            rate_limit=rate_limit,
        )

        return {
            "tool": "nuclei",
            "target": target,
            "exit_code": result.exit_code,
            "findings": result.findings,
            "findings_count": len(result.findings),
            "duration_seconds": result.duration_seconds,
            "raw_output": result.stdout[:3000] if result.stdout else "",
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


async def _execute_naabu(
    target: str,
    ports: Optional[str] = None,
    top_ports: Optional[int] = None,
    rate: int = 1000,
) -> Dict:
    """Run Naabu port scanner in the Docker sandbox."""
    if not HAS_SANDBOX:
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await get_sandbox()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        result = await sandbox.run_naabu(
            target=target,
            ports=ports,
            top_ports=top_ports,
            rate=rate,
        )

        open_ports = [f["port"] for f in result.findings]
        return {
            "tool": "naabu",
            "target": target,
            "exit_code": result.exit_code,
            "open_ports": sorted(open_ports),
            "port_count": len(open_ports),
            "findings": result.findings,
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


async def _sandbox_health() -> Dict:
    """Check sandbox container health and available tools."""
    if not HAS_SANDBOX:
        return {"status": "unavailable", "reason": "Sandbox module not installed"}

    try:
        sandbox = await get_sandbox()
        return await sandbox.health_check()
    except Exception as e:
        return {"status": "error", "reason": str(e)}


async def _sandbox_exec(tool: str, args: str, timeout: int = 300) -> Dict:
    """Execute any allowed tool in the Docker sandbox."""
    if not HAS_SANDBOX:
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await get_sandbox()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        result = await sandbox.run_tool(tool=tool, args=args, timeout=timeout)

        return {
            "tool": tool,
            "exit_code": result.exit_code,
            "stdout": result.stdout[:5000] if result.stdout else "",
            "stderr": result.stderr[:2000] if result.stderr else "",
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# MCP Server Definition
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "screenshot_capture",
        "description": "Capture a browser screenshot of a URL using Playwright",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to screenshot"},
                "selector": {"type": "string", "description": "Optional CSS selector to capture"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "payload_delivery",
        "description": "Send an HTTP request with a payload and capture the full response",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Target URL"},
                "method": {"type": "string", "description": "HTTP method", "default": "GET"},
                "payload": {"type": "string", "description": "Payload value"},
                "content_type": {"type": "string", "default": "application/x-www-form-urlencoded"},
                "param": {"type": "string", "description": "Parameter name", "default": "q"},
            },
            "required": ["endpoint", "payload"],
        },
    },
    {
        "name": "dns_lookup",
        "description": "Perform DNS lookups for a domain",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to look up"},
                "record_type": {"type": "string", "default": "A", "description": "DNS record type"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "port_scan",
        "description": "Scan TCP ports on a host",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target host"},
                "ports": {"type": "string", "default": "80,443,8080,8443,3000,5000", "description": "Comma-separated ports"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "technology_detect",
        "description": "Detect technologies from HTTP response headers and body",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to analyze"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "subdomain_enumerate",
        "description": "Enumerate subdomains via common prefix brute-force",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Base domain to enumerate"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "save_finding",
        "description": "Persist a vulnerability finding (JSON string)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_json": {"type": "string", "description": "Finding as JSON string"},
            },
            "required": ["finding_json"],
        },
    },
    {
        "name": "get_vuln_prompt",
        "description": "Retrieve the AI decision prompt for a vulnerability type",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vuln_type": {"type": "string", "description": "Vulnerability type key"},
                "target": {"type": "string", "description": "Target URL"},
                "endpoint": {"type": "string", "description": "Specific endpoint"},
                "param": {"type": "string", "description": "Parameter name"},
                "tech": {"type": "string", "description": "Detected technology"},
            },
            "required": ["vuln_type"],
        },
    },
    # --- Sandbox tools (Docker-based real security tools) ---
    {
        "name": "execute_nuclei",
        "description": "Run Nuclei vulnerability scanner (8000+ templates) in Docker sandbox. Returns structured findings with severity, CVE, CWE.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to scan"},
                "templates": {"type": "string", "description": "Specific template path (e.g. 'cves/2024/', 'vulnerabilities/xss/')"},
                "severity": {"type": "string", "description": "Filter: critical,high,medium,low,info"},
                "tags": {"type": "string", "description": "Filter by tags: xss,sqli,lfi,ssrf,rce"},
                "rate_limit": {"type": "integer", "description": "Requests per second (default 150)", "default": 150},
            },
            "required": ["target"],
        },
    },
    {
        "name": "execute_naabu",
        "description": "Run Naabu port scanner in Docker sandbox. Fast SYN-based scanning with configurable port ranges.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname to scan"},
                "ports": {"type": "string", "description": "Ports to scan (e.g. '80,443,8080' or '1-65535')"},
                "top_ports": {"type": "integer", "description": "Scan top N ports (e.g. 100, 1000)"},
                "rate": {"type": "integer", "description": "Packets per second (default 1000)", "default": 1000},
            },
            "required": ["target"],
        },
    },
    {
        "name": "sandbox_health",
        "description": "Check Docker sandbox status and available security tools",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "sandbox_exec",
        "description": "Execute any allowed security tool in the Docker sandbox (nuclei, naabu, nmap, httpx, subfinder, katana, ffuf, sqlmap, nikto, etc.)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool": {"type": "string", "description": "Tool name (e.g. nuclei, naabu, nmap, httpx, subfinder, katana, ffuf, gobuster, dalfox, nikto, sqlmap, curl)"},
                "args": {"type": "string", "description": "Command-line arguments for the tool"},
                "timeout": {"type": "integer", "description": "Max execution time in seconds (default 300)", "default": 300},
            },
            "required": ["tool", "args"],
        },
    },
]

# Tool dispatcher
TOOL_HANDLERS = {
    "screenshot_capture": lambda args: _screenshot_capture(args["url"], args.get("selector")),
    "payload_delivery": lambda args: _payload_delivery(
        args["endpoint"], args.get("method", "GET"), args.get("payload", ""),
        args.get("content_type", "application/x-www-form-urlencoded"),
        args.get("headers"), args.get("param", "q")
    ),
    "dns_lookup": lambda args: _dns_lookup(args["domain"], args.get("record_type", "A")),
    "port_scan": lambda args: _port_scan(args["host"], args.get("ports", "80,443,8080,8443,3000,5000")),
    "technology_detect": lambda args: _technology_detect(args["url"]),
    "subdomain_enumerate": lambda args: _subdomain_enumerate(args["domain"]),
    "save_finding": lambda args: _save_finding(args["finding_json"]),
    "get_vuln_prompt": lambda args: _get_vuln_prompt(
        args["vuln_type"], args.get("target", ""), args.get("endpoint", ""),
        args.get("param", ""), args.get("tech", "")
    ),
    # Sandbox tools
    "execute_nuclei": lambda args: _execute_nuclei(
        args["target"], args.get("templates"), args.get("severity"),
        args.get("tags"), args.get("rate_limit", 150)
    ),
    "execute_naabu": lambda args: _execute_naabu(
        args["target"], args.get("ports"), args.get("top_ports"),
        args.get("rate", 1000)
    ),
    "sandbox_health": lambda args: _sandbox_health(),
    "sandbox_exec": lambda args: _sandbox_exec(
        args["tool"], args["args"], args.get("timeout", 300)
    ),
}


def create_mcp_server() -> "Server":
    """Create and configure the MCP server with all pentest tools."""
    if not HAS_MCP:
        raise RuntimeError("MCP package not installed. Install with: pip install 'mcp>=1.0.0'")

    server = Server("neurosploit-tools")

    @server.list_tools()
    async def list_tools() -> list:
        return [Tool(**t) for t in TOOLS]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list:
        handler = TOOL_HANDLERS.get(name)
        if not handler:
            return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

        try:
            result = await handler(arguments)
            return [TextContent(type="text", text=json.dumps(result, default=str))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    return server


async def main():
    """Run the MCP server via stdio transport."""
    server = create_mcp_server()

    transport = os.getenv("MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    else:
        logger.error(f"Unsupported transport: {transport}. Use 'stdio'.")


if __name__ == "__main__":
    asyncio.run(main())
