"""
NeuroSploit v3 - Full Recon Integration

Integrates 40+ security/recon tools for comprehensive reconnaissance:
- Subdomain Enumeration: subfinder, amass, assetfinder, chaos, cero
- DNS Resolution: dnsx, massdns, puredns
- HTTP Probing: httpx, httprobe
- URL Discovery: gau, waybackurls, katana, gospider, hakrawler, cariddi
- Port Scanning: nmap, naabu, rustscan
- Tech Detection: whatweb, wafw00f
- Fuzzing: ffuf, gobuster, dirb, dirsearch
- Vulnerability Scanning: nuclei, nikto
- Parameter Discovery: arjun, paramspider
"""
import asyncio
import subprocess
import json
import os
import sys
import shutil
from typing import Optional, Callable, List, Dict, Any
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.api.websocket import manager as ws_manager


class ReconIntegration:
    """
    Full reconnaissance integration with 40+ security tools.
    Automatically uses available tools and skips missing ones.
    """

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.base_path = Path("/app")
        self.results_path = self.base_path / "data" / "recon"
        self.results_path.mkdir(parents=True, exist_ok=True)
        self.wordlists_path = Path("/opt/wordlists")

        # Track available tools
        self.available_tools = {}

    async def log(self, level: str, message: str):
        """Send log message via WebSocket"""
        await ws_manager.broadcast_log(self.scan_id, level, message)
        print(f"[{level.upper()}] {message}")

    def _tool_exists(self, tool: str) -> bool:
        """Check if a tool is available"""
        if tool not in self.available_tools:
            self.available_tools[tool] = shutil.which(tool) is not None
        return self.available_tools[tool]

    async def run_full_recon(self, target: str, depth: str = "medium") -> Dict[str, Any]:
        """
        Run full reconnaissance using all available tools.

        Args:
            target: Target domain or URL
            depth: quick, medium, or full

        Returns:
            Dictionary with all recon results
        """
        await self.log("info", f"🚀 Starting FULL reconnaissance on {target}")
        await self.log("info", f"📊 Depth level: {depth}")
        await ws_manager.broadcast_progress(self.scan_id, 5, "Initializing reconnaissance...")

        # Check available tools
        await self._check_tools()

        results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "depth": depth,
            "subdomains": [],
            "live_hosts": [],
            "urls": [],
            "endpoints": [],
            "ports": [],
            "technologies": [],
            "vulnerabilities": [],
            "js_files": [],
            "parameters": [],
            "interesting_paths": [],
            "dns_records": [],
            "screenshots": [],
            "secrets": []
        }

        # Extract domain from URL
        domain = self._extract_domain(target)
        base_url = target if target.startswith("http") else f"https://{target}"

        # Run recon phases based on depth
        phases = self._get_phases(depth)
        total_phases = len(phases)

        for i, (phase_name, phase_func) in enumerate(phases):
            try:
                progress = 5 + int((i / total_phases) * 35)
                await ws_manager.broadcast_progress(self.scan_id, progress, f"Recon: {phase_name}")
                await self.log("info", f"▶ Running {phase_name}...")

                phase_results = await phase_func(domain, base_url)
                results = self._merge_results(results, phase_results)

                # Broadcast discoveries
                for endpoint in phase_results.get("endpoints", []):
                    if isinstance(endpoint, dict):
                        await ws_manager.broadcast_endpoint_found(self.scan_id, endpoint)

                for url in phase_results.get("urls", [])[:10]:
                    await ws_manager.broadcast_url_discovered(self.scan_id, url)

                await self.log("info", f"✓ {phase_name} complete")
            except Exception as e:
                await self.log("warning", f"⚠ {phase_name} failed: {str(e)}")

        # Summary
        await self.log("info", f"═══════════════════════════════════════")
        await self.log("info", f"📊 Reconnaissance Summary:")
        await self.log("info", f"   • Subdomains: {len(results['subdomains'])}")
        await self.log("info", f"   • Live hosts: {len(results['live_hosts'])}")
        await self.log("info", f"   • URLs: {len(results['urls'])}")
        await self.log("info", f"   • Endpoints: {len(results['endpoints'])}")
        await self.log("info", f"   • Open ports: {len(results['ports'])}")
        await self.log("info", f"   • JS files: {len(results['js_files'])}")
        await self.log("info", f"   • Nuclei findings: {len(results['vulnerabilities'])}")
        await self.log("info", f"═══════════════════════════════════════")

        return results

    async def _check_tools(self):
        """Check and report available tools"""
        essential_tools = [
            "subfinder", "httpx", "nuclei", "nmap", "katana", "gau",
            "waybackurls", "ffuf", "gobuster", "amass", "naabu"
        ]

        available = []
        missing = []

        for tool in essential_tools:
            if self._tool_exists(tool):
                available.append(tool)
            else:
                missing.append(tool)

        await self.log("info", f"🔧 Tools available: {', '.join(available)}")
        if missing:
            await self.log("debug", f"Missing tools: {', '.join(missing)}")

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL"""
        domain = target.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0]
        domain = domain.split(":")[0]
        return domain

    def _get_phases(self, depth: str) -> List[tuple]:
        """Get recon phases based on depth"""
        quick_phases = [
            ("DNS Resolution", self._dns_resolution),
            ("HTTP Probing", self._http_probe),
            ("Basic Path Discovery", self._basic_paths),
        ]

        medium_phases = quick_phases + [
            ("Subdomain Enumeration", self._subdomain_enum),
            ("URL Collection", self._url_collection),
            ("Port Scan (Top 100)", self._port_scan_quick),
            ("Technology Detection", self._tech_detection),
            ("Web Crawling", self._web_crawl),
        ]

        full_phases = medium_phases + [
            ("Full Port Scan", self._port_scan_full),
            ("Parameter Discovery", self._param_discovery),
            ("JavaScript Analysis", self._js_analysis),
            ("Directory Fuzzing", self._directory_fuzz),
            ("Nuclei Vulnerability Scan", self._nuclei_scan),
            ("Screenshot Capture", self._screenshot_capture),
        ]

        return {
            "quick": quick_phases,
            "medium": medium_phases,
            "full": full_phases
        }.get(depth, medium_phases)

    async def _run_command(self, cmd: List[str], timeout: int = 120) -> str:
        """Run a shell command asynchronously"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            return stdout.decode('utf-8', errors='ignore')
        except asyncio.TimeoutError:
            try:
                process.kill()
            except:
                pass
            return ""
        except Exception as e:
            return ""

    # =========================================================================
    # RECON PHASES
    # =========================================================================

    async def _dns_resolution(self, domain: str, base_url: str) -> Dict:
        """DNS resolution using dnsx, dig"""
        results = {"dns_records": [], "subdomains": []}

        # Try dnsx
        if self._tool_exists("dnsx"):
            output = await self._run_command(
                ["dnsx", "-d", domain, "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-silent"],
                timeout=60
            )
            if output:
                for line in output.strip().split("\n"):
                    if line:
                        results["dns_records"].append(line)
                        await self.log("debug", f"DNS: {line}")

        # Fallback to dig
        if not results["dns_records"]:
            for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                output = await self._run_command(["dig", domain, record_type, "+short"], timeout=10)
                if output:
                    for line in output.strip().split("\n"):
                        if line:
                            results["dns_records"].append(f"{record_type}: {line}")

        return results

    async def _http_probe(self, domain: str, base_url: str) -> Dict:
        """HTTP probing using httpx, httprobe"""
        results = {"live_hosts": [], "endpoints": []}

        # Try httpx (preferred)
        if self._tool_exists("httpx"):
            output = await self._run_command(
                ["httpx", "-u", domain, "-silent", "-status-code", "-title",
                 "-tech-detect", "-content-length", "-web-server"],
                timeout=60
            )
            if output:
                for line in output.strip().split("\n"):
                    if line:
                        results["live_hosts"].append(line)
                        parts = line.split()
                        url = parts[0] if parts else f"https://{domain}"
                        results["endpoints"].append({
                            "url": url,
                            "method": "GET",
                            "path": "/",
                            "status": int(parts[1].strip("[]")) if len(parts) > 1 and parts[1].strip("[]").isdigit() else 200,
                            "source": "httpx"
                        })

        # Try httprobe
        elif self._tool_exists("httprobe"):
            process = await asyncio.create_subprocess_exec(
                "httprobe",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(
                process.communicate(input=f"{domain}\n".encode()),
                timeout=30
            )
            if stdout:
                for line in stdout.decode().strip().split("\n"):
                    if line:
                        results["live_hosts"].append(line)
                        results["endpoints"].append({
                            "url": line,
                            "method": "GET",
                            "path": "/",
                            "source": "httprobe"
                        })

        # Fallback to curl
        if not results["live_hosts"]:
            for proto in ["https", "http"]:
                url = f"{proto}://{domain}"
                output = await self._run_command(
                    ["curl", "-sI", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", url],
                    timeout=15
                )
                if output and output.strip() not in ["000", ""]:
                    results["live_hosts"].append(f"{url} [{output.strip()}]")
                    results["endpoints"].append({
                        "url": url,
                        "status": int(output.strip()) if output.strip().isdigit() else 0,
                        "source": "curl"
                    })

        return results

    async def _basic_paths(self, domain: str, base_url: str) -> Dict:
        """Check common paths"""
        results = {"endpoints": [], "interesting_paths": []}

        common_paths = [
            "/", "/robots.txt", "/sitemap.xml", "/.git/config", "/.env",
            "/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/api-docs",
            "/swagger.json", "/openapi.json", "/.well-known/security.txt",
            "/admin", "/administrator", "/login", "/register", "/dashboard",
            "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
            "/phpmyadmin", "/pma", "/console", "/debug", "/trace",
            "/actuator", "/actuator/health", "/actuator/env", "/metrics",
            "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
            "/backup", "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql",
            "/config", "/config.php", "/config.json", "/settings.json",
            "/uploads", "/files", "/static", "/assets", "/media",
            "/test", "/dev", "/staging", "/temp", "/tmp",
            "/.git/HEAD", "/.svn/entries", "/.DS_Store",
            "/info.php", "/phpinfo.php", "/test.php",
            "/elmah.axd", "/trace.axd", "/web.config"
        ]

        import aiohttp
        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        timeout = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            for path in common_paths:
                tasks.append(self._check_path(session, base_url, path, results))

            await asyncio.gather(*tasks, return_exceptions=True)

        return results

    async def _check_path(self, session, base_url: str, path: str, results: Dict):
        """Check a single path"""
        try:
            url = f"{base_url.rstrip('/')}{path}"
            async with session.get(url, allow_redirects=False) as response:
                if response.status < 404:
                    endpoint = {
                        "url": url,
                        "path": path,
                        "status": response.status,
                        "content_type": response.headers.get("Content-Type", ""),
                        "content_length": response.headers.get("Content-Length", ""),
                        "source": "path_check"
                    }
                    results["endpoints"].append(endpoint)

                    # Mark interesting paths
                    sensitive_paths = ["/.git", "/.env", "/debug", "/actuator",
                                      "/backup", "/config", "/.htaccess", "/phpinfo",
                                      "/trace", "/elmah", "/web.config"]
                    if any(s in path for s in sensitive_paths):
                        results["interesting_paths"].append({
                            "path": path,
                            "status": response.status,
                            "risk": "high",
                            "reason": "Potentially sensitive file/endpoint"
                        })
                        await self.log("warning", f"🚨 Interesting: {path} [{response.status}]")
                    else:
                        await self.log("info", f"Found: {path} [{response.status}]")
        except:
            pass

    async def _subdomain_enum(self, domain: str, base_url: str) -> Dict:
        """Subdomain enumeration using multiple tools"""
        results = {"subdomains": []}
        found_subs = set()

        await self.log("info", f"🔍 Enumerating subdomains for {domain}")

        # 1. Subfinder (fast and reliable)
        if self._tool_exists("subfinder"):
            await self.log("debug", "Running subfinder...")
            output = await self._run_command(
                ["subfinder", "-d", domain, "-silent", "-all"],
                timeout=180
            )
            if output:
                for sub in output.strip().split("\n"):
                    if sub and sub not in found_subs:
                        found_subs.add(sub)

        # 2. Amass (comprehensive)
        if self._tool_exists("amass"):
            await self.log("debug", "Running amass passive...")
            output = await self._run_command(
                ["amass", "enum", "-passive", "-d", domain, "-timeout", "3"],
                timeout=240
            )
            if output:
                for sub in output.strip().split("\n"):
                    if sub and sub not in found_subs:
                        found_subs.add(sub)

        # 3. Assetfinder
        if self._tool_exists("assetfinder"):
            await self.log("debug", "Running assetfinder...")
            output = await self._run_command(
                ["assetfinder", "--subs-only", domain],
                timeout=60
            )
            if output:
                for sub in output.strip().split("\n"):
                    if sub and sub not in found_subs:
                        found_subs.add(sub)

        # 4. Chaos (if API key available)
        if self._tool_exists("chaos") and os.environ.get("CHAOS_KEY"):
            await self.log("debug", "Running chaos...")
            output = await self._run_command(
                ["chaos", "-d", domain, "-silent"],
                timeout=60
            )
            if output:
                for sub in output.strip().split("\n"):
                    if sub and sub not in found_subs:
                        found_subs.add(sub)

        # 5. Cero (certificate transparency)
        if self._tool_exists("cero"):
            await self.log("debug", "Running cero...")
            output = await self._run_command(
                ["cero", domain],
                timeout=60
            )
            if output:
                for sub in output.strip().split("\n"):
                    if sub and domain in sub and sub not in found_subs:
                        found_subs.add(sub)

        results["subdomains"] = list(found_subs)
        await self.log("info", f"✓ Found {len(found_subs)} subdomains")

        return results

    async def _url_collection(self, domain: str, base_url: str) -> Dict:
        """Collect URLs from various sources"""
        results = {"urls": [], "parameters": [], "js_files": []}
        found_urls = set()

        await self.log("info", f"🔗 Collecting URLs for {domain}")

        # 1. GAU (GetAllUrls)
        if self._tool_exists("gau"):
            await self.log("debug", "Running gau...")
            output = await self._run_command(
                ["gau", "--threads", "5", "--subs", domain],
                timeout=180
            )
            if output:
                for url in output.strip().split("\n")[:1000]:
                    if url and url not in found_urls:
                        found_urls.add(url)
                        if url.endswith(".js"):
                            results["js_files"].append(url)
                        if "?" in url:
                            results["parameters"].append(url)

        # 2. Waybackurls
        if self._tool_exists("waybackurls"):
            await self.log("debug", "Running waybackurls...")
            output = await self._run_command(
                ["waybackurls", domain],
                timeout=120
            )
            if output:
                for url in output.strip().split("\n")[:1000]:
                    if url and url not in found_urls:
                        found_urls.add(url)
                        if url.endswith(".js"):
                            results["js_files"].append(url)
                        if "?" in url:
                            results["parameters"].append(url)

        results["urls"] = list(found_urls)
        await self.log("info", f"✓ Collected {len(found_urls)} URLs, {len(results['parameters'])} with parameters")

        return results

    async def _port_scan_quick(self, domain: str, base_url: str) -> Dict:
        """Quick port scan (top 100)"""
        results = {"ports": []}

        await self.log("info", f"🔌 Port scanning {domain} (top 100)")

        # Try naabu (fastest)
        if self._tool_exists("naabu"):
            await self.log("debug", "Running naabu...")
            output = await self._run_command(
                ["naabu", "-host", domain, "-top-ports", "100", "-silent"],
                timeout=120
            )
            if output:
                for line in output.strip().split("\n"):
                    if line:
                        results["ports"].append(line)
                        await self.log("info", f"Port: {line}")

        # Fallback to nmap
        elif self._tool_exists("nmap"):
            await self.log("debug", "Running nmap...")
            output = await self._run_command(
                ["nmap", "-sT", "-T4", "--top-ports", "100", "-oG", "-", domain],
                timeout=180
            )
            if output:
                for line in output.split("\n"):
                    if "Ports:" in line:
                        ports_part = line.split("Ports:")[1]
                        for port_info in ports_part.split(","):
                            if "/open/" in port_info:
                                port = port_info.strip().split("/")[0]
                                results["ports"].append(f"{domain}:{port}")
                                await self.log("info", f"Port: {domain}:{port}")

        return results

    async def _port_scan_full(self, domain: str, base_url: str) -> Dict:
        """Full port scan"""
        results = {"ports": []}

        await self.log("info", f"🔌 Full port scan on {domain}")

        # Try rustscan (fastest full scan)
        if self._tool_exists("rustscan"):
            await self.log("debug", "Running rustscan...")
            output = await self._run_command(
                ["rustscan", "-a", domain, "--ulimit", "5000", "-g"],
                timeout=300
            )
            if output:
                for line in output.strip().split("\n"):
                    if line and "->" in line:
                        results["ports"].append(line)

        # Fallback to naabu full
        elif self._tool_exists("naabu"):
            output = await self._run_command(
                ["naabu", "-host", domain, "-p", "-", "-silent"],
                timeout=600
            )
            if output:
                for line in output.strip().split("\n"):
                    if line:
                        results["ports"].append(line)

        return results

    async def _tech_detection(self, domain: str, base_url: str) -> Dict:
        """Detect technologies"""
        results = {"technologies": []}

        await self.log("info", f"🔬 Detecting technologies on {base_url}")

        # Try whatweb
        if self._tool_exists("whatweb"):
            await self.log("debug", "Running whatweb...")
            output = await self._run_command(
                ["whatweb", "-q", "-a", "3", "--color=never", base_url],
                timeout=60
            )
            if output:
                results["technologies"].append({"source": "whatweb", "data": output.strip()})
                await self.log("debug", f"WhatWeb: {output[:200]}...")

        # Try wafw00f (WAF detection)
        if self._tool_exists("wafw00f"):
            await self.log("debug", "Running wafw00f...")
            output = await self._run_command(
                ["wafw00f", base_url, "-o", "-"],
                timeout=60
            )
            if output and "No WAF" not in output:
                results["technologies"].append({"source": "wafw00f", "data": output.strip()})
                await self.log("warning", f"WAF detected: {output[:100]}")

        return results

    async def _web_crawl(self, domain: str, base_url: str) -> Dict:
        """Crawl the website for endpoints"""
        results = {"endpoints": [], "js_files": [], "urls": []}

        await self.log("info", f"🕷 Crawling {base_url}")

        # Try katana (modern, fast)
        if self._tool_exists("katana"):
            await self.log("debug", "Running katana...")
            output = await self._run_command(
                ["katana", "-u", base_url, "-d", "3", "-silent", "-jc", "-kf", "all"],
                timeout=180
            )
            if output:
                for url in output.strip().split("\n"):
                    if url:
                        if url.endswith(".js"):
                            results["js_files"].append(url)
                        results["endpoints"].append({"url": url, "source": "katana"})
                        results["urls"].append(url)

        # Try gospider
        if self._tool_exists("gospider"):
            await self.log("debug", "Running gospider...")
            output = await self._run_command(
                ["gospider", "-s", base_url, "-d", "2", "-t", "5", "--no-redirect", "-q"],
                timeout=180
            )
            if output:
                for line in output.strip().split("\n"):
                    if "[" in line and "]" in line:
                        parts = line.split(" - ")
                        if len(parts) > 1:
                            url = parts[-1].strip()
                            if url and url.startswith("http"):
                                if url not in results["urls"]:
                                    results["urls"].append(url)
                                    results["endpoints"].append({"url": url, "source": "gospider"})

        # Try hakrawler
        if self._tool_exists("hakrawler") and not results["endpoints"]:
            await self.log("debug", "Running hakrawler...")
            process = await asyncio.create_subprocess_exec(
                "hakrawler", "-d", "2", "-u",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(
                process.communicate(input=f"{base_url}\n".encode()),
                timeout=120
            )
            if stdout:
                for url in stdout.decode().strip().split("\n"):
                    if url and url.startswith("http"):
                        results["urls"].append(url)
                        results["endpoints"].append({"url": url, "source": "hakrawler"})

        await self.log("info", f"✓ Crawled {len(results['endpoints'])} endpoints, {len(results['js_files'])} JS files")
        return results

    async def _param_discovery(self, domain: str, base_url: str) -> Dict:
        """Discover parameters"""
        results = {"parameters": []}

        await self.log("info", f"🔎 Discovering parameters for {domain}")

        # Try paramspider
        if self._tool_exists("paramspider"):
            await self.log("debug", "Running paramspider...")
            output = await self._run_command(
                ["paramspider", "-d", domain, "--quiet"],
                timeout=120
            )
            if output:
                for url in output.strip().split("\n"):
                    if url and "?" in url:
                        results["parameters"].append(url)

        # Try arjun
        if self._tool_exists("arjun"):
            await self.log("debug", "Running arjun...")
            output = await self._run_command(
                ["arjun", "-u", base_url, "--stable", "-oT", "/dev/stdout"],
                timeout=180
            )
            if output:
                for line in output.strip().split("\n"):
                    if ":" in line and line not in results["parameters"]:
                        results["parameters"].append(line)

        return results

    async def _js_analysis(self, domain: str, base_url: str) -> Dict:
        """Analyze JavaScript files for secrets and endpoints"""
        results = {"secrets": [], "endpoints": [], "js_files": []}

        await self.log("info", f"📜 Analyzing JavaScript files")

        # Try getJS
        if self._tool_exists("getJS"):
            await self.log("debug", "Running getJS...")
            output = await self._run_command(
                ["getJS", "-u", base_url, "--complete"],
                timeout=60
            )
            if output:
                for js_url in output.strip().split("\n"):
                    if js_url and js_url.endswith(".js"):
                        results["js_files"].append(js_url)

        return results

    async def _directory_fuzz(self, domain: str, base_url: str) -> Dict:
        """Directory fuzzing"""
        results = {"endpoints": []}

        wordlist = self.wordlists_path / "common.txt"
        if not wordlist.exists():
            return results

        await self.log("info", f"📂 Fuzzing directories on {base_url}")

        # Try ffuf (fastest)
        if self._tool_exists("ffuf"):
            await self.log("debug", "Running ffuf...")
            output = await self._run_command(
                ["ffuf", "-u", f"{base_url}/FUZZ", "-w", str(wordlist),
                 "-mc", "200,201,204,301,302,307,401,403,405",
                 "-t", "50", "-o", "-", "-of", "json"],
                timeout=180
            )
            if output:
                try:
                    data = json.loads(output)
                    for result in data.get("results", []):
                        results["endpoints"].append({
                            "url": result.get("url", ""),
                            "status": result.get("status", 0),
                            "length": result.get("length", 0),
                            "source": "ffuf"
                        })
                except:
                    pass

        # Try gobuster
        elif self._tool_exists("gobuster"):
            await self.log("debug", "Running gobuster...")
            output = await self._run_command(
                ["gobuster", "dir", "-u", base_url, "-w", str(wordlist),
                 "-t", "50", "-q", "--no-error"],
                timeout=180
            )
            if output:
                for line in output.strip().split("\n"):
                    if line and "(Status:" in line:
                        parts = line.split()
                        if parts:
                            path = parts[0]
                            results["endpoints"].append({
                                "url": f"{base_url}{path}",
                                "path": path,
                                "source": "gobuster"
                            })

        return results

    async def _nuclei_scan(self, domain: str, base_url: str) -> Dict:
        """Run nuclei vulnerability scanner"""
        results = {"vulnerabilities": []}

        if not self._tool_exists("nuclei"):
            return results

        await self.log("info", f"☢ Running Nuclei vulnerability scan on {base_url}")

        output = await self._run_command(
            ["nuclei", "-u", base_url, "-severity", "critical,high,medium",
             "-silent", "-json", "-c", "25"],
            timeout=600
        )

        if output:
            for line in output.strip().split("\n"):
                if line:
                    try:
                        vuln = json.loads(line)
                        results["vulnerabilities"].append({
                            "name": vuln.get("info", {}).get("name", "Unknown"),
                            "severity": vuln.get("info", {}).get("severity", "unknown"),
                            "url": vuln.get("matched-at", ""),
                            "template": vuln.get("template-id", ""),
                            "description": vuln.get("info", {}).get("description", ""),
                            "matcher_name": vuln.get("matcher-name", "")
                        })

                        await ws_manager.broadcast_vulnerability_found(self.scan_id, {
                            "title": vuln.get("info", {}).get("name", "Unknown"),
                            "severity": vuln.get("info", {}).get("severity", "unknown"),
                            "type": "nuclei",
                            "endpoint": vuln.get("matched-at", "")
                        })

                        severity = vuln.get("info", {}).get("severity", "unknown").upper()
                        await self.log("warning", f"☢ NUCLEI [{severity}]: {vuln.get('info', {}).get('name')}")
                    except:
                        pass

        await self.log("info", f"✓ Nuclei found {len(results['vulnerabilities'])} issues")
        return results

    async def _screenshot_capture(self, domain: str, base_url: str) -> Dict:
        """Capture screenshots of web pages"""
        results = {"screenshots": []}

        if not self._tool_exists("gowitness"):
            return results

        await self.log("info", f"📸 Capturing screenshots")

        screenshot_dir = self.results_path / "screenshots" / self.scan_id
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        output = await self._run_command(
            ["gowitness", "single", base_url, "-P", str(screenshot_dir)],
            timeout=60
        )

        # List captured screenshots
        if screenshot_dir.exists():
            for f in screenshot_dir.glob("*.png"):
                results["screenshots"].append(str(f))

        return results

    def _merge_results(self, base: Dict, new: Dict) -> Dict:
        """Merge two result dictionaries"""
        for key, value in new.items():
            if key in base:
                if isinstance(value, list):
                    # Deduplicate while merging
                    existing = set(str(x) for x in base[key])
                    for item in value:
                        if str(item) not in existing:
                            base[key].append(item)
                            existing.add(str(item))
                elif isinstance(value, dict):
                    base[key].update(value)
            else:
                base[key] = value
        return base


async def check_tools_installed() -> Dict[str, bool]:
    """Check which recon tools are installed"""
    tools = [
        # Subdomain enumeration
        "subfinder", "amass", "assetfinder", "chaos", "cero",
        # DNS
        "dnsx", "massdns", "puredns",
        # HTTP probing
        "httpx", "httprobe",
        # URL discovery
        "gau", "waybackurls", "katana", "gospider", "hakrawler", "cariddi", "getJS",
        # Port scanning
        "nmap", "naabu", "rustscan",
        # Tech detection
        "whatweb", "wafw00f",
        # Fuzzing
        "ffuf", "gobuster", "dirb", "dirsearch", "wfuzz",
        # Parameter discovery
        "arjun", "paramspider",
        # Vulnerability scanning
        "nuclei", "nikto", "sqlmap", "dalfox", "crlfuzz",
        # Utilities
        "gf", "qsreplace", "unfurl", "anew", "jq",
        # Screenshot
        "gowitness",
        # Network
        "curl", "wget", "dig", "whois"
    ]

    results = {}
    for tool in tools:
        results[tool] = shutil.which(tool) is not None

    return results
