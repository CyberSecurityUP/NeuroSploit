#!/usr/bin/env python3
"""
Reconnaissance Tools - Network scanning, web recon, OSINT, DNS enumeration
Ferramentas avancadas de recon com suporte a multiplas ferramentas externas
"""

import subprocess
import json
import re
import socket
import requests
import shutil
import os
import concurrent.futures
from typing import Dict, List, Optional, Set, Tuple
import logging
from urllib.parse import urlparse, parse_qs
from pathlib import Path

try:
    import dns.resolver
except ImportError:
    dns = None

logger = logging.getLogger(__name__)


def check_tool(tool_name: str) -> Tuple[bool, Optional[str]]:
    """Verifica se uma ferramenta esta instalada."""
    path = shutil.which(tool_name)
    return (path is not None, path)


def run_tool(cmd: List[str], timeout: int = 300) -> Dict:
    """Executa uma ferramenta e retorna o resultado."""
    result = {
        "tool": cmd[0] if cmd else "unknown",
        "command": " ".join(cmd),
        "success": False,
        "stdout": "",
        "stderr": "",
        "exit_code": -1
    }

    if not shutil.which(cmd[0]):
        result["stderr"] = f"Tool '{cmd[0]}' not found"
        return result

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr
        result["exit_code"] = proc.returncode
        result["success"] = proc.returncode == 0
    except subprocess.TimeoutExpired:
        result["stderr"] = f"Timeout after {timeout}s"
    except Exception as e:
        result["stderr"] = str(e)

    return result


class NetworkScanner:
    """Network scanning and port enumeration"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.nmap_path = config.get('tools', {}).get('nmap', '/usr/bin/nmap')
    
    def scan(self, target: str) -> Dict:
        """Perform comprehensive network scan"""
        logger.info(f"Scanning target: {target}")
        
        results = {
            "target": target,
            "hosts": {},
            "summary": {}
        }
        
        try:
            # Quick scan for open ports
            quick_scan = self._nmap_scan(target, "-sS -T4 -p-")
            results["hosts"].update(quick_scan)
            
            # Service version detection
            if results["hosts"]:
                version_scan = self._nmap_scan(target, "-sV -sC")
                results["hosts"].update(version_scan)
            
            # Vulnerability scan
            vuln_scan = self._nmap_vuln_scan(target)
            results["vulnerabilities"] = vuln_scan
            
            results["summary"] = self._generate_summary(results["hosts"])
            
        except Exception as e:
            logger.error(f"Network scan error: {e}")
            results["error"] = str(e)
        
        return results
    
    def _nmap_scan(self, target: str, options: str) -> Dict:
        """Execute nmap scan"""
        try:
            cmd = f"{self.nmap_path} {options} {target} -oX -"
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                timeout=300,
                text=True
            )
            
            return self._parse_nmap_output(result.stdout)
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return {}
    
    def _nmap_vuln_scan(self, target: str) -> List[Dict]:
        """Scan for vulnerabilities using NSE scripts"""
        try:
            cmd = f"{self.nmap_path} --script vuln {target}"
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                timeout=600,
                text=True
            )
            
            return self._parse_vuln_output(result.stdout)
        except Exception as e:
            logger.error(f"Vulnerability scan error: {e}")
            return []
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse nmap XML output"""
        hosts = {}
        
        # Simple parsing - in production, use proper XML parser
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
        
        current_ip = None
        for line in output.split('\n'):
            ip_match = re.search(ip_pattern, line)
            if ip_match and 'Nmap scan report' in line:
                current_ip = ip_match.group(1)
                hosts[current_ip] = {
                    "ip": current_ip,
                    "open_ports": [],
                    "os": "unknown"
                }
            
            port_match = re.search(port_pattern, line)
            if port_match and current_ip:
                hosts[current_ip]["open_ports"].append({
                    "port": int(port_match.group(1)),
                    "service": port_match.group(2),
                    "version": "unknown"
                })
        
        return hosts
    
    def _parse_vuln_output(self, output: str) -> List[Dict]:
        """Parse vulnerability scan output"""
        vulnerabilities = []
        
        # Extract CVEs and vulnerability info
        cve_pattern = r'(CVE-\d{4}-\d+)'
        for match in re.finditer(cve_pattern, output):
            vulnerabilities.append({
                "cve": match.group(1),
                "severity": "unknown"
            })
        
        return vulnerabilities
    
    def _generate_summary(self, hosts: Dict) -> Dict:
        """Generate scan summary"""
        total_hosts = len(hosts)
        total_ports = sum(len(h.get("open_ports", [])) for h in hosts.values())
        services = set()
        
        for host in hosts.values():
            for port in host.get("open_ports", []):
                services.add(port.get("service"))
        
        return {
            "total_hosts": total_hosts,
            "total_open_ports": total_ports,
            "unique_services": list(services)
        }


class WebRecon:
    """Web application reconnaissance"""
    
    def __init__(self, config: Dict):
        self.config = config
    
    def analyze(self, url: str) -> Dict:
        """Analyze web application"""
        logger.info(f"Analyzing web application: {url}")
        
        results = {
            "url": url,
            "technologies": [],
            "headers": {},
            "security_headers": {},
            "endpoints": [],
            "forms": [],
            "vulnerabilities": []
        }
        
        try:
            # Technology detection
            results["technologies"] = self._detect_technologies(url)
            
            # Header analysis
            results["headers"], results["security_headers"] = self._analyze_headers(url)
            
            # Endpoint discovery
            results["endpoints"] = self._discover_endpoints(url)
            
            # Form detection
            results["forms"] = self._detect_forms(url)
            
            # Quick vulnerability checks
            results["vulnerabilities"] = self._check_vulnerabilities(url)
            
        except Exception as e:
            logger.error(f"Web recon error: {e}")
            results["error"] = str(e)
        
        return results
    
    def _detect_technologies(self, url: str) -> List[str]:
        """Detect web technologies"""
        technologies = []
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            
            # Check headers for technology indicators
            server = response.headers.get('Server', '')
            if server:
                technologies.append(f"Server: {server}")
            
            x_powered_by = response.headers.get('X-Powered-By', '')
            if x_powered_by:
                technologies.append(f"X-Powered-By: {x_powered_by}")
            
            # Check content for framework indicators
            content = response.text.lower()
            if 'wordpress' in content:
                technologies.append("WordPress")
            if 'joomla' in content:
                technologies.append("Joomla")
            if 'drupal' in content:
                technologies.append("Drupal")
            if 'django' in content:
                technologies.append("Django")
            if 'laravel' in content:
                technologies.append("Laravel")
            
        except Exception as e:
            logger.error(f"Technology detection error: {e}")
        
        return technologies
    
    def _analyze_headers(self, url: str) -> tuple:
        """Analyze HTTP headers"""
        headers = {}
        security_headers = {}
        
        try:
            response = requests.head(url, timeout=10, verify=False)
            headers = dict(response.headers)
            
            # Check for security headers
            security_checks = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-XSS-Protection'
            ]
            
            for header in security_checks:
                if header in headers:
                    security_headers[header] = headers[header]
                else:
                    security_headers[header] = "Missing"
        
        except Exception as e:
            logger.error(f"Header analysis error: {e}")
        
        return headers, security_headers
    
    def _discover_endpoints(self, url: str) -> List[str]:
        """Discover endpoints using common paths"""
        endpoints = []
        common_paths = [
            '/admin', '/login', '/api', '/config', '/backup',
            '/admin.php', '/phpinfo.php', '/info.php',
            '/robots.txt', '/sitemap.xml', '/.git', '/.env'
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in common_paths:
            try:
                response = requests.head(
                    f"{base_url}{path}",
                    timeout=5,
                    verify=False,
                    allow_redirects=False
                )
                
                if response.status_code < 400:
                    endpoints.append(path)
            except:
                continue
        
        return endpoints
    
    def _detect_forms(self, url: str) -> List[Dict]:
        """Detect forms on webpage"""
        forms = []
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            
            # Simple form detection
            form_pattern = r'<form[^>]*>(.*?)</form>'
            for match in re.finditer(form_pattern, response.text, re.DOTALL):
                forms.append({
                    "action": re.search(r'action=["\']([^"\']+)["\']', match.group(0)),
                    "method": re.search(r'method=["\']([^"\']+)["\']', match.group(0))
                })
        except Exception as e:
            logger.error(f"Form detection error: {e}")
        
        return forms
    
    def _check_vulnerabilities(self, url: str) -> List[str]:
        """Quick vulnerability checks"""
        vulnerabilities = []
        
        try:
            # SQL Injection test
            test_url = f"{url}?id=1'"
            response = requests.get(test_url, timeout=10, verify=False)
            if 'sql' in response.text.lower() or 'mysql' in response.text.lower():
                vulnerabilities.append("Potential SQL Injection")
            
            # XSS test
            test_url = f"{url}?q=<script>alert(1)</script>"
            response = requests.get(test_url, timeout=10, verify=False)
            if '<script>alert(1)</script>' in response.text:
                vulnerabilities.append("Potential XSS")
        
        except Exception as e:
            logger.error(f"Vulnerability check error: {e}")
        
        return vulnerabilities


class OSINTCollector:
    """Open Source Intelligence collection"""
    
    def __init__(self, config: Dict):
        self.config = config
    
    def collect(self, target: str) -> Dict:
        """Collect OSINT data"""
        logger.info(f"Collecting OSINT for: {target}")
        
        return {
            "target": target,
            "emails": self._find_emails(target),
            "social_media": self._find_social_media(target),
            "data_breaches": self._check_breaches(target),
            "metadata": self._collect_metadata(target)
        }
    
    def _find_emails(self, target: str) -> List[str]:
        """Find email addresses"""
        # Placeholder - would use theHarvester or similar
        return []
    
    def _find_social_media(self, target: str) -> Dict:
        """Find social media profiles"""
        return {}
    
    def _check_breaches(self, target: str) -> List[str]:
        """Check for data breaches"""
        return []
    
    def _collect_metadata(self, target: str) -> Dict:
        """Collect metadata"""
        return {}


class DNSEnumerator:
    """DNS enumeration"""
    
    def __init__(self, config: Dict):
        self.config = config
    
    def enumerate(self, domain: str) -> Dict:
        """Enumerate DNS records"""
        logger.info(f"Enumerating DNS for: {domain}")
        
        records = {
            "domain": domain,
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "SOA": []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except:
                continue
        
        return records


class SubdomainFinder:
    """Subdomain discovery"""

    def __init__(self, config: Dict):
        self.config = config

    def find(self, domain: str) -> List[str]:
        """Find subdomains"""
        logger.info(f"Finding subdomains for: {domain}")

        subdomains = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev',
            'staging', 'api', 'blog', 'shop', 'portal'
        ]

        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.append(subdomain)
            except:
                continue

        return subdomains


# ============================================================================
# ADVANCED RECON TOOLS
# ============================================================================

class AdvancedSubdomainEnum:
    """Advanced subdomain enumeration using multiple tools."""

    TOOLS = ['subfinder', 'amass', 'assetfinder', 'findomain']

    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get('timeout', 300)

    def enumerate(self, domain: str) -> Dict:
        """Enumerate subdomains using all available tools."""
        logger.info(f"[*] Enumerating subdomains for: {domain}")
        print(f"[*] Enumerating subdomains for: {domain}")

        all_subdomains: Set[str] = set()
        results = {"domain": domain, "subdomains": [], "by_tool": {}}

        for tool in self.TOOLS:
            installed, _ = check_tool(tool)
            if not installed:
                logger.warning(f"    [-] {tool} not installed, skipping...")
                continue

            print(f"    [*] Running {tool}...")
            tool_subs = self._run_tool(tool, domain)
            results["by_tool"][tool] = tool_subs
            all_subdomains.update(tool_subs)
            print(f"    [+] {tool}: {len(tool_subs)} subdomains")

        results["subdomains"] = sorted(list(all_subdomains))
        results["total"] = len(all_subdomains)
        print(f"[+] Total unique subdomains: {len(all_subdomains)}")

        return results

    def _run_tool(self, tool: str, domain: str) -> List[str]:
        """Run a specific tool."""
        subdomains = []

        if tool == "subfinder":
            result = run_tool(["subfinder", "-d", domain, "-silent"], self.timeout)
        elif tool == "amass":
            result = run_tool(["amass", "enum", "-passive", "-d", domain], self.timeout)
        elif tool == "assetfinder":
            result = run_tool(["assetfinder", "--subs-only", domain], self.timeout)
        elif tool == "findomain":
            result = run_tool(["findomain", "-t", domain, "-q"], self.timeout)
        else:
            return []

        if result["stdout"]:
            for line in result["stdout"].strip().split('\n'):
                sub = line.strip().lower()
                if sub and domain in sub:
                    subdomains.append(sub)

        return subdomains


class HttpProber:
    """Check active HTTP hosts using httpx or httprobe."""

    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get('timeout', 120)

    def probe(self, hosts: List[str]) -> Dict:
        """Check which hosts are alive via HTTP/HTTPS."""
        logger.info(f"[*] Probing {len(hosts)} hosts...")
        print(f"[*] Probing {len(hosts)} hosts via HTTP...")

        results = {
            "total_input": len(hosts),
            "alive": [],
            "technologies": {},
            "status_codes": {}
        }

        # Try httpx first (more complete)
        httpx_installed, _ = check_tool("httpx")
        if httpx_installed:
            results = self._run_httpx(hosts)
        else:
            # Fallback to httprobe
            httprobe_installed, _ = check_tool("httprobe")
            if httprobe_installed:
                results = self._run_httprobe(hosts)
            else:
                # Manual fallback with curl
                results = self._manual_probe(hosts)

        print(f"[+] Alive hosts: {len(results['alive'])}")
        return results

    def _run_httpx(self, hosts: List[str]) -> Dict:
        """Run httpx for advanced probing."""
        results = {"total_input": len(hosts), "alive": [], "technologies": {}, "status_codes": {}}

        # Create temp file with hosts
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(hosts))
            hosts_file = f.name

        try:
            cmd = ["httpx", "-l", hosts_file, "-silent", "-status-code", "-tech-detect", "-json"]
            result = run_tool(cmd, self.timeout)

            if result["stdout"]:
                for line in result["stdout"].strip().split('\n'):
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        url = data.get("url", "")
                        if url:
                            results["alive"].append(url)

                            # Technologies
                            techs = data.get("tech", [])
                            for tech in techs:
                                results["technologies"][tech] = results["technologies"].get(tech, 0) + 1

                            # Status codes
                            status = str(data.get("status_code", ""))
                            if status:
                                results["status_codes"][status] = results["status_codes"].get(status, 0) + 1
                    except json.JSONDecodeError:
                        continue
        finally:
            os.unlink(hosts_file)

        return results

    def _run_httprobe(self, hosts: List[str]) -> Dict:
        """Run httprobe for basic probing."""
        results = {"total_input": len(hosts), "alive": [], "technologies": {}, "status_codes": {}}

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(hosts))
            hosts_file = f.name

        try:
            with open(hosts_file, 'r') as stdin:
                proc = subprocess.run(
                    ["httprobe"],
                    stdin=stdin,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )
                if proc.stdout:
                    results["alive"] = [line.strip() for line in proc.stdout.strip().split('\n') if line.strip()]
        except Exception as e:
            logger.error(f"httprobe error: {e}")
        finally:
            os.unlink(hosts_file)

        return results

    def _manual_probe(self, hosts: List[str]) -> Dict:
        """Manual probing using requests."""
        results = {"total_input": len(hosts), "alive": [], "technologies": {}, "status_codes": {}}

        for host in hosts[:100]:  # Limit to avoid long execution
            for scheme in ['https://', 'http://']:
                url = f"{scheme}{host}" if not host.startswith('http') else host
                try:
                    resp = requests.head(url, timeout=5, verify=False, allow_redirects=True)
                    results["alive"].append(url)
                    results["status_codes"][str(resp.status_code)] = results["status_codes"].get(str(resp.status_code), 0) + 1
                    break
                except:
                    continue

        return results


class URLCollector:
    """Collect URLs using gau, waybackurls and waymore."""

    TOOLS = ['gau', 'waybackurls', 'waymore']

    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get('timeout', 300)

    def collect(self, domain: str) -> Dict:
        """Collect URLs from passive sources."""
        logger.info(f"[*] Collecting URLs for: {domain}")
        print(f"[*] Collecting historical URLs for: {domain}")

        all_urls: Set[str] = set()
        urls_with_params: Set[str] = set()
        js_files: Set[str] = set()
        results = {"domain": domain, "urls": [], "by_tool": {}}

        for tool in self.TOOLS:
            installed, _ = check_tool(tool)
            if not installed:
                continue

            print(f"    [*] Running {tool}...")
            tool_urls = self._run_tool(tool, domain)
            results["by_tool"][tool] = len(tool_urls)

            for url in tool_urls:
                all_urls.add(url)
                if '?' in url and '=' in url:
                    urls_with_params.add(url)
                if '.js' in url.lower():
                    js_files.add(url)

            print(f"    [+] {tool}: {len(tool_urls)} URLs")

        results["urls"] = list(all_urls)
        results["urls_with_params"] = list(urls_with_params)
        results["js_files"] = list(js_files)
        results["total"] = len(all_urls)
        print(f"[+] Total unique URLs: {len(all_urls)}")
        print(f"[+] URLs with params: {len(urls_with_params)}")
        print(f"[+] JS files: {len(js_files)}")

        return results

    def _run_tool(self, tool: str, domain: str) -> List[str]:
        """Run a specific tool."""
        urls = []

        if tool == "gau":
            result = run_tool(["gau", domain], self.timeout)
        elif tool == "waybackurls":
            result = run_tool(["waybackurls", domain], self.timeout)
        elif tool == "waymore":
            result = run_tool(["waymore", "-i", domain, "-mode", "U"], self.timeout)
        else:
            return []

        if result["stdout"]:
            for line in result["stdout"].strip().split('\n'):
                url = line.strip()
                if url and url.startswith(('http://', 'https://')):
                    urls.append(url)

        return urls


class WebCrawler:
    """Web crawler using katana or gospider."""

    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get('timeout', 300)
        self.depth = config.get('crawl_depth', 3)

    def crawl(self, target: str) -> Dict:
        """Crawl target to discover URLs, forms, endpoints."""
        logger.info(f"[*] Crawling: {target}")
        print(f"[*] Starting crawl on: {target}")

        results = {
            "target": target,
            "urls": [],
            "forms": [],
            "js_files": [],
            "api_endpoints": [],
            "params": []
        }

        # Try katana first
        katana_installed, _ = check_tool("katana")
        if katana_installed:
            results = self._run_katana(target)
        else:
            # Fallback to gospider
            gospider_installed, _ = check_tool("gospider")
            if gospider_installed:
                results = self._run_gospider(target)

        print(f"[+] URLs discovered: {len(results.get('urls', []))}")
        return results

    def _run_katana(self, target: str) -> Dict:
        """Run katana for crawling."""
        results = {"target": target, "urls": [], "forms": [], "js_files": [], "api_endpoints": [], "params": []}

        cmd = ["katana", "-u", target, "-d", str(self.depth), "-silent", "-jc", "-kf", "all", "-ef", "css,png,jpg,gif,svg,ico"]
        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            for line in result["stdout"].strip().split('\n'):
                url = line.strip()
                if not url:
                    continue

                results["urls"].append(url)

                if '.js' in url.lower():
                    results["js_files"].append(url)
                if '/api/' in url.lower() or '/v1/' in url or '/v2/' in url:
                    results["api_endpoints"].append(url)
                if '?' in url and '=' in url:
                    results["params"].append(url)

        return results

    def _run_gospider(self, target: str) -> Dict:
        """Run gospider for crawling."""
        results = {"target": target, "urls": [], "forms": [], "js_files": [], "api_endpoints": [], "params": []}

        cmd = ["gospider", "-s", target, "-d", str(self.depth), "--no-redirect", "-q"]
        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            for line in result["stdout"].strip().split('\n'):
                # gospider output: [source] URL
                if ' - ' in line:
                    url = line.split(' - ')[-1].strip()
                else:
                    url = line.strip()

                if url and url.startswith(('http://', 'https://')):
                    results["urls"].append(url)

                    if '.js' in url.lower():
                        results["js_files"].append(url)
                    if '/api/' in url.lower():
                        results["api_endpoints"].append(url)
                    if '?' in url:
                        results["params"].append(url)

        return results


class PortScanner:
    """Port scanner using naabu or nmap."""

    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get('timeout', 600)

    def scan(self, target: str, ports: str = "1-10000") -> Dict:
        """Port scan on target."""
        logger.info(f"[*] Scanning ports on: {target}")
        print(f"[*] Scanning ports on: {target}")

        results = {"target": target, "open_ports": [], "by_service": {}}

        # Try naabu first (faster)
        naabu_installed, _ = check_tool("naabu")
        if naabu_installed:
            results = self._run_naabu(target, ports)
        else:
            # Fallback to nmap
            nmap_installed, _ = check_tool("nmap")
            if nmap_installed:
                results = self._run_nmap(target, ports)

        print(f"[+] Open ports: {len(results.get('open_ports', []))}")
        return results

    def _run_naabu(self, target: str, ports: str) -> Dict:
        """Run naabu for fast port scan."""
        results = {"target": target, "open_ports": [], "by_service": {}}

        cmd = ["naabu", "-host", target, "-p", ports, "-silent"]
        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            for line in result["stdout"].strip().split('\n'):
                line = line.strip()
                if ':' in line:
                    host, port = line.rsplit(':', 1)
                    try:
                        results["open_ports"].append({
                            "host": host,
                            "port": int(port),
                            "protocol": "tcp"
                        })
                    except ValueError:
                        continue

        return results

    def _run_nmap(self, target: str, ports: str) -> Dict:
        """Run nmap for detailed port scan."""
        results = {"target": target, "open_ports": [], "by_service": {}}

        cmd = ["nmap", "-sS", "-T4", "-p", ports, "--open", target]
        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            port_pattern = r"(\d+)/(\w+)\s+open\s+(\S+)"
            for match in re.finditer(port_pattern, result["stdout"]):
                port_info = {
                    "host": target,
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "service": match.group(3)
                }
                results["open_ports"].append(port_info)
                results["by_service"][match.group(3)] = results["by_service"].get(match.group(3), 0) + 1

        return results


class VulnScanner:
    """Vulnerability scanner using nuclei."""

    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get('timeout', 600)

    def scan(self, targets: List[str], templates: str = None) -> Dict:
        """Vulnerability scan on targets."""
        logger.info(f"[*] Scanning vulnerabilities on {len(targets)} targets")
        print(f"[*] Scanning vulnerabilities on {len(targets)} targets...")

        results = {
            "total_targets": len(targets),
            "vulnerabilities": [],
            "by_severity": {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        }

        nuclei_installed, _ = check_tool("nuclei")
        if not nuclei_installed:
            print("    [-] nuclei not installed")
            return results

        # Create temp file with targets
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            targets_file = f.name

        try:
            cmd = ["nuclei", "-l", targets_file, "-silent", "-nc", "-j"]
            if templates:
                cmd.extend(["-t", templates])

            result = run_tool(cmd, self.timeout)

            if result["stdout"]:
                for line in result["stdout"].strip().split('\n'):
                    if not line.strip():
                        continue
                    try:
                        finding = json.loads(line)
                        vuln = {
                            "template": finding.get("template-id", ""),
                            "name": finding.get("info", {}).get("name", ""),
                            "severity": finding.get("info", {}).get("severity", "info"),
                            "url": finding.get("matched-at", ""),
                            "description": finding.get("info", {}).get("description", ""),
                            "curl_command": finding.get("curl-command", "")
                        }
                        results["vulnerabilities"].append(vuln)

                        sev = vuln["severity"].lower()
                        if sev in results["by_severity"]:
                            results["by_severity"][sev].append(vuln)

                        print(f"    [!] [{sev.upper()}] {vuln['name']} - {vuln['url']}")
                    except json.JSONDecodeError:
                        continue
        finally:
            os.unlink(targets_file)

        print(f"[+] Vulnerabilities found: {len(results['vulnerabilities'])}")
        return results


class FullReconRunner:
    """Run all recon tools and consolidate results."""

    def __init__(self, config: Dict = None):
        self.config = config or {}

    def run(self, target: str, target_type: str = "domain") -> Dict:
        """
        Run full recon and return consolidated context.

        Args:
            target: Target domain or URL
            target_type: Target type (domain, url)

        Returns:
            Dict with all consolidated results
        """
        from core.context_builder import ReconContextBuilder

        print(f"\n{'='*70}")
        print("    NEUROSPLOIT - ADVANCED RECON")
        print(f"{'='*70}")
        print(f"\n[*] Target: {target}")
        print(f"[*] Type: {target_type}\n")

        # Initialize context builder
        ctx = ReconContextBuilder()
        ctx.set_target(target, target_type)

        # Extract domain from target
        if target_type == "url":
            parsed = urlparse(target)
            domain = parsed.netloc
        else:
            domain = target

        # 1. Subdomain Enumeration
        print("\n" + "=" * 50)
        print("[PHASE 1] Subdomain Enumeration")
        print("=" * 50)
        sub_enum = AdvancedSubdomainEnum(self.config)
        sub_results = sub_enum.enumerate(domain)
        ctx.add_subdomains(sub_results.get("subdomains", []))
        ctx.add_tool_result("subdomain_enum", sub_results)

        # 2. HTTP Probing
        print("\n" + "=" * 50)
        print("[PHASE 2] HTTP Probing")
        print("=" * 50)
        prober = HttpProber(self.config)
        probe_results = prober.probe(sub_results.get("subdomains", [domain]))
        ctx.add_live_hosts(probe_results.get("alive", []))
        ctx.add_technologies(list(probe_results.get("technologies", {}).keys()))
        ctx.add_tool_result("http_probe", probe_results)

        # 3. URL Collection
        print("\n" + "=" * 50)
        print("[PHASE 3] URL Collection")
        print("=" * 50)
        url_collector = URLCollector(self.config)
        url_results = url_collector.collect(domain)
        ctx.add_urls(url_results.get("urls", []))
        ctx.add_js_files(url_results.get("js_files", []))
        ctx.add_tool_result("url_collection", url_results)

        # 4. Web Crawling
        print("\n" + "=" * 50)
        print("[PHASE 4] Web Crawling")
        print("=" * 50)
        crawler = WebCrawler(self.config)
        alive_hosts = probe_results.get("alive", [])
        if alive_hosts:
            crawl_target = alive_hosts[0]  # Crawl first alive host
            crawl_results = crawler.crawl(crawl_target)
            ctx.add_urls(crawl_results.get("urls", []))
            ctx.add_js_files(crawl_results.get("js_files", []))
            ctx.add_api_endpoints(crawl_results.get("api_endpoints", []))
            ctx.add_tool_result("crawling", crawl_results)

        # 5. Port Scanning
        print("\n" + "=" * 50)
        print("[PHASE 5] Port Scanning")
        print("=" * 50)
        port_scanner = PortScanner(self.config)
        port_results = port_scanner.scan(domain)
        ctx.add_open_ports(port_results.get("open_ports", []))
        ctx.add_tool_result("port_scan", port_results)

        # 6. DNS Enumeration
        print("\n" + "=" * 50)
        print("[PHASE 6] DNS Enumeration")
        print("=" * 50)
        dns_enum = DNSEnumerator(self.config)
        dns_results = dns_enum.enumerate(domain)
        dns_records = []
        for rtype, records in dns_results.items():
            if rtype != "domain" and records:
                for r in records:
                    dns_records.append(f"[{rtype}] {r}")
        ctx.add_dns_records(dns_records)
        ctx.add_tool_result("dns_enum", dns_results)

        # 7. Vulnerability Scanning
        print("\n" + "=" * 50)
        print("[PHASE 7] Vulnerability Scanning")
        print("=" * 50)
        vuln_scanner = VulnScanner(self.config)
        scan_targets = probe_results.get("alive", [target])[:20]  # Limit to 20
        vuln_results = vuln_scanner.scan(scan_targets)

        vulns = []
        for v in vuln_results.get("vulnerabilities", []):
            vulns.append({
                "title": v.get("name", ""),
                "severity": v.get("severity", "info"),
                "affected_endpoint": v.get("url", ""),
                "description": v.get("description", "")
            })
        ctx.add_vulnerabilities(vulns)
        ctx.add_tool_result("vuln_scan", vuln_results)

        # Identify interesting paths
        all_urls = list(ctx.urls)
        ctx.add_interesting_paths(all_urls)

        # Save consolidated context
        print("\n" + "=" * 50)
        print("[FINAL PHASE] Consolidating Context")
        print("=" * 50)
        saved = ctx.save()

        print(f"\n{'='*70}")
        print("[+] RECON COMPLETE!")
        print(f"    - Subdomains: {len(ctx.subdomains)}")
        print(f"    - Live hosts: {len(ctx.live_hosts)}")
        print(f"    - URLs: {len(ctx.urls)}")
        print(f"    - URLs with params: {len(ctx.urls_with_params)}")
        print(f"    - Open ports: {len(ctx.open_ports)}")
        print(f"    - Vulnerabilities: {len(ctx.vulnerabilities)}")
        print(f"\n[+] Context saved to: {saved['json']}")
        print(f"{'='*70}\n")

        return {
            "context": saved["context"],
            "context_file": str(saved["json"]),
            "context_text_file": str(saved["txt"]),
            "context_text": ctx.get_llm_prompt_context()
        }
