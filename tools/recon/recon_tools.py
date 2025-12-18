#!/usr/bin/env python3
"""
Reconnaissance Tools - Network scanning, web recon, OSINT, DNS enumeration
"""

import subprocess
import json
import re
import socket
import requests
from typing import Dict, List
import logging
from urllib.parse import urlparse
import dns.resolver

logger = logging.getLogger(__name__)


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
