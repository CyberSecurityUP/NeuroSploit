#!/usr/bin/env python3
"""
NeuroSploit Advanced Reconnaissance Module
Deep enumeration with multiple tools and techniques
"""

import subprocess
import json
import re
import socket
import requests
import shutil
import os
import sys
import concurrent.futures
import hashlib
import base64
import tempfile
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
import logging
from urllib.parse import urlparse, parse_qs, urljoin, quote
from pathlib import Path
from dataclasses import dataclass, field

try:
    import dns.resolver
except ImportError:
    dns = None

logger = logging.getLogger(__name__)

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# CONFIGURATION
# =============================================================================

SECLISTS_BASE = "/opt/wordlists/SecLists"
WORDLISTS = {
    "directories_small": f"{SECLISTS_BASE}/Discovery/Web-Content/directory-list-2.3-small.txt",
    "directories_medium": f"{SECLISTS_BASE}/Discovery/Web-Content/raft-medium-directories.txt",
    "directories_big": f"{SECLISTS_BASE}/Discovery/Web-Content/directory-list-2.3-big.txt",
    "common": f"{SECLISTS_BASE}/Discovery/Web-Content/common.txt",
    "subdomains_small": f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-5000.txt",
    "subdomains_medium": f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-20000.txt",
    "subdomains_big": f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-110000.txt",
    "dns_jhaddix": f"{SECLISTS_BASE}/Discovery/DNS/dns-Jhaddix.txt",
    "params": f"{SECLISTS_BASE}/Discovery/Web-Content/burp-parameter-names.txt",
    "api_endpoints": f"{SECLISTS_BASE}/Discovery/Web-Content/api/api-endpoints.txt",
    "backup_files": f"{SECLISTS_BASE}/Discovery/Web-Content/Common-DB-Backups.txt",
}

# Common ports for fast scan
COMMON_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,8888,9000,9200,27017"
TOP_1000_PORTS = "1-1000"
FULL_PORTS = "1-65535"

# Patterns for sensitive data extraction
SECRET_PATTERNS = {
    "aws_key": r"(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "aws_secret": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
    "github_token": r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
    "google_api": r"AIza[0-9A-Za-z\\-_]{35}",
    "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "jwt": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "password_field": r"(?i)(?:password|passwd|pwd|secret|token|api_key|apikey|auth)[\s]*[=:]\s*['\"]?[^\s'\"]+",
    "internal_ip": r"(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}",
    "s3_bucket": r"(?:s3://|s3\.amazonaws\.com/|s3-[\w-]+\.amazonaws\.com/)[\w.-]+",
    "firebase": r"https://[\w-]+\.firebaseio\.com",
    "bearer_token": r"(?i)bearer\s+[a-zA-Z0-9\-_.~+/]+=*",
}

# CNAME records indicating potential takeover
TAKEOVER_CNAMES = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "pantheonsite.io": "Pantheon",
    "domains.tumblr.com": "Tumblr",
    "wpengine.com": "WP Engine",
    "ghost.io": "Ghost",
    "myshopify.com": "Shopify",
    "surge.sh": "Surge.sh",
    "bitbucket.io": "Bitbucket",
    "freshdesk.com": "Freshdesk",
    "zendesk.com": "Zendesk",
    "uservoice.com": "UserVoice",
    "teamwork.com": "Teamwork",
    "helpjuice.com": "Helpjuice",
    "helpscoutdocs.com": "HelpScout",
    "feedpress.me": "Feedpress",
    "readme.io": "Readme.io",
    "statuspage.io": "Statuspage",
    "azurewebsites.net": "Azure",
    "cloudapp.net": "Azure",
    "trafficmanager.net": "Azure",
    "blob.core.windows.net": "Azure Blob",
    "cloudfront.net": "AWS CloudFront",
    "s3.amazonaws.com": "AWS S3",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "amazonaws.com": "AWS",
    "storage.googleapis.com": "Google Cloud Storage",
    "appspot.com": "Google App Engine",
    "firebaseapp.com": "Firebase",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "now.sh": "Vercel",
    "fly.dev": "Fly.io",
    "render.com": "Render",
}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def check_tool(tool_name: str) -> Tuple[bool, Optional[str]]:
    """Check if a tool is installed and return its path."""
    path = shutil.which(tool_name)
    return (path is not None, path)


def run_tool(cmd: List[str], timeout: int = 300, stdin_data: str = None) -> Dict:
    """Execute a tool and return structured results."""
    result = {
        "tool": cmd[0] if cmd else "unknown",
        "command": " ".join(cmd),
        "success": False,
        "stdout": "",
        "stderr": "",
        "exit_code": -1,
        "timed_out": False
    }

    tool_path = shutil.which(cmd[0])
    if not tool_path:
        result["stderr"] = f"Tool '{cmd[0]}' not found in PATH"
        return result

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_data
        )
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr
        result["exit_code"] = proc.returncode
        result["success"] = proc.returncode == 0
    except subprocess.TimeoutExpired:
        result["stderr"] = f"Timeout after {timeout}s"
        result["timed_out"] = True
    except Exception as e:
        result["stderr"] = str(e)

    return result


def get_wordlist(name: str, fallback: str = None) -> Optional[str]:
    """Get wordlist path, checking if it exists."""
    path = WORDLISTS.get(name)
    if path and os.path.exists(path):
        return path
    if fallback and os.path.exists(fallback):
        return fallback
    return None


def extract_domain(target: str) -> str:
    """Extract domain from URL or return as-is."""
    if target.startswith(('http://', 'https://')):
        return urlparse(target).netloc
    return target


def make_url(host: str, scheme: str = "https") -> str:
    """Ensure host has proper URL format."""
    if host.startswith(('http://', 'https://')):
        return host
    return f"{scheme}://{host}"


def print_phase(phase_num: int, title: str):
    """Print phase header."""
    print(f"\n{'='*60}")
    print(f"[PHASE {phase_num}] {title}")
    print(f"{'='*60}")


def print_result(icon: str, msg: str):
    """Print formatted result."""
    print(f"    {icon} {msg}")


# =============================================================================
# ADVANCED SUBDOMAIN ENUMERATION
# =============================================================================

class AdvancedSubdomainEnum:
    """Deep subdomain enumeration using multiple tools and techniques."""

    TOOLS = ['subfinder', 'amass', 'assetfinder', 'findomain', 'puredns', 'shuffledns']

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 300)

    def enumerate(self, domain: str, depth: str = "medium") -> Dict:
        """
        Enumerate subdomains with multiple tools.

        Args:
            domain: Target domain
            depth: quick, medium, deep
        """
        logger.info(f"[*] Subdomain enumeration for: {domain}")
        print(f"[*] Starting subdomain enumeration for: {domain}")
        print(f"    Depth: {depth}")

        all_subdomains: Set[str] = set()
        results = {
            "domain": domain,
            "subdomains": [],
            "by_tool": {},
            "crt_sh": [],
            "dns_bruteforce": []
        }

        # 1. Certificate Transparency (crt.sh) - Always run first (passive)
        print_result("[~]", "Querying Certificate Transparency logs (crt.sh)...")
        crt_subs = self._crtsh_enum(domain)
        results["crt_sh"] = crt_subs
        all_subdomains.update(crt_subs)
        print_result("[+]", f"crt.sh: {len(crt_subs)} subdomains")

        # 2. Run enumeration tools
        tools_to_run = self.TOOLS if depth == "deep" else self.TOOLS[:4]

        for tool in tools_to_run:
            installed, _ = check_tool(tool)
            if not installed:
                continue

            print_result("[~]", f"Running {tool}...")
            tool_subs = self._run_tool(tool, domain)
            results["by_tool"][tool] = tool_subs
            all_subdomains.update(tool_subs)
            print_result("[+]", f"{tool}: {len(tool_subs)} subdomains")

        # 3. DNS Bruteforce (for deep mode)
        if depth == "deep":
            wordlist = get_wordlist("subdomains_medium")
            if wordlist:
                print_result("[~]", "Running DNS bruteforce...")
                brute_subs = self._dns_bruteforce(domain, wordlist)
                results["dns_bruteforce"] = brute_subs
                all_subdomains.update(brute_subs)
                print_result("[+]", f"Bruteforce: {len(brute_subs)} subdomains")

        # 4. Permutation/mutation (for deep mode)
        if depth == "deep" and all_subdomains:
            print_result("[~]", "Generating permutations...")
            perms = self._generate_permutations(list(all_subdomains)[:100], domain)
            valid_perms = self._resolve_subdomains(perms)
            all_subdomains.update(valid_perms)
            print_result("[+]", f"Permutations: {len(valid_perms)} valid")

        results["subdomains"] = sorted(list(all_subdomains))
        results["total"] = len(all_subdomains)
        print_result("[✓]", f"Total unique subdomains: {len(all_subdomains)}")

        return results

    def _crtsh_enum(self, domain: str) -> List[str]:
        """Query crt.sh Certificate Transparency logs."""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub and "*" not in sub and domain in sub:
                            subdomains.add(sub)
        except Exception as e:
            logger.warning(f"crt.sh error: {e}")
        return list(subdomains)

    def _run_tool(self, tool: str, domain: str) -> List[str]:
        """Run specific subdomain enumeration tool."""
        subdomains = []

        cmd_map = {
            "subfinder": ["subfinder", "-d", domain, "-silent", "-all"],
            "amass": ["amass", "enum", "-passive", "-d", domain, "-silent"],
            "assetfinder": ["assetfinder", "--subs-only", domain],
            "findomain": ["findomain", "-t", domain, "-q"],
            "puredns": ["puredns", "bruteforce", get_wordlist("subdomains_small") or "", domain, "-q"],
            "shuffledns": ["shuffledns", "-d", domain, "-w", get_wordlist("subdomains_small") or "", "-silent"]
        }

        cmd = cmd_map.get(tool)
        if not cmd:
            return []

        result = run_tool(cmd, self.timeout)
        if result["stdout"]:
            for line in result["stdout"].strip().split('\n'):
                sub = line.strip().lower()
                if sub and domain in sub and "*" not in sub:
                    subdomains.append(sub)

        return subdomains

    def _dns_bruteforce(self, domain: str, wordlist: str) -> List[str]:
        """DNS bruteforce using wordlist."""
        found = []
        try:
            with open(wordlist, 'r') as f:
                words = [w.strip() for w in f.readlines()[:5000]]

            def check_sub(word):
                subdomain = f"{word}.{domain}"
                try:
                    socket.gethostbyname(subdomain)
                    return subdomain
                except:
                    return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                results = executor.map(check_sub, words)
                found = [r for r in results if r]
        except Exception as e:
            logger.warning(f"DNS bruteforce error: {e}")
        return found

    def _generate_permutations(self, subdomains: List[str], domain: str) -> List[str]:
        """Generate subdomain permutations."""
        permutations = set()
        prefixes = ['dev', 'staging', 'stage', 'test', 'uat', 'qa', 'prod', 'api', 'admin', 'internal', 'private', 'beta', 'alpha', 'old', 'new', 'v1', 'v2']
        suffixes = ['-dev', '-staging', '-test', '-api', '-admin', '-internal', '2', '-v2', '-old', '-new']

        for sub in subdomains:
            parts = sub.replace(f".{domain}", "").split(".")
            if parts:
                base = parts[0]
                for prefix in prefixes:
                    permutations.add(f"{prefix}.{sub}")
                    permutations.add(f"{prefix}-{base}.{domain}")
                for suffix in suffixes:
                    permutations.add(f"{base}{suffix}.{domain}")

        return list(permutations)[:1000]

    def _resolve_subdomains(self, subdomains: List[str]) -> List[str]:
        """Resolve subdomains to check if they exist."""
        valid = []

        def resolve(sub):
            try:
                socket.gethostbyname(sub)
                return sub
            except:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(resolve, subdomains)
            valid = [r for r in results if r]

        return valid


# =============================================================================
# HTTP PROBING
# =============================================================================

class HttpProber:
    """Advanced HTTP probing with technology detection."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 180)

    def probe(self, hosts: List[str]) -> Dict:
        """Probe hosts for HTTP/HTTPS with detailed info."""
        logger.info(f"[*] Probing {len(hosts)} hosts...")
        print(f"[*] Probing {len(hosts)} hosts for HTTP/HTTPS...")

        results = {
            "total_input": len(hosts),
            "alive": [],
            "details": {},
            "technologies": {},
            "status_codes": {},
            "by_status": defaultdict(list),
            "redirects": [],
            "interesting": []
        }

        httpx_ok, _ = check_tool("httpx")
        if httpx_ok:
            results = self._run_httpx(hosts)
        else:
            results = self._manual_probe(hosts)

        # Identify interesting hosts
        results["interesting"] = self._identify_interesting(results)

        print_result("[+]", f"Alive hosts: {len(results['alive'])}")
        print_result("[+]", f"Technologies found: {len(results['technologies'])}")

        if results["interesting"]:
            print_result("[!]", f"Interesting hosts: {len(results['interesting'])}")

        return results

    def _run_httpx(self, hosts: List[str]) -> Dict:
        """Run httpx with maximum output."""
        results = {
            "total_input": len(hosts),
            "alive": [],
            "details": {},
            "technologies": {},
            "status_codes": {},
            "by_status": defaultdict(list),
            "redirects": [],
            "interesting": []
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(hosts))
            hosts_file = f.name

        try:
            cmd = [
                "httpx", "-l", hosts_file, "-silent",
                "-status-code", "-content-length", "-title", "-tech-detect",
                "-web-server", "-cdn", "-follow-redirects", "-json",
                "-threads", "50", "-timeout", "10"
            ]
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

                            # Store detailed info
                            results["details"][url] = {
                                "status": data.get("status_code"),
                                "title": data.get("title", ""),
                                "server": data.get("webserver", ""),
                                "content_length": data.get("content_length", 0),
                                "technologies": data.get("tech", []),
                                "cdn": data.get("cdn", False),
                                "final_url": data.get("final_url", url)
                            }

                            # Track redirects
                            if data.get("final_url") and data["final_url"] != url:
                                results["redirects"].append({
                                    "from": url,
                                    "to": data["final_url"]
                                })

                            # Technologies
                            for tech in data.get("tech", []):
                                results["technologies"][tech] = results["technologies"].get(tech, 0) + 1

                            # Status codes
                            status = str(data.get("status_code", ""))
                            if status:
                                results["status_codes"][status] = results["status_codes"].get(status, 0) + 1
                                results["by_status"][status].append(url)

                    except json.JSONDecodeError:
                        continue
        finally:
            os.unlink(hosts_file)

        return results

    def _manual_probe(self, hosts: List[str]) -> Dict:
        """Manual HTTP probing fallback."""
        results = {
            "total_input": len(hosts),
            "alive": [],
            "details": {},
            "technologies": {},
            "status_codes": {},
            "by_status": defaultdict(list),
            "redirects": [],
            "interesting": []
        }

        def probe_host(host):
            for scheme in ['https', 'http']:
                url = make_url(host, scheme)
                try:
                    resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                    return {
                        "url": url,
                        "status": resp.status_code,
                        "title": re.search(r'<title>(.*?)</title>', resp.text, re.I),
                        "server": resp.headers.get("Server", ""),
                        "headers": dict(resp.headers)
                    }
                except:
                    continue
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(probe_host, h): h for h in hosts[:500]}
            for future in concurrent.futures.as_completed(futures):
                try:
                    data = future.result()
                    if data:
                        url = data["url"]
                        results["alive"].append(url)
                        results["details"][url] = data
                        status = str(data["status"])
                        results["status_codes"][status] = results["status_codes"].get(status, 0) + 1
                        results["by_status"][status].append(url)
                except:
                    continue

        return results

    def _identify_interesting(self, results: Dict) -> List[Dict]:
        """Identify potentially interesting hosts."""
        interesting = []

        for url, details in results.get("details", {}).items():
            reasons = []

            # Check for interesting status codes
            status = details.get("status", 0)
            if status in [401, 403, 500, 502, 503]:
                reasons.append(f"Status {status}")

            # Check for interesting titles
            title = details.get("title", "").lower()
            interesting_titles = ['admin', 'login', 'dashboard', 'panel', 'jenkins', 'gitlab', 'jira', 'confluence', 'kibana', 'grafana', 'debug', 'staging', 'internal']
            for t in interesting_titles:
                if t in title:
                    reasons.append(f"Title contains '{t}'")
                    break

            # Check for interesting technologies
            techs = details.get("technologies", [])
            risky_techs = ['Apache Tomcat', 'Jenkins', 'GitLab', 'Jira', 'Confluence', 'Elasticsearch', 'Kibana', 'Grafana', 'phpMyAdmin', 'WordPress', 'Drupal']
            for tech in techs:
                if any(rt.lower() in tech.lower() for rt in risky_techs):
                    reasons.append(f"Technology: {tech}")

            if reasons:
                interesting.append({"url": url, "reasons": reasons})

        return interesting


# =============================================================================
# DIRECTORY BRUTEFORCE WITH FEROXBUSTER
# =============================================================================

class DirectoryBruter:
    """Directory/file bruteforcing using feroxbuster or fallbacks."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 600)

    def bruteforce(self, target: str, wordlist_size: str = "medium", extensions: List[str] = None) -> Dict:
        """
        Directory bruteforce using feroxbuster.

        Args:
            target: Target URL
            wordlist_size: small, medium, big
            extensions: File extensions to check
        """
        logger.info(f"[*] Directory bruteforce on: {target}")
        print(f"[*] Starting directory bruteforce on: {target}")

        results = {
            "target": target,
            "directories": [],
            "files": [],
            "interesting": [],
            "status_codes": {},
            "total": 0
        }

        # Get wordlist
        wordlist_key = f"directories_{wordlist_size}"
        wordlist = get_wordlist(wordlist_key, WORDLISTS.get("common"))

        if not wordlist:
            print_result("[-]", "No wordlist available")
            return results

        print_result("[~]", f"Using wordlist: {os.path.basename(wordlist)}")

        # Default extensions
        if not extensions:
            extensions = ["php", "asp", "aspx", "jsp", "html", "js", "json", "xml", "txt", "bak", "old", "conf", "config", "sql", "zip", "tar.gz", "log"]

        ferox_ok, _ = check_tool("feroxbuster")
        if ferox_ok:
            results = self._run_feroxbuster(target, wordlist, extensions)
        else:
            # Fallback to gobuster or ffuf
            gobuster_ok, _ = check_tool("gobuster")
            if gobuster_ok:
                results = self._run_gobuster(target, wordlist, extensions)
            else:
                ffuf_ok, _ = check_tool("ffuf")
                if ffuf_ok:
                    results = self._run_ffuf(target, wordlist, extensions)
                else:
                    print_result("[-]", "No directory bruteforce tool available")
                    return results

        # Identify interesting findings
        results["interesting"] = self._identify_interesting(results)

        print_result("[+]", f"Total found: {results['total']}")
        print_result("[+]", f"Directories: {len(results['directories'])}")
        print_result("[+]", f"Files: {len(results['files'])}")
        if results["interesting"]:
            print_result("[!]", f"Interesting: {len(results['interesting'])}")

        return results

    def _run_feroxbuster(self, target: str, wordlist: str, extensions: List[str]) -> Dict:
        """Run feroxbuster for directory bruteforce."""
        results = {
            "target": target,
            "directories": [],
            "files": [],
            "interesting": [],
            "status_codes": {},
            "total": 0
        }

        ext_str = ",".join(extensions)
        cmd = [
            "feroxbuster",
            "-u", target,
            "-w", wordlist,
            "-x", ext_str,
            "-t", "50",
            "-C", "404,400",
            "--silent",
            "--no-state",
            "-o", "-",
            "--json"
        ]

        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            for line in result["stdout"].strip().split('\n'):
                if not line.strip() or not line.startswith('{'):
                    continue
                try:
                    data = json.loads(line)
                    if data.get("type") == "response":
                        entry = {
                            "url": data.get("url", ""),
                            "status": data.get("status", 0),
                            "size": data.get("content_length", 0),
                            "words": data.get("word_count", 0),
                            "lines": data.get("line_count", 0)
                        }

                        if entry["url"]:
                            results["total"] += 1
                            status = str(entry["status"])
                            results["status_codes"][status] = results["status_codes"].get(status, 0) + 1

                            if entry["url"].endswith('/'):
                                results["directories"].append(entry)
                            else:
                                results["files"].append(entry)
                except:
                    continue

        return results

    def _run_gobuster(self, target: str, wordlist: str, extensions: List[str]) -> Dict:
        """Run gobuster as fallback."""
        results = {
            "target": target,
            "directories": [],
            "files": [],
            "interesting": [],
            "status_codes": {},
            "total": 0
        }

        ext_str = ",".join(extensions)
        cmd = [
            "gobuster", "dir",
            "-u", target,
            "-w", wordlist,
            "-x", ext_str,
            "-t", "50",
            "-q",
            "--no-error"
        ]

        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            pattern = r"(\S+)\s+\(Status:\s*(\d+)\)"
            for match in re.finditer(pattern, result["stdout"]):
                path, status = match.groups()
                entry = {"url": urljoin(target, path), "status": int(status), "size": 0}
                results["total"] += 1
                results["status_codes"][status] = results["status_codes"].get(status, 0) + 1

                if path.endswith('/'):
                    results["directories"].append(entry)
                else:
                    results["files"].append(entry)

        return results

    def _run_ffuf(self, target: str, wordlist: str, extensions: List[str]) -> Dict:
        """Run ffuf as fallback."""
        results = {
            "target": target,
            "directories": [],
            "files": [],
            "interesting": [],
            "status_codes": {},
            "total": 0
        }

        fuzz_url = f"{target.rstrip('/')}/FUZZ"
        cmd = [
            "ffuf",
            "-u", fuzz_url,
            "-w", wordlist,
            "-t", "50",
            "-mc", "200,201,204,301,302,307,308,401,403,405,500",
            "-o", "-",
            "-of", "json",
            "-s"
        ]

        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            try:
                data = json.loads(result["stdout"])
                for entry in data.get("results", []):
                    item = {
                        "url": entry.get("url", ""),
                        "status": entry.get("status", 0),
                        "size": entry.get("length", 0)
                    }
                    results["total"] += 1
                    status = str(item["status"])
                    results["status_codes"][status] = results["status_codes"].get(status, 0) + 1

                    if item["url"].endswith('/'):
                        results["directories"].append(item)
                    else:
                        results["files"].append(item)
            except:
                pass

        return results

    def _identify_interesting(self, results: Dict) -> List[Dict]:
        """Identify interesting findings."""
        interesting = []
        interesting_patterns = [
            r'\.(?:bak|backup|old|orig|save|swp|tmp)$',
            r'\.(?:sql|db|mdb|sqlite)$',
            r'\.(?:conf|config|cfg|ini|env)$',
            r'\.(?:log|logs)$',
            r'(?:admin|login|dashboard|panel|console)',
            r'(?:upload|uploads|files|backup)',
            r'(?:api|v1|v2|graphql)',
            r'(?:\.git|\.svn|\.hg)',
            r'(?:phpinfo|info\.php|test\.php)',
            r'(?:wp-admin|wp-content|wp-includes)',
            r'(?:install|setup|config)',
        ]

        all_items = results["directories"] + results["files"]
        for item in all_items:
            url = item.get("url", "").lower()
            for pattern in interesting_patterns:
                if re.search(pattern, url):
                    interesting.append(item)
                    break

        return interesting


# =============================================================================
# PARAMETER SPIDER
# =============================================================================

class ParamSpider:
    """Parameter discovery using paramspider and analysis."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 300)

    def spider(self, domain: str) -> Dict:
        """Discover parameters from various sources."""
        logger.info(f"[*] Parameter discovery for: {domain}")
        print(f"[*] Starting parameter discovery for: {domain}")

        results = {
            "domain": domain,
            "urls_with_params": [],
            "unique_params": set(),
            "by_param": defaultdict(list),
            "interesting_params": [],
            "total": 0
        }

        # Try paramspider
        paramspider_ok, _ = check_tool("paramspider")
        if paramspider_ok:
            print_result("[~]", "Running paramspider...")
            ps_results = self._run_paramspider(domain)
            results["urls_with_params"].extend(ps_results)
        else:
            print_result("[-]", "paramspider not available, using alternative methods...")

        # Also collect from gau/waybackurls
        print_result("[~]", "Collecting URLs from archives...")
        archive_urls = self._collect_archive_urls(domain)

        # Parse parameters
        all_urls = results["urls_with_params"] + archive_urls
        for url in all_urls:
            params = self._extract_params(url)
            for param in params:
                results["unique_params"].add(param)
                results["by_param"][param].append(url)

        results["unique_params"] = list(results["unique_params"])
        results["total"] = len(all_urls)

        # Identify interesting parameters
        results["interesting_params"] = self._identify_interesting_params(results["unique_params"])

        # Convert defaultdict to regular dict for JSON serialization
        results["by_param"] = dict(results["by_param"])

        print_result("[+]", f"URLs with params: {len(all_urls)}")
        print_result("[+]", f"Unique parameters: {len(results['unique_params'])}")
        if results["interesting_params"]:
            print_result("[!]", f"Interesting params: {', '.join(results['interesting_params'][:10])}")

        return results

    def _run_paramspider(self, domain: str) -> List[str]:
        """Run paramspider tool."""
        urls = []

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = ["paramspider", "-d", domain, "-o", tmpdir, "-s"]
            result = run_tool(cmd, self.timeout)

            # Read output files
            for f in Path(tmpdir).glob("*.txt"):
                try:
                    with open(f, 'r') as file:
                        urls.extend([line.strip() for line in file if '=' in line])
                except:
                    continue

        return urls

    def _collect_archive_urls(self, domain: str) -> List[str]:
        """Collect URLs with parameters from archives."""
        urls = []

        # Try gau
        gau_ok, _ = check_tool("gau")
        if gau_ok:
            result = run_tool(["gau", "--subs", domain], self.timeout)
            if result["stdout"]:
                for line in result["stdout"].strip().split('\n'):
                    url = line.strip()
                    if '?' in url and '=' in url:
                        urls.append(url)

        # Try waybackurls
        wayback_ok, _ = check_tool("waybackurls")
        if wayback_ok:
            result = run_tool(["waybackurls", domain], self.timeout)
            if result["stdout"]:
                for line in result["stdout"].strip().split('\n'):
                    url = line.strip()
                    if '?' in url and '=' in url:
                        urls.append(url)

        return list(set(urls))

    def _extract_params(self, url: str) -> List[str]:
        """Extract parameter names from URL."""
        params = []
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            params = list(query.keys())
        except:
            pass
        return params

    def _identify_interesting_params(self, params: List[str]) -> List[str]:
        """Identify potentially interesting/vulnerable parameters."""
        interesting = []

        sqli_params = ['id', 'pid', 'uid', 'userid', 'user_id', 'item', 'itemid', 'cat', 'category', 'page', 'p', 'q', 'query', 'search', 's', 'keyword', 'order', 'sort', 'filter']
        xss_params = ['q', 'query', 'search', 's', 'keyword', 'name', 'username', 'user', 'email', 'message', 'msg', 'comment', 'text', 'content', 'title', 'desc', 'description', 'error', 'err', 'ref', 'callback', 'redirect', 'url', 'return', 'returnUrl', 'return_url', 'next', 'goto', 'dest', 'destination', 'redir']
        lfi_params = ['file', 'filename', 'path', 'filepath', 'page', 'include', 'inc', 'dir', 'document', 'doc', 'folder', 'root', 'pg', 'template', 'view']
        ssrf_params = ['url', 'uri', 'link', 'src', 'source', 'dest', 'redirect', 'uri', 'path', 'continue', 'return', 'page', 'feed', 'host', 'site', 'html', 'domain', 'callback', 'api']
        rce_params = ['cmd', 'exec', 'command', 'execute', 'ping', 'query', 'jump', 'code', 'reg', 'do', 'func', 'arg', 'option', 'load', 'process', 'step', 'read', 'function', 'req', 'feature', 'exe', 'module', 'payload', 'run', 'print']
        idor_params = ['id', 'user', 'userid', 'user_id', 'account', 'account_id', 'accountid', 'uid', 'pid', 'profile', 'profile_id', 'doc', 'document', 'order', 'order_id', 'orderid', 'invoice', 'invoice_id', 'number', 'no']

        all_interesting = set(sqli_params + xss_params + lfi_params + ssrf_params + rce_params + idor_params)

        for param in params:
            param_lower = param.lower()
            if param_lower in all_interesting:
                interesting.append(param)

        return interesting


# =============================================================================
# URL COLLECTION
# =============================================================================

class URLCollector:
    """Collect URLs using multiple passive sources."""

    TOOLS = ['gau', 'waybackurls', 'waymore', 'hakrawler']

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 300)

    def collect(self, domain: str) -> Dict:
        """Collect URLs from passive sources."""
        logger.info(f"[*] URL collection for: {domain}")
        print(f"[*] Collecting URLs for: {domain}")

        all_urls: Set[str] = set()
        urls_with_params: Set[str] = set()
        js_files: Set[str] = set()
        api_endpoints: Set[str] = set()

        results = {
            "domain": domain,
            "urls": [],
            "urls_with_params": [],
            "js_files": [],
            "api_endpoints": [],
            "by_tool": {},
            "by_extension": defaultdict(list),
            "total": 0
        }

        for tool in self.TOOLS:
            installed, _ = check_tool(tool)
            if not installed:
                continue

            print_result("[~]", f"Running {tool}...")
            tool_urls = self._run_tool(tool, domain)
            results["by_tool"][tool] = len(tool_urls)

            for url in tool_urls:
                all_urls.add(url)

                # Categorize
                url_lower = url.lower()
                if '?' in url and '=' in url:
                    urls_with_params.add(url)
                if '.js' in url_lower:
                    js_files.add(url)
                if any(x in url_lower for x in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/json/']):
                    api_endpoints.add(url)

                # By extension
                ext_match = re.search(r'\.(\w{2,5})(?:\?|$)', url_lower)
                if ext_match:
                    ext = ext_match.group(1)
                    results["by_extension"][ext].append(url)

            print_result("[+]", f"{tool}: {len(tool_urls)} URLs")

        results["urls"] = list(all_urls)
        results["urls_with_params"] = list(urls_with_params)
        results["js_files"] = list(js_files)
        results["api_endpoints"] = list(api_endpoints)
        results["total"] = len(all_urls)
        results["by_extension"] = dict(results["by_extension"])

        print_result("[✓]", f"Total unique URLs: {len(all_urls)}")
        print_result("[+]", f"URLs with params: {len(urls_with_params)}")
        print_result("[+]", f"JS files: {len(js_files)}")
        print_result("[+]", f"API endpoints: {len(api_endpoints)}")

        return results

    def _run_tool(self, tool: str, domain: str) -> List[str]:
        """Run URL collection tool."""
        urls = []

        cmd_map = {
            "gau": ["gau", "--subs", domain],
            "waybackurls": ["waybackurls", domain],
            "waymore": ["waymore", "-i", domain, "-mode", "U", "-oU", "-"],
            "hakrawler": ["hakrawler", "-url", f"https://{domain}", "-subs", "-plain"]
        }

        cmd = cmd_map.get(tool)
        if not cmd:
            return []

        result = run_tool(cmd, self.timeout)
        if result["stdout"]:
            for line in result["stdout"].strip().split('\n'):
                url = line.strip()
                if url and url.startswith(('http://', 'https://')):
                    urls.append(url)

        return urls


# =============================================================================
# WEB CRAWLER
# =============================================================================

class WebCrawler:
    """Web crawling with katana or gospider."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 300)
        self.depth = self.config.get('crawl_depth', 3)

    def crawl(self, target: str) -> Dict:
        """Crawl target to discover URLs, forms, endpoints."""
        logger.info(f"[*] Crawling: {target}")
        print(f"[*] Crawling: {target}")

        results = {
            "target": target,
            "urls": [],
            "forms": [],
            "js_files": [],
            "api_endpoints": [],
            "params": [],
            "comments": [],
            "total": 0
        }

        katana_ok, _ = check_tool("katana")
        if katana_ok:
            results = self._run_katana(target)
        else:
            gospider_ok, _ = check_tool("gospider")
            if gospider_ok:
                results = self._run_gospider(target)

        print_result("[+]", f"URLs discovered: {len(results.get('urls', []))}")
        print_result("[+]", f"JS files: {len(results.get('js_files', []))}")
        print_result("[+]", f"API endpoints: {len(results.get('api_endpoints', []))}")

        return results

    def _run_katana(self, target: str) -> Dict:
        """Run katana for advanced crawling."""
        results = {
            "target": target,
            "urls": [],
            "forms": [],
            "js_files": [],
            "api_endpoints": [],
            "params": [],
            "comments": [],
            "total": 0
        }

        cmd = [
            "katana",
            "-u", target,
            "-d", str(self.depth),
            "-silent",
            "-jc",  # JavaScript crawling
            "-kf", "all",  # Known files
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
            "-ct", "60",  # Concurrency
            "-timeout", "10",
            "-aff"  # Automatic form filling
        ]

        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            for line in result["stdout"].strip().split('\n'):
                url = line.strip()
                if not url:
                    continue

                results["urls"].append(url)
                results["total"] += 1
                url_lower = url.lower()

                if '.js' in url_lower:
                    results["js_files"].append(url)
                if any(x in url_lower for x in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/']):
                    results["api_endpoints"].append(url)
                if '?' in url and '=' in url:
                    results["params"].append(url)

        return results

    def _run_gospider(self, target: str) -> Dict:
        """Run gospider as fallback."""
        results = {
            "target": target,
            "urls": [],
            "forms": [],
            "js_files": [],
            "api_endpoints": [],
            "params": [],
            "comments": [],
            "total": 0
        }

        cmd = [
            "gospider",
            "-s", target,
            "-d", str(self.depth),
            "-c", "10",
            "-t", "5",
            "--js",
            "-q"
        ]

        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            for line in result["stdout"].strip().split('\n'):
                if ' - ' in line:
                    url = line.split(' - ')[-1].strip()
                else:
                    url = line.strip()

                if url and url.startswith(('http://', 'https://')):
                    results["urls"].append(url)
                    results["total"] += 1
                    url_lower = url.lower()

                    if '.js' in url_lower:
                        results["js_files"].append(url)
                    if '/api/' in url_lower:
                        results["api_endpoints"].append(url)
                    if '?' in url:
                        results["params"].append(url)

        return results


# =============================================================================
# ADVANCED PORT SCANNING
# =============================================================================

class PortScanner:
    """Advanced port scanning with rustscan, naabu, or nmap."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 600)

    def scan(self, target: str, scan_type: str = "quick") -> Dict:
        """
        Port scan with service detection.

        Args:
            target: Target host/IP
            scan_type: quick (top ports), full (all ports), stealth
        """
        logger.info(f"[*] Port scanning: {target}")
        print(f"[*] Port scanning: {target} ({scan_type} mode)")

        results = {
            "target": target,
            "open_ports": [],
            "services": {},
            "by_service": defaultdict(list),
            "total": 0
        }

        # Determine port range based on scan type
        if scan_type == "quick":
            ports = COMMON_PORTS
        elif scan_type == "full":
            ports = FULL_PORTS
        else:
            ports = TOP_1000_PORTS

        # Try rustscan first (fastest)
        rustscan_ok, _ = check_tool("rustscan")
        if rustscan_ok:
            print_result("[~]", "Using rustscan (fastest)...")
            results = self._run_rustscan(target, ports)
        else:
            # Try naabu
            naabu_ok, _ = check_tool("naabu")
            if naabu_ok:
                print_result("[~]", "Using naabu...")
                results = self._run_naabu(target, ports)
            else:
                # Fallback to nmap
                nmap_ok, _ = check_tool("nmap")
                if nmap_ok:
                    print_result("[~]", "Using nmap...")
                    results = self._run_nmap(target, ports)

        # Service version detection on open ports
        if results["open_ports"] and scan_type != "quick":
            print_result("[~]", "Running service version detection...")
            services = self._detect_services(target, results["open_ports"])
            results["services"] = services

            for port, service in services.items():
                results["by_service"][service].append(port)

        results["by_service"] = dict(results["by_service"])

        print_result("[+]", f"Open ports: {results['total']}")
        if results["services"]:
            print_result("[+]", f"Services detected: {len(results['services'])}")

        return results

    def _run_rustscan(self, target: str, ports: str) -> Dict:
        """Run rustscan for ultra-fast scanning."""
        results = {
            "target": target,
            "open_ports": [],
            "services": {},
            "by_service": defaultdict(list),
            "total": 0
        }

        cmd = ["rustscan", "-a", target, "-p", ports, "--ulimit", "5000", "-g"]
        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            # Parse rustscan output format: host -> [ports]
            for line in result["stdout"].strip().split('\n'):
                if '->' in line:
                    ports_str = line.split('->')[-1].strip().strip('[]')
                    for port in ports_str.split(','):
                        try:
                            p = int(port.strip())
                            results["open_ports"].append({"port": p, "protocol": "tcp"})
                        except:
                            continue

        results["total"] = len(results["open_ports"])
        return results

    def _run_naabu(self, target: str, ports: str) -> Dict:
        """Run naabu for fast port scanning."""
        results = {
            "target": target,
            "open_ports": [],
            "services": {},
            "by_service": defaultdict(list),
            "total": 0
        }

        cmd = ["naabu", "-host", target, "-p", ports, "-silent", "-c", "100"]
        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            for line in result["stdout"].strip().split('\n'):
                line = line.strip()
                if ':' in line:
                    try:
                        _, port = line.rsplit(':', 1)
                        results["open_ports"].append({"port": int(port), "protocol": "tcp"})
                    except:
                        continue

        results["total"] = len(results["open_ports"])
        return results

    def _run_nmap(self, target: str, ports: str) -> Dict:
        """Run nmap for port scanning."""
        results = {
            "target": target,
            "open_ports": [],
            "services": {},
            "by_service": defaultdict(list),
            "total": 0
        }

        cmd = ["nmap", "-sS", "-T4", "-p", ports, "--open", "-Pn", target]
        result = run_tool(cmd, self.timeout)

        if result["stdout"]:
            port_pattern = r"(\d+)/(\w+)\s+open\s+(\S+)"
            for match in re.finditer(port_pattern, result["stdout"]):
                port_info = {
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "service": match.group(3)
                }
                results["open_ports"].append(port_info)
                results["by_service"][match.group(3)].append(int(match.group(1)))

        results["total"] = len(results["open_ports"])
        return results

    def _detect_services(self, target: str, ports: List[Dict]) -> Dict:
        """Detect services on open ports using nmap."""
        services = {}

        nmap_ok, _ = check_tool("nmap")
        if not nmap_ok:
            return services

        port_list = ",".join([str(p["port"]) for p in ports[:50]])  # Limit to 50 ports
        cmd = ["nmap", "-sV", "-p", port_list, "-Pn", target]
        result = run_tool(cmd, 300)

        if result["stdout"]:
            pattern = r"(\d+)/\w+\s+open\s+(\S+)\s+(.*)"
            for match in re.finditer(pattern, result["stdout"]):
                port = int(match.group(1))
                service = f"{match.group(2)} {match.group(3)}".strip()
                services[port] = service

        return services


# =============================================================================
# DNS ENUMERATION
# =============================================================================

class DNSEnumerator:
    """Advanced DNS enumeration."""

    def __init__(self, config: Dict = None):
        self.config = config or {}

    def enumerate(self, domain: str) -> Dict:
        """Complete DNS enumeration."""
        logger.info(f"[*] DNS enumeration for: {domain}")
        print(f"[*] DNS enumeration for: {domain}")

        results = {
            "domain": domain,
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "SOA": [],
            "CNAME": [],
            "SRV": [],
            "zone_transfer": [],
            "nameservers_info": []
        }

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV']

        if dns:
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    results[rtype] = [str(rdata) for rdata in answers]
                    print_result("[+]", f"{rtype}: {len(results[rtype])} records")
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    print_result("[-]", f"Domain {domain} does not exist")
                    break
                except Exception as e:
                    pass

            # Try zone transfer on each nameserver
            if results["NS"]:
                print_result("[~]", "Attempting zone transfer...")
                for ns in results["NS"]:
                    zt_result = self._try_zone_transfer(domain, ns.rstrip('.'))
                    if zt_result:
                        results["zone_transfer"].extend(zt_result)
                        print_result("[!]", f"Zone transfer successful on {ns}!")
        else:
            # Fallback to dig/nslookup
            print_result("[~]", "Using dig/nslookup fallback...")
            results = self._dig_fallback(domain)

        return results

    def _try_zone_transfer(self, domain: str, nameserver: str) -> List[str]:
        """Attempt zone transfer."""
        records = []
        try:
            import dns.zone
            import dns.query
            z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10))
            for name, node in z.nodes.items():
                records.append(str(name))
        except Exception:
            pass
        return records

    def _dig_fallback(self, domain: str) -> Dict:
        """Fallback using dig command."""
        results = {
            "domain": domain,
            "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SOA": [], "CNAME": [], "SRV": [],
            "zone_transfer": [], "nameservers_info": []
        }

        dig_ok, _ = check_tool("dig")
        if not dig_ok:
            return results

        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            result = run_tool(["dig", "+short", rtype, domain], 30)
            if result["stdout"]:
                results[rtype] = [r.strip() for r in result["stdout"].strip().split('\n') if r.strip()]

        return results


# =============================================================================
# VULNERABILITY SCANNER
# =============================================================================

class VulnScanner:
    """Vulnerability scanning using nuclei."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 900)

    def scan(self, targets: List[str], severity: str = "all", templates: str = None) -> Dict:
        """
        Vulnerability scan with nuclei.

        Args:
            targets: List of URLs to scan
            severity: critical, high, medium, low, info, all
            templates: Specific template path or tag
        """
        logger.info(f"[*] Vulnerability scanning {len(targets)} targets")
        print(f"[*] Vulnerability scanning {len(targets)} targets...")

        results = {
            "total_targets": len(targets),
            "vulnerabilities": [],
            "by_severity": {"critical": [], "high": [], "medium": [], "low": [], "info": []},
            "by_type": defaultdict(list),
            "statistics": {}
        }

        nuclei_ok, _ = check_tool("nuclei")
        if not nuclei_ok:
            print_result("[-]", "nuclei not installed")
            return results

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            targets_file = f.name

        try:
            cmd = ["nuclei", "-l", targets_file, "-silent", "-nc", "-j", "-c", "50", "-bs", "25", "-rl", "150"]

            if severity != "all":
                cmd.extend(["-s", severity])
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
                            "host": finding.get("host", ""),
                            "description": finding.get("info", {}).get("description", ""),
                            "tags": finding.get("info", {}).get("tags", []),
                            "reference": finding.get("info", {}).get("reference", []),
                            "curl_command": finding.get("curl-command", ""),
                            "matcher_name": finding.get("matcher-name", ""),
                            "extracted": finding.get("extracted-results", [])
                        }
                        results["vulnerabilities"].append(vuln)

                        sev = vuln["severity"].lower()
                        if sev in results["by_severity"]:
                            results["by_severity"][sev].append(vuln)

                        # By type/tag
                        for tag in vuln["tags"]:
                            results["by_type"][tag].append(vuln)

                        # Print finding
                        sev_icon = {"critical": "[!!]", "high": "[!]", "medium": "[*]", "low": "[+]", "info": "[i]"}.get(sev, "[?]")
                        print_result(sev_icon, f"[{sev.upper()}] {vuln['name']} - {vuln['url']}")

                    except json.JSONDecodeError:
                        continue

        finally:
            os.unlink(targets_file)

        # Statistics
        results["statistics"] = {
            "total": len(results["vulnerabilities"]),
            "critical": len(results["by_severity"]["critical"]),
            "high": len(results["by_severity"]["high"]),
            "medium": len(results["by_severity"]["medium"]),
            "low": len(results["by_severity"]["low"]),
            "info": len(results["by_severity"]["info"])
        }
        results["by_type"] = dict(results["by_type"])

        print_result("[✓]", f"Total vulnerabilities: {results['statistics']['total']}")
        print_result("[!]", f"Critical: {results['statistics']['critical']} | High: {results['statistics']['high']} | Medium: {results['statistics']['medium']}")

        return results


# =============================================================================
# WAF DETECTION
# =============================================================================

class WAFDetector:
    """Web Application Firewall detection."""

    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
        "Akamai": ["akamai", "akamai-ghost", "ak_bmsc"],
        "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo", "incapsula"],
        "Sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
        "F5 BIG-IP": ["bigipserver", "x-cnection", "x-wa-info"],
        "Barracuda": ["barra_counter_session", "barracuda"],
        "Citrix NetScaler": ["ns_af", "citrix_ns_id", "nsc_"],
        "Fortinet FortiWeb": ["fortiwafsid", "fgd_icon_hash"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "DenyAll": ["sessioncookie", "denyall"],
        "StackPath": ["x-sp-", "stackpath"],
        "Fastly": ["fastly", "x-fastly-request-id"],
        "KeyCDN": ["keycdn", "x-edge-location"],
    }

    def __init__(self, config: Dict = None):
        self.config = config or {}

    def detect(self, target: str) -> Dict:
        """Detect WAF on target."""
        logger.info(f"[*] WAF detection for: {target}")
        print(f"[*] Detecting WAF on: {target}")

        results = {
            "target": target,
            "waf_detected": False,
            "waf_name": None,
            "confidence": "low",
            "indicators": [],
            "bypass_hints": []
        }

        # Try wafw00f first
        wafw00f_ok, _ = check_tool("wafw00f")
        if wafw00f_ok:
            print_result("[~]", "Using wafw00f...")
            wafw00f_result = self._run_wafw00f(target)
            if wafw00f_result.get("waf_detected"):
                results.update(wafw00f_result)
                print_result("[!]", f"WAF Detected: {results['waf_name']}")
                return results

        # Manual detection
        print_result("[~]", "Running manual WAF detection...")
        manual_result = self._manual_detection(target)
        results.update(manual_result)

        if results["waf_detected"]:
            print_result("[!]", f"WAF Detected: {results['waf_name']} (Confidence: {results['confidence']})")
            results["bypass_hints"] = self._get_bypass_hints(results["waf_name"])
        else:
            print_result("[+]", "No WAF detected")

        return results

    def _run_wafw00f(self, target: str) -> Dict:
        """Run wafw00f for WAF detection."""
        result = {
            "waf_detected": False,
            "waf_name": None,
            "confidence": "low",
            "indicators": []
        }

        cmd = ["wafw00f", target, "-o", "-"]
        output = run_tool(cmd, 60)

        if output["stdout"]:
            if "is behind" in output["stdout"]:
                match = re.search(r"is behind (.+?)(?:\s|$)", output["stdout"])
                if match:
                    result["waf_detected"] = True
                    result["waf_name"] = match.group(1).strip()
                    result["confidence"] = "high"
            elif "No WAF" not in output["stdout"]:
                result["waf_detected"] = True
                result["confidence"] = "medium"

        return result

    def _manual_detection(self, target: str) -> Dict:
        """Manual WAF detection via headers and behavior."""
        result = {
            "waf_detected": False,
            "waf_name": None,
            "confidence": "low",
            "indicators": []
        }

        url = make_url(target)

        try:
            # Normal request
            resp_normal = requests.get(url, timeout=10, verify=False)
            headers_normal = {k.lower(): v.lower() for k, v in resp_normal.headers.items()}
            cookies_normal = resp_normal.cookies.get_dict()

            # Check headers and cookies for WAF signatures
            for waf_name, signatures in self.WAF_SIGNATURES.items():
                for sig in signatures:
                    sig_lower = sig.lower()
                    # Check headers
                    for header, value in headers_normal.items():
                        if sig_lower in header or sig_lower in value:
                            result["waf_detected"] = True
                            result["waf_name"] = waf_name
                            result["indicators"].append(f"Header match: {header}")
                            result["confidence"] = "medium"
                            break
                    # Check cookies
                    for cookie_name in cookies_normal:
                        if sig_lower in cookie_name.lower():
                            result["waf_detected"] = True
                            result["waf_name"] = waf_name
                            result["indicators"].append(f"Cookie match: {cookie_name}")
                            result["confidence"] = "medium"
                            break
                if result["waf_detected"]:
                    break

            # Malicious request test (if no WAF detected yet)
            if not result["waf_detected"]:
                payloads = [
                    "?id=1' OR '1'='1",
                    "?q=<script>alert(1)</script>",
                    "?file=../../../etc/passwd",
                    "?cmd=;cat /etc/passwd"
                ]

                for payload in payloads:
                    try:
                        resp_malicious = requests.get(f"{url}{payload}", timeout=10, verify=False)
                        # Check for WAF block responses
                        if resp_malicious.status_code in [403, 406, 429, 503]:
                            content = resp_malicious.text.lower()
                            waf_keywords = ['blocked', 'forbidden', 'denied', 'firewall', 'security', 'waf', 'captcha', 'challenge']
                            if any(kw in content for kw in waf_keywords):
                                result["waf_detected"] = True
                                result["confidence"] = "medium"
                                result["indicators"].append(f"Blocked request: {payload}")
                                break
                    except:
                        continue

        except Exception as e:
            logger.warning(f"WAF detection error: {e}")

        return result

    def _get_bypass_hints(self, waf_name: str) -> List[str]:
        """Get WAF bypass hints."""
        hints = {
            "Cloudflare": [
                "Try finding origin IP via DNS history, Shodan, or SecurityTrails",
                "Use HTTP/2 specific techniques",
                "Try case variation: SeLeCt instead of SELECT",
                "URL encode payloads multiple times"
            ],
            "AWS WAF": [
                "Try unicode normalization bypass",
                "Use JSON-based payloads",
                "Chunk transfer encoding"
            ],
            "ModSecurity": [
                "Try comments in SQL: SEL/**/ECT",
                "Use HPP (HTTP Parameter Pollution)",
                "Try alternative encodings"
            ],
            "Akamai": [
                "Try cache poisoning techniques",
                "Use origin IP if discoverable",
                "Header injection techniques"
            ]
        }
        return hints.get(waf_name, ["Try common bypass techniques: encoding, case variation, HPP"])


# =============================================================================
# JS FILE ANALYZER
# =============================================================================

class JSAnalyzer:
    """JavaScript file analysis for secrets, endpoints, and sensitive info."""

    def __init__(self, config: Dict = None):
        self.config = config or {}

    def analyze(self, js_urls: List[str]) -> Dict:
        """Analyze JavaScript files for sensitive information."""
        logger.info(f"[*] Analyzing {len(js_urls)} JS files")
        print(f"[*] Analyzing {len(js_urls)} JavaScript files for secrets...")

        results = {
            "files_analyzed": 0,
            "secrets": [],
            "api_endpoints": [],
            "domains": [],
            "emails": [],
            "comments": [],
            "by_file": {}
        }

        for url in js_urls[:50]:  # Limit to 50 files
            try:
                file_results = self._analyze_file(url)
                if file_results:
                    results["by_file"][url] = file_results
                    results["secrets"].extend(file_results.get("secrets", []))
                    results["api_endpoints"].extend(file_results.get("endpoints", []))
                    results["domains"].extend(file_results.get("domains", []))
                    results["files_analyzed"] += 1
            except Exception as e:
                logger.warning(f"Error analyzing {url}: {e}")
                continue

        # Deduplicate
        results["secrets"] = list(set([s["value"] if isinstance(s, dict) else s for s in results["secrets"]]))
        results["api_endpoints"] = list(set(results["api_endpoints"]))
        results["domains"] = list(set(results["domains"]))

        print_result("[+]", f"Files analyzed: {results['files_analyzed']}")
        print_result("[!]", f"Secrets found: {len(results['secrets'])}")
        print_result("[+]", f"API endpoints: {len(results['api_endpoints'])}")

        if results["secrets"]:
            for secret in results["secrets"][:5]:
                print_result("[!!]", f"Secret: {secret[:50]}...")

        return results

    def _analyze_file(self, url: str) -> Dict:
        """Analyze single JS file."""
        results = {
            "secrets": [],
            "endpoints": [],
            "domains": [],
            "comments": []
        }

        try:
            resp = requests.get(url, timeout=15, verify=False)
            if resp.status_code != 200:
                return results

            content = resp.text

            # Find secrets
            for secret_type, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    results["secrets"].append({
                        "type": secret_type,
                        "value": match,
                        "file": url
                    })

            # Find API endpoints
            endpoint_patterns = [
                r'["\']/(api|v[0-9]+)/[a-zA-Z0-9/_-]+["\']',
                r'["\']https?://[^"\']+/api/[^"\']+["\']',
                r'fetch\(["\'][^"\']+["\']',
                r'axios\.(get|post|put|delete)\(["\'][^"\']+["\']',
                r'\.ajax\(\{[^}]*url:\s*["\'][^"\']+["\']'
            ]

            for pattern in endpoint_patterns:
                matches = re.findall(pattern, content, re.I)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    endpoint = match.strip('"\'')
                    if len(endpoint) > 3:
                        results["endpoints"].append(endpoint)

            # Find domains/URLs
            domain_pattern = r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}'
            domains = re.findall(domain_pattern, content)
            results["domains"] = list(set(domains))[:20]

        except Exception as e:
            logger.warning(f"JS analysis error for {url}: {e}")

        return results


# =============================================================================
# SUBDOMAIN TAKEOVER DETECTION
# =============================================================================

class TakeoverDetector:
    """Detect potential subdomain takeover vulnerabilities."""

    def __init__(self, config: Dict = None):
        self.config = config or {}

    def detect(self, subdomains: List[str]) -> Dict:
        """Check for subdomain takeover possibilities."""
        logger.info(f"[*] Checking {len(subdomains)} subdomains for takeover")
        print(f"[*] Checking {len(subdomains)} subdomains for takeover...")

        results = {
            "checked": 0,
            "vulnerable": [],
            "potential": [],
            "cname_records": {}
        }

        # Try subjack if available
        subjack_ok, _ = check_tool("subjack")
        if subjack_ok:
            print_result("[~]", "Using subjack...")
            subjack_results = self._run_subjack(subdomains)
            results["vulnerable"].extend(subjack_results)

        # Manual CNAME check
        print_result("[~]", "Checking CNAME records...")
        for subdomain in subdomains[:100]:  # Limit
            cname_result = self._check_cname(subdomain)
            results["checked"] += 1

            if cname_result.get("vulnerable"):
                results["vulnerable"].append(cname_result)
                print_result("[!!]", f"VULNERABLE: {subdomain} -> {cname_result['cname']} ({cname_result['service']})")
            elif cname_result.get("potential"):
                results["potential"].append(cname_result)

            if cname_result.get("cname"):
                results["cname_records"][subdomain] = cname_result["cname"]

        print_result("[+]", f"Subdomains checked: {results['checked']}")
        print_result("[!]", f"Vulnerable: {len(results['vulnerable'])}")
        print_result("[*]", f"Potential: {len(results['potential'])}")

        return results

    def _run_subjack(self, subdomains: List[str]) -> List[Dict]:
        """Run subjack for takeover detection."""
        vulnerable = []

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(subdomains))
            subs_file = f.name

        try:
            cmd = ["subjack", "-w", subs_file, "-t", "50", "-timeout", "30", "-o", "-", "-ssl"]
            result = run_tool(cmd, 300)

            if result["stdout"]:
                for line in result["stdout"].strip().split('\n'):
                    if "[Vulnerable]" in line or "vulnerable" in line.lower():
                        vulnerable.append({"subdomain": line, "source": "subjack"})
        finally:
            os.unlink(subs_file)

        return vulnerable

    def _check_cname(self, subdomain: str) -> Dict:
        """Check CNAME record for takeover indicators."""
        result = {
            "subdomain": subdomain,
            "cname": None,
            "vulnerable": False,
            "potential": False,
            "service": None
        }

        try:
            if dns:
                answers = dns.resolver.resolve(subdomain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target).rstrip('.')
                    result["cname"] = cname

                    # Check against known takeover signatures
                    for pattern, service in TAKEOVER_CNAMES.items():
                        if pattern in cname.lower():
                            result["potential"] = True
                            result["service"] = service

                            # Try to resolve CNAME - if it fails, likely vulnerable
                            try:
                                socket.gethostbyname(cname)
                            except socket.gaierror:
                                result["vulnerable"] = True
                            break
        except:
            pass

        return result


# =============================================================================
# CORS MISCONFIGURATION CHECKER
# =============================================================================

class CORSChecker:
    """Check for CORS misconfigurations."""

    def __init__(self, config: Dict = None):
        self.config = config or {}

    def check(self, targets: List[str]) -> Dict:
        """Check targets for CORS misconfigurations."""
        logger.info(f"[*] CORS check on {len(targets)} targets")
        print(f"[*] Checking {len(targets)} targets for CORS misconfigurations...")

        results = {
            "checked": 0,
            "vulnerable": [],
            "warnings": [],
            "by_type": defaultdict(list)
        }

        for target in targets[:50]:
            url = make_url(target)
            cors_result = self._check_cors(url)
            results["checked"] += 1

            if cors_result.get("vulnerable"):
                results["vulnerable"].append(cors_result)
                results["by_type"][cors_result["type"]].append(url)
                print_result("[!]", f"CORS Vuln ({cors_result['type']}): {url}")
            elif cors_result.get("warning"):
                results["warnings"].append(cors_result)

        results["by_type"] = dict(results["by_type"])

        print_result("[+]", f"Checked: {results['checked']}")
        print_result("[!]", f"Vulnerable: {len(results['vulnerable'])}")

        return results

    def _check_cors(self, url: str) -> Dict:
        """Check single URL for CORS misconfiguration."""
        result = {
            "url": url,
            "vulnerable": False,
            "warning": False,
            "type": None,
            "details": None
        }

        test_origins = [
            "https://evil.com",
            "null",
            f"https://{urlparse(url).netloc}.evil.com",
            urlparse(url).scheme + "://" + urlparse(url).netloc.replace(".", "x"),
        ]

        try:
            for origin in test_origins:
                headers = {"Origin": origin}
                resp = requests.get(url, headers=headers, timeout=10, verify=False)

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                # Check for vulnerable configurations
                if acao == "*":
                    result["warning"] = True
                    result["type"] = "wildcard_origin"
                    result["details"] = "ACAO: * (wildcard)"

                    if acac.lower() == "true":
                        result["vulnerable"] = True
                        result["type"] = "wildcard_with_credentials"
                        return result

                elif acao == origin:
                    result["vulnerable"] = True
                    result["type"] = "origin_reflection"
                    result["details"] = f"Origin reflected: {origin}"

                    if acac.lower() == "true":
                        result["type"] = "origin_reflection_with_credentials"
                    return result

                elif acao == "null" and origin == "null":
                    result["vulnerable"] = True
                    result["type"] = "null_origin_allowed"
                    result["details"] = "null origin allowed"
                    return result

        except Exception as e:
            logger.warning(f"CORS check error for {url}: {e}")

        return result


# =============================================================================
# SCREENSHOT CAPTURE
# =============================================================================

class ScreenshotCapture:
    """Capture screenshots of web targets."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.output_dir = config.get('screenshot_dir', '/opt/NeuroSploitv2/results/screenshots')

    def capture(self, targets: List[str]) -> Dict:
        """Capture screenshots of targets."""
        logger.info(f"[*] Capturing screenshots for {len(targets)} targets")
        print(f"[*] Capturing screenshots for {len(targets)} targets...")

        results = {
            "captured": 0,
            "failed": 0,
            "screenshots": [],
            "output_dir": self.output_dir
        }

        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

        # Try gowitness
        gowitness_ok, _ = check_tool("gowitness")
        if gowitness_ok:
            print_result("[~]", "Using gowitness...")
            results = self._run_gowitness(targets)
        else:
            # Try eyewitness
            eyewitness_ok, _ = check_tool("eyewitness")
            if eyewitness_ok:
                print_result("[~]", "Using eyewitness...")
                results = self._run_eyewitness(targets)
            else:
                print_result("[-]", "No screenshot tool available (gowitness/eyewitness)")

        print_result("[+]", f"Screenshots captured: {results['captured']}")
        print_result("[+]", f"Output directory: {results['output_dir']}")

        return results

    def _run_gowitness(self, targets: List[str]) -> Dict:
        """Run gowitness for screenshots."""
        results = {
            "captured": 0,
            "failed": 0,
            "screenshots": [],
            "output_dir": self.output_dir
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            targets_file = f.name

        try:
            cmd = [
                "gowitness", "file",
                "-f", targets_file,
                "-P", self.output_dir,
                "--timeout", "30",
                "-t", "10"
            ]
            result = run_tool(cmd, 600)

            # Count screenshots
            if os.path.exists(self.output_dir):
                screenshots = list(Path(self.output_dir).glob("*.png"))
                results["captured"] = len(screenshots)
                results["screenshots"] = [str(s) for s in screenshots[:100]]

        finally:
            os.unlink(targets_file)

        return results

    def _run_eyewitness(self, targets: List[str]) -> Dict:
        """Run eyewitness for screenshots."""
        results = {
            "captured": 0,
            "failed": 0,
            "screenshots": [],
            "output_dir": self.output_dir
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            targets_file = f.name

        try:
            cmd = [
                "eyewitness",
                "-f", targets_file,
                "-d", self.output_dir,
                "--timeout", "30",
                "--threads", "10",
                "--no-prompt"
            ]
            result = run_tool(cmd, 600)

            if os.path.exists(self.output_dir):
                screenshots = list(Path(self.output_dir).glob("**/*.png"))
                results["captured"] = len(screenshots)
                results["screenshots"] = [str(s) for s in screenshots[:100]]

        finally:
            os.unlink(targets_file)

        return results


# =============================================================================
# CLOUD BUCKET ENUMERATION
# =============================================================================

class CloudBucketEnum:
    """Enumerate cloud storage buckets (S3, GCS, Azure)."""

    def __init__(self, config: Dict = None):
        self.config = config or {}

    def enumerate(self, domain: str, keywords: List[str] = None) -> Dict:
        """Enumerate cloud buckets based on domain and keywords."""
        logger.info(f"[*] Cloud bucket enumeration for: {domain}")
        print(f"[*] Enumerating cloud buckets for: {domain}")

        results = {
            "domain": domain,
            "s3_buckets": [],
            "gcs_buckets": [],
            "azure_blobs": [],
            "accessible": [],
            "total": 0
        }

        # Generate bucket names
        base_name = domain.replace(".", "-").replace("www-", "")
        bucket_names = self._generate_bucket_names(base_name, keywords or [])

        print_result("[~]", f"Testing {len(bucket_names)} potential bucket names...")

        # Check S3
        s3_found = self._check_s3_buckets(bucket_names)
        results["s3_buckets"] = s3_found

        # Check GCS
        gcs_found = self._check_gcs_buckets(bucket_names)
        results["gcs_buckets"] = gcs_found

        # Check Azure
        azure_found = self._check_azure_blobs(bucket_names)
        results["azure_blobs"] = azure_found

        results["accessible"] = [b for b in s3_found + gcs_found + azure_found if b.get("accessible")]
        results["total"] = len(s3_found) + len(gcs_found) + len(azure_found)

        print_result("[+]", f"S3 buckets: {len(s3_found)}")
        print_result("[+]", f"GCS buckets: {len(gcs_found)}")
        print_result("[+]", f"Azure blobs: {len(azure_found)}")

        if results["accessible"]:
            print_result("[!]", f"Accessible buckets: {len(results['accessible'])}")

        return results

    def _generate_bucket_names(self, base: str, keywords: List[str]) -> List[str]:
        """Generate potential bucket names."""
        names = set()

        prefixes = ['', 'dev-', 'staging-', 'prod-', 'test-', 'backup-', 'assets-', 'static-', 'media-', 'uploads-', 'data-', 'files-', 'cdn-', 'img-', 'images-']
        suffixes = ['', '-dev', '-staging', '-prod', '-test', '-backup', '-assets', '-static', '-media', '-uploads', '-data', '-files', '-cdn', '-images', '-public', '-private', '-internal']

        for prefix in prefixes:
            for suffix in suffixes:
                name = f"{prefix}{base}{suffix}".strip('-')
                if name and 3 <= len(name) <= 63:
                    names.add(name)

        for keyword in keywords:
            names.add(f"{base}-{keyword}")
            names.add(f"{keyword}-{base}")

        return list(names)[:200]

    def _check_s3_buckets(self, names: List[str]) -> List[Dict]:
        """Check for S3 buckets."""
        found = []

        def check_bucket(name):
            try:
                url = f"https://{name}.s3.amazonaws.com"
                resp = requests.head(url, timeout=5)
                if resp.status_code in [200, 403, 301, 307]:
                    accessible = resp.status_code == 200
                    return {"name": name, "url": url, "status": resp.status_code, "accessible": accessible}
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_bucket, names)
            found = [r for r in results if r]

        return found

    def _check_gcs_buckets(self, names: List[str]) -> List[Dict]:
        """Check for Google Cloud Storage buckets."""
        found = []

        def check_bucket(name):
            try:
                url = f"https://storage.googleapis.com/{name}"
                resp = requests.head(url, timeout=5)
                if resp.status_code in [200, 403]:
                    accessible = resp.status_code == 200
                    return {"name": name, "url": url, "status": resp.status_code, "accessible": accessible}
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_bucket, names)
            found = [r for r in results if r]

        return found

    def _check_azure_blobs(self, names: List[str]) -> List[Dict]:
        """Check for Azure Blob Storage."""
        found = []

        def check_blob(name):
            try:
                url = f"https://{name}.blob.core.windows.net"
                resp = requests.head(url, timeout=5)
                if resp.status_code in [200, 403, 400]:
                    accessible = resp.status_code == 200
                    return {"name": name, "url": url, "status": resp.status_code, "accessible": accessible}
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_blob, names)
            found = [r for r in results if r]

        return found


# =============================================================================
# TECHNOLOGY FINGERPRINTER
# =============================================================================

class TechFingerprinter:
    """Advanced technology fingerprinting."""

    def __init__(self, config: Dict = None):
        self.config = config or {}

    def fingerprint(self, target: str) -> Dict:
        """Deep technology fingerprinting."""
        logger.info(f"[*] Fingerprinting: {target}")
        print(f"[*] Technology fingerprinting: {target}")

        results = {
            "target": target,
            "technologies": [],
            "cms": None,
            "web_server": None,
            "programming_language": None,
            "frameworks": [],
            "js_libraries": [],
            "cdn": None,
            "analytics": [],
            "headers": {},
            "meta_tags": {}
        }

        # Try whatweb first
        whatweb_ok, _ = check_tool("whatweb")
        if whatweb_ok:
            print_result("[~]", "Running whatweb...")
            whatweb_results = self._run_whatweb(target)
            results.update(whatweb_results)

        # Manual fingerprinting
        print_result("[~]", "Running manual fingerprinting...")
        manual_results = self._manual_fingerprint(target)

        # Merge results
        results["technologies"] = list(set(results.get("technologies", []) + manual_results.get("technologies", [])))
        results["frameworks"] = list(set(results.get("frameworks", []) + manual_results.get("frameworks", [])))
        results["js_libraries"] = list(set(results.get("js_libraries", []) + manual_results.get("js_libraries", [])))

        if not results["cms"]:
            results["cms"] = manual_results.get("cms")
        if not results["web_server"]:
            results["web_server"] = manual_results.get("web_server")

        results["headers"] = manual_results.get("headers", {})
        results["meta_tags"] = manual_results.get("meta_tags", {})

        print_result("[+]", f"Technologies: {len(results['technologies'])}")
        if results["cms"]:
            print_result("[+]", f"CMS: {results['cms']}")
        if results["web_server"]:
            print_result("[+]", f"Web Server: {results['web_server']}")

        return results

    def _run_whatweb(self, target: str) -> Dict:
        """Run whatweb for fingerprinting."""
        results = {"technologies": [], "cms": None, "web_server": None, "frameworks": [], "js_libraries": []}

        url = make_url(target)
        cmd = ["whatweb", "-a", "3", "--color=never", url]
        result = run_tool(cmd, 120)

        if result["stdout"]:
            # Parse whatweb output
            techs = re.findall(r'\[([^\]]+)\]', result["stdout"])
            results["technologies"] = list(set(techs))

            # Identify specific categories
            cms_keywords = ['WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify', 'PrestaShop', 'OpenCart', 'TYPO3', 'Ghost']
            framework_keywords = ['Laravel', 'Django', 'Rails', 'Express', 'Spring', 'ASP.NET', 'Flask', 'FastAPI', 'Next.js', 'Nuxt']

            for tech in results["technologies"]:
                for cms in cms_keywords:
                    if cms.lower() in tech.lower():
                        results["cms"] = cms
                for fw in framework_keywords:
                    if fw.lower() in tech.lower():
                        results["frameworks"].append(fw)

        return results

    def _manual_fingerprint(self, target: str) -> Dict:
        """Manual technology fingerprinting."""
        results = {
            "technologies": [],
            "cms": None,
            "web_server": None,
            "programming_language": None,
            "frameworks": [],
            "js_libraries": [],
            "headers": {},
            "meta_tags": {}
        }

        url = make_url(target)

        try:
            resp = requests.get(url, timeout=15, verify=False)

            # Headers analysis
            headers = dict(resp.headers)
            results["headers"] = headers

            if 'Server' in headers:
                results["web_server"] = headers['Server']
                results["technologies"].append(f"Server: {headers['Server']}")

            if 'X-Powered-By' in headers:
                results["programming_language"] = headers['X-Powered-By']
                results["technologies"].append(f"X-Powered-By: {headers['X-Powered-By']}")

            # Content analysis
            content = resp.text.lower()

            # CMS detection
            cms_signatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Drupal': ['drupal', 'sites/default/files'],
                'Joomla': ['joomla', '/components/com_'],
                'Magento': ['magento', 'mage/'],
                'Shopify': ['shopify', 'cdn.shopify'],
                'Ghost': ['ghost', 'ghost/'],
            }

            for cms, sigs in cms_signatures.items():
                if any(sig in content for sig in sigs):
                    results["cms"] = cms
                    results["technologies"].append(cms)
                    break

            # JS Library detection
            js_libs = {
                'jQuery': ['jquery', 'jquery.min.js'],
                'React': ['react', 'react.production.min.js', '__react'],
                'Vue.js': ['vue.js', 'vue.min.js', '__vue__'],
                'Angular': ['angular', 'ng-app', 'ng-controller'],
                'Bootstrap': ['bootstrap', 'bootstrap.min'],
                'Tailwind': ['tailwindcss', 'tailwind'],
            }

            for lib, sigs in js_libs.items():
                if any(sig in content for sig in sigs):
                    results["js_libraries"].append(lib)
                    results["technologies"].append(lib)

            # Meta tags
            meta_patterns = {
                'generator': r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
                'framework': r'<meta[^>]*name=["\']framework["\'][^>]*content=["\']([^"\']+)["\']',
            }

            for name, pattern in meta_patterns.items():
                match = re.search(pattern, content, re.I)
                if match:
                    results["meta_tags"][name] = match.group(1)
                    results["technologies"].append(match.group(1))

        except Exception as e:
            logger.warning(f"Manual fingerprint error: {e}")

        return results


# =============================================================================
# FULL RECON RUNNER - ORCHESTRATOR
# =============================================================================

class FullReconRunner:
    """
    Complete reconnaissance orchestrator.
    Runs all phases and consolidates results.
    """

    def __init__(self, config: Dict = None):
        self.config = config or {}

    def run(self, target: str, target_type: str = "domain", depth: str = "medium") -> Dict:
        """
        Run comprehensive reconnaissance.

        Args:
            target: Target domain or URL
            target_type: domain, url
            depth: quick, medium, deep

        Returns:
            Consolidated recon results
        """
        from core.context_builder import ReconContextBuilder

        print(f"\n{'='*70}")
        print("    NEUROSPLOIT v2 - ADVANCED RECONNAISSANCE ENGINE")
        print(f"{'='*70}")
        print(f"\n[*] Target: {target}")
        print(f"[*] Type: {target_type}")
        print(f"[*] Depth: {depth}\n")

        # Initialize context builder
        ctx = ReconContextBuilder()
        ctx.set_target(target, target_type)

        # Extract domain
        domain = extract_domain(target) if target_type == "url" else target

        # ================================================================
        # PHASE 1: Subdomain Enumeration
        # ================================================================
        print_phase(1, "SUBDOMAIN ENUMERATION")
        sub_enum = AdvancedSubdomainEnum(self.config)
        sub_results = sub_enum.enumerate(domain, depth)
        ctx.add_subdomains(sub_results.get("subdomains", []))
        ctx.add_tool_result("subdomain_enum", sub_results)

        subdomains = sub_results.get("subdomains", [domain])

        # ================================================================
        # PHASE 2: HTTP Probing
        # ================================================================
        print_phase(2, "HTTP PROBING & TECHNOLOGY DETECTION")
        prober = HttpProber(self.config)
        probe_results = prober.probe(subdomains)
        ctx.add_live_hosts(probe_results.get("alive", []))
        ctx.add_technologies(list(probe_results.get("technologies", {}).keys()))
        ctx.add_tool_result("http_probe", probe_results)

        alive_hosts = probe_results.get("alive", [])

        # ================================================================
        # PHASE 3: WAF Detection
        # ================================================================
        print_phase(3, "WAF DETECTION")
        waf_detector = WAFDetector(self.config)
        waf_result = waf_detector.detect(target)
        ctx.add_tool_result("waf_detection", waf_result)

        # ================================================================
        # PHASE 4: Port Scanning
        # ================================================================
        print_phase(4, "PORT SCANNING")
        port_scanner = PortScanner(self.config)
        scan_type = "quick" if depth == "quick" else ("full" if depth == "deep" else "quick")
        port_results = port_scanner.scan(domain, scan_type)
        ctx.add_open_ports(port_results.get("open_ports", []))
        ctx.add_tool_result("port_scan", port_results)

        # ================================================================
        # PHASE 5: Directory Bruteforce
        # ================================================================
        if alive_hosts and depth != "quick":
            print_phase(5, "DIRECTORY BRUTEFORCE")
            dir_bruter = DirectoryBruter(self.config)
            wordlist_size = "medium" if depth == "medium" else "big"
            dir_results = dir_bruter.bruteforce(alive_hosts[0], wordlist_size)
            ctx.add_interesting_paths([d.get("url", "") for d in dir_results.get("interesting", [])])
            ctx.add_tool_result("dir_bruteforce", dir_results)

        # ================================================================
        # PHASE 6: URL Collection
        # ================================================================
        print_phase(6, "URL COLLECTION")
        url_collector = URLCollector(self.config)
        url_results = url_collector.collect(domain)
        ctx.add_urls(url_results.get("urls", []))
        ctx.add_js_files(url_results.get("js_files", []))
        ctx.add_api_endpoints(url_results.get("api_endpoints", []))
        ctx.add_tool_result("url_collection", url_results)

        # ================================================================
        # PHASE 7: Parameter Discovery
        # ================================================================
        print_phase(7, "PARAMETER DISCOVERY")
        param_spider = ParamSpider(self.config)
        param_results = param_spider.spider(domain)
        ctx.add_tool_result("param_discovery", param_results)

        # ================================================================
        # PHASE 8: Web Crawling
        # ================================================================
        if alive_hosts:
            print_phase(8, "WEB CRAWLING")
            crawler = WebCrawler(self.config)
            crawl_results = crawler.crawl(alive_hosts[0])
            ctx.add_urls(crawl_results.get("urls", []))
            ctx.add_js_files(crawl_results.get("js_files", []))
            ctx.add_api_endpoints(crawl_results.get("api_endpoints", []))
            ctx.add_tool_result("crawling", crawl_results)

        # ================================================================
        # PHASE 9: JavaScript Analysis
        # ================================================================
        js_files = list(ctx.js_files)
        if js_files:
            print_phase(9, "JAVASCRIPT ANALYSIS")
            js_analyzer = JSAnalyzer(self.config)
            js_results = js_analyzer.analyze(js_files)
            ctx.add_secrets(js_results.get("secrets", []))
            ctx.add_api_endpoints(js_results.get("api_endpoints", []))
            ctx.add_tool_result("js_analysis", js_results)

        # ================================================================
        # PHASE 10: DNS Enumeration
        # ================================================================
        print_phase(10, "DNS ENUMERATION")
        dns_enum = DNSEnumerator(self.config)
        dns_results = dns_enum.enumerate(domain)
        dns_records = []
        for rtype, records in dns_results.items():
            if rtype != "domain" and records:
                for r in records:
                    dns_records.append(f"[{rtype}] {r}")
        ctx.add_dns_records(dns_records)
        ctx.add_tool_result("dns_enum", dns_results)

        # ================================================================
        # PHASE 11: Subdomain Takeover Check
        # ================================================================
        if depth != "quick" and subdomains:
            print_phase(11, "SUBDOMAIN TAKEOVER CHECK")
            takeover = TakeoverDetector(self.config)
            takeover_results = takeover.detect(subdomains[:100])
            ctx.add_tool_result("subdomain_takeover", takeover_results)

            if takeover_results.get("vulnerable"):
                for v in takeover_results["vulnerable"]:
                    ctx.add_vulnerabilities([{
                        "title": "Subdomain Takeover",
                        "severity": "high",
                        "affected_endpoint": v.get("subdomain", ""),
                        "description": f"Potential subdomain takeover via {v.get('service', 'unknown')}"
                    }])

        # ================================================================
        # PHASE 12: CORS Misconfiguration Check
        # ================================================================
        if alive_hosts and depth != "quick":
            print_phase(12, "CORS MISCONFIGURATION CHECK")
            cors_checker = CORSChecker(self.config)
            cors_results = cors_checker.check(alive_hosts[:30])
            ctx.add_tool_result("cors_check", cors_results)

            for vuln in cors_results.get("vulnerable", []):
                ctx.add_vulnerabilities([{
                    "title": f"CORS Misconfiguration ({vuln.get('type', '')})",
                    "severity": "medium",
                    "affected_endpoint": vuln.get("url", ""),
                    "description": vuln.get("details", "")
                }])

        # ================================================================
        # PHASE 13: Cloud Bucket Enumeration
        # ================================================================
        if depth == "deep":
            print_phase(13, "CLOUD BUCKET ENUMERATION")
            cloud_enum = CloudBucketEnum(self.config)
            cloud_results = cloud_enum.enumerate(domain)
            ctx.add_tool_result("cloud_buckets", cloud_results)

            for bucket in cloud_results.get("accessible", []):
                ctx.add_vulnerabilities([{
                    "title": "Accessible Cloud Bucket",
                    "severity": "high",
                    "affected_endpoint": bucket.get("url", ""),
                    "description": f"Publicly accessible cloud storage: {bucket.get('name', '')}"
                }])

        # ================================================================
        # PHASE 14: Technology Fingerprinting
        # ================================================================
        print_phase(14, "TECHNOLOGY FINGERPRINTING")
        fingerprinter = TechFingerprinter(self.config)
        tech_results = fingerprinter.fingerprint(target)
        ctx.add_technologies(tech_results.get("technologies", []))
        ctx.add_tool_result("tech_fingerprint", tech_results)

        # ================================================================
        # PHASE 15: Vulnerability Scanning
        # ================================================================
        print_phase(15, "VULNERABILITY SCANNING (NUCLEI)")
        vuln_scanner = VulnScanner(self.config)
        scan_targets = alive_hosts[:30] if alive_hosts else [target]
        severity = "all" if depth == "deep" else "critical,high,medium"
        vuln_results = vuln_scanner.scan(scan_targets, severity)

        for v in vuln_results.get("vulnerabilities", []):
            ctx.add_vulnerabilities([{
                "title": v.get("name", ""),
                "severity": v.get("severity", "info"),
                "affected_endpoint": v.get("url", ""),
                "description": v.get("description", ""),
                "references": v.get("reference", [])
            }])
        ctx.add_tool_result("vuln_scan", vuln_results)

        # ================================================================
        # PHASE 16: Screenshot Capture (optional)
        # ================================================================
        if depth == "deep" and alive_hosts:
            print_phase(16, "SCREENSHOT CAPTURE")
            screenshot = ScreenshotCapture(self.config)
            screenshot_results = screenshot.capture(alive_hosts[:20])
            ctx.add_tool_result("screenshots", screenshot_results)

        # ================================================================
        # CONSOLIDATION
        # ================================================================
        print(f"\n{'='*70}")
        print("[FINAL] CONSOLIDATING RESULTS")
        print(f"{'='*70}")

        # Identify interesting paths from all URLs
        all_urls = list(ctx.urls)
        ctx.add_interesting_paths(all_urls)

        # Save context
        saved = ctx.save()

        # Print summary
        print(f"\n{'='*70}")
        print("[✓] RECONNAISSANCE COMPLETE!")
        print(f"{'='*70}")
        print(f"""
    SUMMARY:
    ─────────────────────────────────────────────
    Subdomains discovered:     {len(ctx.subdomains)}
    Live hosts:                {len(ctx.live_hosts)}
    Open ports:                {len(ctx.open_ports)}
    URLs collected:            {len(ctx.urls)}
    URLs with parameters:      {len(ctx.urls_with_params)}
    JavaScript files:          {len(ctx.js_files)}
    API endpoints:             {len(ctx.api_endpoints)}
    Technologies detected:     {len(ctx.technologies)}
    Vulnerabilities found:     {len(ctx.vulnerabilities)}

    WAF Detected:              {waf_result.get('waf_name', 'None')}

    Context saved to:          {saved['json']}
    ─────────────────────────────────────────────
""")

        return {
            "context": saved["context"],
            "context_file": str(saved["json"]),
            "context_text_file": str(saved["txt"]),
            "context_text": ctx.get_llm_prompt_context(),
            "summary": {
                "subdomains": len(ctx.subdomains),
                "live_hosts": len(ctx.live_hosts),
                "open_ports": len(ctx.open_ports),
                "urls": len(ctx.urls),
                "vulnerabilities": len(ctx.vulnerabilities),
                "waf": waf_result.get('waf_name')
            }
        }


# =============================================================================
# LEGACY CLASSES (Backwards Compatibility)
# =============================================================================

class NetworkScanner(PortScanner):
    """Legacy NetworkScanner - now uses PortScanner."""
    pass


class WebRecon:
    """Legacy web reconnaissance - now uses multiple specialized classes."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.fingerprinter = TechFingerprinter(config)
        self.waf_detector = WAFDetector(config)

    def analyze(self, url: str) -> Dict:
        """Analyze web application."""
        results = {
            "url": url,
            "technologies": [],
            "headers": {},
            "security_headers": {},
            "endpoints": [],
            "forms": [],
            "vulnerabilities": [],
            "waf": None
        }

        # Technology fingerprinting
        tech_results = self.fingerprinter.fingerprint(url)
        results["technologies"] = tech_results.get("technologies", [])
        results["headers"] = tech_results.get("headers", {})

        # WAF detection
        waf_results = self.waf_detector.detect(url)
        results["waf"] = waf_results.get("waf_name")

        # Security headers check
        security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security',
                          'Content-Security-Policy', 'X-XSS-Protection', 'Referrer-Policy']

        for header in security_headers:
            if header in results["headers"]:
                results["security_headers"][header] = results["headers"][header]
            else:
                results["security_headers"][header] = "Missing"

        return results


class OSINTCollector:
    """OSINT collection."""

    def __init__(self, config: Dict = None):
        self.config = config or {}

    def collect(self, target: str) -> Dict:
        """Collect OSINT data."""
        return {
            "target": target,
            "emails": [],
            "social_media": {},
            "data_breaches": [],
            "metadata": {}
        }


class SubdomainFinder(AdvancedSubdomainEnum):
    """Legacy SubdomainFinder - now uses AdvancedSubdomainEnum."""

    def find(self, domain: str) -> List[str]:
        """Find subdomains."""
        results = self.enumerate(domain, depth="quick")
        return results.get("subdomains", [])
