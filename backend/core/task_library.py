"""
NeuroSploit v3 - Task/Prompt Library System

Manage reusable tasks and prompts for the AI Agent.
- Create, save, edit, delete tasks
- Preset tasks for common scenarios
- Custom task builder
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


class TaskCategory(Enum):
    """Task categories"""
    RECON = "recon"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    CUSTOM = "custom"
    FULL_AUTO = "full_auto"


@dataclass
class Task:
    """A reusable task/prompt"""
    id: str
    name: str
    description: str
    category: str
    prompt: str
    system_prompt: Optional[str] = None
    tools_required: List[str] = None
    estimated_tokens: int = 0
    created_at: str = ""
    updated_at: str = ""
    author: str = "user"
    tags: List[str] = None
    is_preset: bool = False

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at
        if self.tools_required is None:
            self.tools_required = []
        if self.tags is None:
            self.tags = []


class TaskLibrary:
    """Manage the task/prompt library"""

    def __init__(self, library_path: str = "prompts/task_library.json"):
        self.library_path = Path(library_path)
        self.library_path.parent.mkdir(parents=True, exist_ok=True)
        self.tasks: Dict[str, Task] = {}
        self._load_library()
        self._ensure_presets()

    def _load_library(self):
        """Load tasks from library file"""
        if self.library_path.exists():
            try:
                with open(self.library_path, 'r') as f:
                    data = json.load(f)
                    for task_data in data.get("tasks", []):
                        task = Task(**task_data)
                        self.tasks[task.id] = task
            except Exception as e:
                print(f"Error loading task library: {e}")

    def _save_library(self):
        """Save tasks to library file"""
        data = {
            "version": "1.0",
            "updated_at": datetime.utcnow().isoformat(),
            "tasks": [asdict(task) for task in self.tasks.values()]
        }
        with open(self.library_path, 'w') as f:
            json.dump(data, f, indent=2)

    def _ensure_presets(self):
        """Ensure preset tasks exist"""
        presets = self._get_preset_tasks()
        for preset in presets:
            if preset.id not in self.tasks:
                self.tasks[preset.id] = preset
        self._save_library()

    def _get_preset_tasks(self) -> List[Task]:
        """Get all preset tasks"""
        return [
            # === RECON TASKS ===
            Task(
                id="recon_full",
                name="Full Reconnaissance",
                description="Complete reconnaissance: subdomains, ports, technologies, endpoints",
                category=TaskCategory.RECON.value,
                prompt="""Perform comprehensive reconnaissance on the target:

1. **Subdomain Enumeration**: Find all subdomains
2. **Port Scanning**: Identify open ports and services
3. **Technology Detection**: Fingerprint web technologies, frameworks, servers
4. **Endpoint Discovery**: Crawl and find all accessible endpoints
5. **Parameter Discovery**: Find URL parameters and form inputs
6. **JavaScript Analysis**: Extract endpoints from JS files
7. **API Discovery**: Find API endpoints and documentation

Consolidate all findings into a structured report.""",
                system_prompt="You are a reconnaissance expert. Gather information systematically and thoroughly.",
                tools_required=["subfinder", "httpx", "nmap", "katana", "gau"],
                estimated_tokens=2000,
                tags=["recon", "discovery", "enumeration"],
                is_preset=True
            ),
            Task(
                id="recon_passive",
                name="Passive Reconnaissance",
                description="Non-intrusive reconnaissance using public data only",
                category=TaskCategory.RECON.value,
                prompt="""Perform PASSIVE reconnaissance only (no direct interaction with target):

1. **OSINT**: Search for public information
2. **DNS Records**: Enumerate DNS records
3. **Historical Data**: Check Wayback Machine, archive.org
4. **Certificate Transparency**: Find subdomains from CT logs
5. **Google Dorking**: Search for exposed files/information
6. **Social Media**: Find related accounts and information

Do NOT send any requests directly to the target.""",
                system_prompt="You are an OSINT expert. Only use passive techniques.",
                tools_required=["subfinder", "gau", "waybackurls"],
                estimated_tokens=1500,
                tags=["recon", "passive", "osint"],
                is_preset=True
            ),

            # === VULNERABILITY TASKS ===
            Task(
                id="vuln_owasp_top10",
                name="OWASP Top 10 Assessment",
                description="Test for OWASP Top 10 vulnerabilities",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Test the target for OWASP Top 10 vulnerabilities:

1. **A01 - Broken Access Control**: Test for IDOR, privilege escalation
2. **A02 - Cryptographic Failures**: Check for weak crypto, exposed secrets
3. **A03 - Injection**: Test SQL, NoSQL, OS, LDAP injection
4. **A04 - Insecure Design**: Analyze business logic flaws
5. **A05 - Security Misconfiguration**: Check headers, default configs
6. **A06 - Vulnerable Components**: Identify outdated libraries
7. **A07 - Authentication Failures**: Test auth bypass, weak passwords
8. **A08 - Data Integrity Failures**: Check for insecure deserialization
9. **A09 - Security Logging Failures**: Test for logging gaps
10. **A10 - SSRF**: Test for server-side request forgery

For each finding:
- Provide CVSS score and calculation
- Detailed description
- Proof of Concept
- Remediation recommendation""",
                system_prompt="You are a web security expert specializing in OWASP vulnerabilities.",
                tools_required=["nuclei", "sqlmap", "xsstrike"],
                estimated_tokens=5000,
                tags=["vulnerability", "owasp", "web"],
                is_preset=True
            ),
            Task(
                id="vuln_api_security",
                name="API Security Testing",
                description="Test API endpoints for security issues",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Test the API for security vulnerabilities:

1. **Authentication**: Test JWT, OAuth, API keys
2. **Authorization**: Check for BOLA, BFLA, broken object level auth
3. **Rate Limiting**: Test for missing rate limits
4. **Input Validation**: Injection attacks on API params
5. **Data Exposure**: Check for excessive data exposure
6. **Mass Assignment**: Test for mass assignment vulnerabilities
7. **Security Misconfiguration**: CORS, headers, error handling
8. **Injection**: GraphQL, SQL, NoSQL injection

For each finding provide CVSS, PoC, and remediation.""",
                system_prompt="You are an API security expert.",
                tools_required=["nuclei", "ffuf"],
                estimated_tokens=4000,
                tags=["vulnerability", "api", "rest", "graphql"],
                is_preset=True
            ),
            Task(
                id="vuln_injection",
                name="Injection Testing",
                description="Comprehensive injection vulnerability testing",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Test all input points for injection vulnerabilities:

1. **SQL Injection**: Error-based, union, blind, time-based
2. **NoSQL Injection**: MongoDB, CouchDB injections
3. **Command Injection**: OS command execution
4. **LDAP Injection**: Directory service injection
5. **XPath Injection**: XML path injection
6. **Template Injection (SSTI)**: Jinja2, Twig, Freemarker
7. **Header Injection**: Host header, CRLF injection
8. **Email Header Injection**: SMTP injection

Test ALL parameters: URL, POST body, headers, cookies.
Provide working PoC for each finding.""",
                system_prompt="You are an injection attack specialist. Test thoroughly but safely.",
                tools_required=["sqlmap", "commix"],
                estimated_tokens=4000,
                tags=["vulnerability", "injection", "sqli", "rce"],
                is_preset=True
            ),

            # === FULL AUTO TASKS ===
            Task(
                id="full_bug_bounty",
                name="Bug Bounty Hunter Mode",
                description="Full automated bug bounty workflow: recon -> analyze -> test -> report",
                category=TaskCategory.FULL_AUTO.value,
                prompt="""Execute complete bug bounty workflow:

## PHASE 1: RECONNAISSANCE
- Enumerate all subdomains and assets
- Probe for live hosts
- Discover all endpoints
- Identify technologies and frameworks

## PHASE 2: ANALYSIS
- Analyze attack surface
- Identify high-value targets
- Map authentication flows
- Document API endpoints

## PHASE 3: VULNERABILITY TESTING
- Test for critical vulnerabilities first (RCE, SQLi, Auth Bypass)
- Test for high severity (XSS, SSRF, IDOR)
- Test for medium/low (Info disclosure, misconfigs)

## PHASE 4: EXPLOITATION
- Develop PoC for confirmed vulnerabilities
- Calculate CVSS scores
- Document impact and risk

## PHASE 5: REPORTING
- Generate professional report
- Include all findings with evidence
- Provide remediation steps

Focus on impact. Prioritize critical findings.""",
                system_prompt="""You are an elite bug bounty hunter. Your goal is to find real, impactful vulnerabilities.
Be thorough but efficient. Focus on high-severity issues first.
Every finding must have: Evidence, CVSS, Impact, PoC, Remediation.""",
                tools_required=["subfinder", "httpx", "nuclei", "katana", "sqlmap"],
                estimated_tokens=10000,
                tags=["full", "bug_bounty", "automated"],
                is_preset=True
            ),
            Task(
                id="full_pentest",
                name="Full Penetration Test",
                description="Complete penetration test workflow",
                category=TaskCategory.FULL_AUTO.value,
                prompt="""Execute comprehensive penetration test:

## PHASE 1: INFORMATION GATHERING
- Passive reconnaissance
- Active reconnaissance
- Network mapping
- Service enumeration

## PHASE 2: VULNERABILITY ANALYSIS
- Automated scanning
- Manual testing
- Business logic analysis
- Configuration review

## PHASE 3: EXPLOITATION
- Exploit confirmed vulnerabilities
- Post-exploitation (if authorized)
- Privilege escalation attempts
- Lateral movement (if authorized)

## PHASE 4: DOCUMENTATION
- Document all findings
- Calculate CVSS 3.1 scores
- Create proof of concepts
- Write remediation recommendations

## PHASE 5: REPORTING
- Executive summary
- Technical findings
- Risk assessment
- Remediation roadmap

This is a full penetration test. Be thorough and professional.""",
                system_prompt="""You are a professional penetration tester conducting an authorized security assessment.
Document everything. Be thorough. Follow methodology.
All findings must include: Title, CVSS, Description, Evidence, Impact, Remediation.""",
                tools_required=["nmap", "nuclei", "sqlmap", "nikto", "ffuf"],
                estimated_tokens=15000,
                tags=["full", "pentest", "professional"],
                is_preset=True
            ),

            # === CUSTOM/FLEXIBLE TASKS ===
            Task(
                id="custom_prompt",
                name="Custom Prompt (Full AI Mode)",
                description="Execute any custom prompt - AI decides what tools to use",
                category=TaskCategory.CUSTOM.value,
                prompt="""[USER_PROMPT_HERE]

Analyze this request and:
1. Determine what information/tools are needed
2. Plan the approach
3. Execute the necessary tests
4. Analyze results
5. Report findings

You have full autonomy to use any tools and techniques needed.""",
                system_prompt="""You are an autonomous AI security agent.
Analyze the user's request and execute it completely.
You can use any tools available. Be creative and thorough.
If the task requires testing, test. If it requires analysis, analyze.
Always provide detailed results with evidence.""",
                tools_required=[],
                estimated_tokens=5000,
                tags=["custom", "flexible", "ai"],
                is_preset=True
            ),
            Task(
                id="analyze_only",
                name="Analysis Only (No Testing)",
                description="AI analysis without active testing - uses provided data",
                category=TaskCategory.CUSTOM.value,
                prompt="""Analyze the provided data/context WITHOUT performing active tests:

1. Review all provided information
2. Identify potential security issues
3. Assess risk levels
4. Provide recommendations

Do NOT send any requests to the target.
Base your analysis only on provided data.""",
                system_prompt="You are a security analyst. Analyze provided data without active testing.",
                tools_required=[],
                estimated_tokens=2000,
                tags=["analysis", "passive", "review"],
                is_preset=True
            ),

            # === REPORTING TASKS ===
            Task(
                id="report_executive",
                name="Executive Summary Report",
                description="Generate executive-level security report",
                category=TaskCategory.REPORTING.value,
                prompt="""Generate an executive summary report from the findings:

1. **Executive Summary**: High-level overview for management
2. **Risk Assessment**: Overall security posture rating
3. **Key Findings**: Top critical/high findings only
4. **Business Impact**: How vulnerabilities affect the business
5. **Recommendations**: Prioritized remediation roadmap
6. **Metrics**: Charts and statistics

Keep it concise and business-focused. Avoid technical jargon.""",
                system_prompt="You are a security consultant writing for executives.",
                tools_required=[],
                estimated_tokens=2000,
                tags=["reporting", "executive", "summary"],
                is_preset=True
            ),
            Task(
                id="report_technical",
                name="Technical Security Report",
                description="Generate detailed technical security report",
                category=TaskCategory.REPORTING.value,
                prompt="""Generate a detailed technical security report:

For each vulnerability include:
1. **Title**: Clear, descriptive title
2. **Severity**: Critical/High/Medium/Low/Info
3. **CVSS Score**: Calculate CVSS 3.1 score with vector
4. **CWE ID**: Relevant CWE classification
5. **Description**: Detailed technical explanation
6. **Affected Component**: Endpoint, parameter, function
7. **Proof of Concept**: Working PoC code/steps
8. **Evidence**: Screenshots, requests, responses
9. **Impact**: What an attacker could achieve
10. **Remediation**: Specific fix recommendations
11. **References**: OWASP, CWE, vendor docs

Be thorough and technical.""",
                system_prompt="You are a senior security engineer writing a technical report.",
                tools_required=[],
                estimated_tokens=3000,
                tags=["reporting", "technical", "detailed"],
                is_preset=True
            ),
        ]

    def create_task(self, task: Task) -> Task:
        """Create a new task"""
        if not task.id:
            task.id = f"custom_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        task.created_at = datetime.utcnow().isoformat()
        task.updated_at = task.created_at
        self.tasks[task.id] = task
        self._save_library()
        return task

    def update_task(self, task_id: str, updates: Dict) -> Optional[Task]:
        """Update an existing task"""
        if task_id not in self.tasks:
            return None
        task = self.tasks[task_id]
        for key, value in updates.items():
            if hasattr(task, key):
                setattr(task, key, value)
        task.updated_at = datetime.utcnow().isoformat()
        self._save_library()
        return task

    def delete_task(self, task_id: str) -> bool:
        """Delete a task (cannot delete presets)"""
        if task_id not in self.tasks:
            return False
        if self.tasks[task_id].is_preset:
            return False  # Cannot delete presets
        del self.tasks[task_id]
        self._save_library()
        return True

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by ID"""
        return self.tasks.get(task_id)

    def list_tasks(self, category: Optional[str] = None) -> List[Task]:
        """List all tasks, optionally filtered by category"""
        tasks = list(self.tasks.values())
        if category:
            tasks = [t for t in tasks if t.category == category]
        return sorted(tasks, key=lambda t: (not t.is_preset, t.name))

    def search_tasks(self, query: str) -> List[Task]:
        """Search tasks by name, description, or tags"""
        query = query.lower()
        results = []
        for task in self.tasks.values():
            if (query in task.name.lower() or
                query in task.description.lower() or
                any(query in tag.lower() for tag in task.tags)):
                results.append(task)
        return results

    def get_categories(self) -> List[str]:
        """Get all task categories"""
        return [c.value for c in TaskCategory]

    def export_task(self, task_id: str, filepath: str) -> bool:
        """Export a task to a file"""
        task = self.get_task(task_id)
        if not task:
            return False
        with open(filepath, 'w') as f:
            json.dump(asdict(task), f, indent=2)
        return True

    def import_task(self, filepath: str) -> Optional[Task]:
        """Import a task from a file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            task = Task(**data)
            task.is_preset = False  # Imported tasks are not presets
            return self.create_task(task)
        except Exception as e:
            print(f"Error importing task: {e}")
            return None


# Singleton instance
_library_instance = None

def get_task_library() -> TaskLibrary:
    """Get the singleton task library instance"""
    global _library_instance
    if _library_instance is None:
        _library_instance = TaskLibrary()
    return _library_instance
