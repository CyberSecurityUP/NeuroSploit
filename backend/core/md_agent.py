"""
NeuroSploit v3 - Markdown-Based Agent System

Each .md file in prompts/md_library/ acts as a self-contained agent definition
with its own methodology, system prompt, and output format.

After recon completes, the MdAgentOrchestrator dispatches each selected agent
against the target URL with full recon context.  Findings flow through the
normal validation pipeline.

Components:
  - MdAgentDefinition: parsed .md agent metadata
  - MdAgent(SpecialistAgent): executes a single .md agent via LLM
  - MdAgentLibrary: loads & indexes all .md agent definitions
  - MdAgentOrchestrator: runs selected agents post-recon
"""

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.agent_base import SpecialistAgent, AgentResult

logger = logging.getLogger(__name__)

# ─── Agent categories ───────────────────────────────────────────────
# Only 'offensive' agents are dispatched during auto-pentest by default.
# Others are available on explicit selection.

# General-purpose agents (from md_library)
AGENT_CATEGORIES: Dict[str, str] = {
    "pentest_generalist": "generalist",
    "red_team_agent": "generalist",
    "bug_bounty_hunter": "generalist",
    "owasp_expert": "generalist",
    "exploit_expert": "generalist",
    "cwe_expert": "generalist",
    "replay_attack_specialist": "generalist",
    "Pentestfull": "methodology",
}
# All vuln-type agents default to "offensive" (handled in _load_all fallback)

# Agents that should NOT run as standalone agents (methodology files, dupes)
SKIP_AGENTS = {"Pentestfull"}

# Default agents to run when none are explicitly selected:
# Run ALL vuln-type (offensive) agents — the system is designed for 100-agent dispatch
DEFAULT_OFFENSIVE_AGENTS: List[str] = []  # Empty = use all offensive agents


# ─── Data classes ────────────────────────────────────────────────────

@dataclass
class MdAgentDefinition:
    """Parsed .md agent definition."""
    name: str                       # filename stem (e.g. "owasp_expert")
    display_name: str               # human-readable (e.g. "OWASP Expert")
    category: str                   # offensive / analysis / defensive / methodology
    user_prompt_template: str       # raw user prompt with {placeholders}
    system_prompt: str              # system prompt
    file_path: str                  # absolute path to .md file
    placeholders: List[str] = field(default_factory=list)  # detected {vars}


# ─── MdAgent: executes one .md agent via LLM ────────────────────────

class MdAgent(SpecialistAgent):
    """Executes a single .md-based agent against a target URL.

    The agent fills the .md template with recon context, sends to the LLM,
    then parses structured findings from the response.
    """

    def __init__(
        self,
        definition: MdAgentDefinition,
        llm=None,
        memory=None,
        budget_allocation: float = 0.0,
        budget=None,
        validation_judge=None,
    ):
        super().__init__(
            name=f"md_{definition.name}",
            llm=llm,
            memory=memory,
            budget_allocation=budget_allocation,
            budget=budget,
        )
        self.definition = definition
        self.validation_judge = validation_judge

    async def run(self, context: Dict) -> AgentResult:
        """Execute the .md agent against the target with recon context."""
        result = AgentResult(agent_name=self.name)
        target = context.get("target", "")

        if not target:
            result.error = "No target provided"
            return result

        # Build prompts
        user_prompt = self._build_user_prompt(context)
        system_prompt = self.definition.system_prompt

        # LLM call
        try:
            response = await self._llm_call(
                f"{system_prompt}\n\n{user_prompt}",
                category="md_agent",
                estimated_tokens=2000,
            )
        except Exception as e:
            result.error = f"LLM call failed: {e}"
            return result

        if not response:
            result.error = "Empty LLM response"
            return result

        # Parse findings from structured response
        parsed = self._parse_findings(response, target)
        result.findings = parsed
        result.data = {
            "agent_name": self.definition.display_name,
            "agent_category": self.definition.category,
            "findings_count": len(parsed),
            "raw_response_length": len(response),
        }
        self.tasks_completed += 1

        return result

    # ── Prompt building ──────────────────────────────────────────────

    def _build_user_prompt(self, context: Dict) -> str:
        """Fill the .md template placeholders with recon context."""
        target = context.get("target", "")
        endpoints = context.get("endpoints", [])
        technologies = context.get("technologies", [])
        parameters = context.get("parameters", {})
        headers = context.get("headers", {})
        forms = context.get("forms", [])
        waf_info = context.get("waf_info", "")
        existing_findings = context.get("existing_findings", [])

        # Build context objects for different placeholder patterns
        scope_json = json.dumps({
            "target": target,
            "endpoints_discovered": len(endpoints),
            "technologies": technologies[:15],
            "waf": waf_info or "Not detected",
        }, indent=2)

        initial_info_json = json.dumps({
            "target_url": target,
            "endpoints": [
                ep.get("url", ep) if isinstance(ep, dict) else str(ep)
                for ep in endpoints[:30]
            ],
            "parameters": (
                {k: v for k, v in list(parameters.items())[:20]}
                if isinstance(parameters, dict) else {}
            ),
            "technologies": technologies[:15],
            "headers": {k: v for k, v in list(headers.items())[:10]},
            "forms": [
                {"action": f.get("action", ""), "method": f.get("method", "GET")}
                for f in (forms[:10] if isinstance(forms, list) else [])
            ],
        }, indent=2)

        target_environment_json = json.dumps({
            "target": target,
            "technology_stack": technologies[:10],
            "waf": waf_info or "None detected",
            "endpoints_count": len(endpoints),
            "parameters_count": (
                len(parameters) if isinstance(parameters, dict) else 0
            ),
        }, indent=2)

        existing_findings_summary = ""
        if existing_findings:
            existing_findings_summary = "\n".join(
                f"- [{getattr(f, 'severity', 'unknown').upper()}] "
                f"{getattr(f, 'title', '?')} at {getattr(f, 'affected_endpoint', '?')}"
                for f in existing_findings[:20]
            )

        recon_data_json = json.dumps({
            "target": target,
            "endpoints": [
                ep.get("url", ep) if isinstance(ep, dict) else str(ep)
                for ep in endpoints[:30]
            ],
            "technologies": technologies[:15],
            "parameters": (
                {k: v for k, v in list(parameters.items())[:20]}
                if isinstance(parameters, dict) else {}
            ),
            "existing_findings": existing_findings_summary or "None yet",
        }, indent=2)

        # Replacement map for all known placeholders
        replacements = {
            # New vuln-type agents use these two:
            "{target}": target,
            "{recon_json}": recon_data_json,
            # Legacy generalist agents use these:
            "{scope_json}": scope_json,
            "{initial_info_json}": initial_info_json,
            "{mission_objectives_json}": json.dumps({
                "primary": f"Identify and exploit vulnerabilities on {target}",
                "scope": "Web application only",
                "existing_findings": len(existing_findings),
            }, indent=2),
            "{target_environment_json}": target_environment_json,
            "{user_input}": target,
            "{target_info_json}": initial_info_json,
            "{recon_data_json}": recon_data_json,
            "{vulnerability_details_json}": json.dumps({
                "target": target,
                "known_technologies": technologies[:10],
                "endpoints": [
                    ep.get("url", ep) if isinstance(ep, dict) else str(ep)
                    for ep in endpoints[:15]
                ],
            }, indent=2),
            "{traffic_logs_json}": json.dumps({
                "target": target,
                "note": "Live traffic analysis - test authentication replay on discovered endpoints",
                "endpoints": [
                    ep.get("url", ep) if isinstance(ep, dict) else str(ep)
                    for ep in endpoints[:10]
                ],
            }, indent=2),
            "{code_vulnerability_json}": json.dumps({
                "target": target,
                "technologies": technologies[:10],
                "note": "Analyze target for CWE weaknesses based on observed behavior",
            }, indent=2),
        }

        # Apply replacements
        prompt = self.definition.user_prompt_template
        for placeholder, value in replacements.items():
            prompt = prompt.replace(placeholder, value)

        # Inject recon context appendix if any placeholders remain unfilled
        if "{" in prompt:
            prompt += f"\n\n**Recon Context:**\n{recon_data_json}"

        return prompt

    # ── Finding parsing ──────────────────────────────────────────────

    def _parse_findings(self, response: str, target: str) -> List[Dict]:
        """Parse structured findings from LLM response.

        Handles multiple output formats from different .md agents:
        - FINDING: key-value blocks (vuln-type agents)
        - Headed sections (## [SEVERITY] Vulnerability: ...)
        - OWASP format (## OWASP A0X: ...)
        - Generic bold-label patterns
        """
        findings = []

        # Pattern 1: FINDING: blocks (used by 100 vuln-type agents)
        finding_blocks = re.split(r"(?:^|\n)FINDING:", response)
        if len(finding_blocks) > 1:
            for block in finding_blocks[1:]:  # skip text before first FINDING:
                parsed = self._parse_finding_block(block, target)
                if parsed:
                    findings.append(parsed)
            if findings:
                return findings

        # Pattern 2: Section-based findings (## [SEVERITY] Vulnerability: Title)
        vuln_sections = re.findall(
            r"##\s*\[?(Critical|High|Medium|Low|Info)\]?\s*(?:Vulnerability|Attack|OWASP\s+A\d+)[\s:]*([^\n]+)",
            response, re.IGNORECASE,
        )

        if vuln_sections:
            parts = re.split(
                r"(?=##\s*\[?(?:Critical|High|Medium|Low|Info)\]?\s*(?:Vulnerability|Attack|OWASP))",
                response, flags=re.IGNORECASE,
            )
            for part in parts:
                finding = self._parse_finding_section(part, target)
                if finding:
                    findings.append(finding)
        else:
            # Pattern 3: Generic vulnerability mentions with evidence
            generic = re.findall(
                r"\*\*(?:Vulnerability|Finding|Issue)[:\s]*\*\*\s*([^\n]+)",
                response, re.IGNORECASE,
            )
            for title in generic:
                findings.append({
                    "title": title.strip(),
                    "severity": "medium",
                    "vulnerability_type": self._infer_vuln_type(title),
                    "description": "",
                    "affected_endpoint": target,
                    "evidence": "",
                    "poc_code": "",
                    "source_agent": self.definition.display_name,
                })

        return findings

    def _parse_finding_block(self, block: str, target: str) -> Optional[Dict]:
        """Parse a FINDING: key-value block from vuln-type agent response.

        Expected format:
            FINDING:
            - Title: SSRF in url parameter at /api/fetch
            - Severity: High
            - CWE: CWE-918
            - Endpoint: https://target.com/api/fetch
            - Evidence: Internal content returned
            - Impact: Internal network access
            - Remediation: Whitelist URLs
        """
        if not block.strip():
            return None

        # Extract key-value pairs (- Key: Value)
        kvs: Dict[str, str] = {}
        for match in re.finditer(r"-\s*([A-Za-z][\w\s/]*?):\s*(.+)", block):
            key = match.group(1).strip().lower().replace(" ", "_")
            kvs[key] = match.group(2).strip()

        title = kvs.get("title", "").strip()
        if not title:
            return None

        # Extract severity
        sev_raw = kvs.get("severity", "medium").lower().strip()
        severity = "medium"
        for s in ("critical", "high", "medium", "low", "info"):
            if s in sev_raw:
                severity = s
                break

        # Extract CWE
        cwe = ""
        cwe_raw = kvs.get("cwe", "")
        cwe_match = re.search(r"CWE-(\d+)", cwe_raw)
        if cwe_match:
            cwe = f"CWE-{cwe_match.group(1)}"

        # Use agent name as vuln type if it matches a known type
        vuln_type = self.definition.name
        if vuln_type.startswith("md_"):
            vuln_type = vuln_type[3:]

        # Extract endpoint
        endpoint = kvs.get("endpoint", kvs.get("url", target)).strip()

        # Extract code blocks as PoC
        poc = ""
        code_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", block, re.DOTALL)
        if code_blocks:
            poc = "\n---\n".join(b.strip() for b in code_blocks[:3])

        return {
            "title": title,
            "severity": severity,
            "vulnerability_type": vuln_type,
            "cvss_score": 0.0,
            "cwe_id": cwe,
            "description": kvs.get("impact", ""),
            "affected_endpoint": endpoint,
            "evidence": kvs.get("evidence", kvs.get("proof", "")),
            "poc_code": poc or kvs.get("poc", kvs.get("payload", "")),
            "impact": kvs.get("impact", ""),
            "remediation": kvs.get("remediation", kvs.get("fix", "")),
            "source_agent": self.definition.display_name,
            "parameter": kvs.get("parameter", kvs.get("param", "")),
        }

    def _parse_finding_section(self, section: str, target: str) -> Optional[Dict]:
        """Parse a single finding section from the response."""
        if not section.strip():
            return None

        # Extract title
        title_match = re.search(
            r"##\s*\[?(?:Critical|High|Medium|Low|Info)\]?\s*(?:Vulnerability|Attack|OWASP[^:]*)[:\s]*(.+)",
            section, re.IGNORECASE,
        )
        title = title_match.group(1).strip() if title_match else ""
        if not title:
            return None

        # Extract severity from header or table
        severity = "medium"
        sev_match = re.search(
            r"\*\*Severity\*\*\s*\|?\s*(Critical|High|Medium|Low|Info)",
            section, re.IGNORECASE,
        )
        if sev_match:
            severity = sev_match.group(1).lower()
        else:
            header_sev = re.search(
                r"##\s*\[?(Critical|High|Medium|Low|Info)\]?",
                section, re.IGNORECASE,
            )
            if header_sev:
                severity = header_sev.group(1).lower()

        # Extract CVSS
        cvss_match = re.search(r"(\d+\.\d+)", section[:500])
        cvss = float(cvss_match.group(1)) if cvss_match else 0.0

        # Extract CWE
        cwe_match = re.search(r"CWE-(\d+)", section)
        cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else ""

        # Extract endpoint
        endpoint = target
        ep_match = re.search(
            r"\*\*Endpoint\*\*\s*\|?\s*(https?://[^\s|]+)",
            section, re.IGNORECASE,
        )
        if ep_match:
            endpoint = ep_match.group(1).strip()

        # Extract description
        desc = ""
        desc_match = re.search(
            r"###?\s*Description\s*\n(.*?)(?=\n###?\s|\Z)",
            section, re.DOTALL | re.IGNORECASE,
        )
        if desc_match:
            desc = desc_match.group(1).strip()[:1000]

        # Extract PoC code blocks
        poc = ""
        code_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", section, re.DOTALL)
        if code_blocks:
            poc = "\n---\n".join(block.strip() for block in code_blocks[:3])

        # Extract evidence/proof
        evidence = ""
        ev_match = re.search(
            r"###?\s*(?:Proof|Evidence|Tool (?:Output|Evidence))\s*\n(.*?)(?=\n###?\s|\Z)",
            section, re.DOTALL | re.IGNORECASE,
        )
        if ev_match:
            evidence = ev_match.group(1).strip()[:1000]

        # Extract impact
        impact = ""
        imp_match = re.search(
            r"###?\s*Impact\s*\n(.*?)(?=\n###?\s|\Z)",
            section, re.DOTALL | re.IGNORECASE,
        )
        if imp_match:
            impact = imp_match.group(1).strip()[:500]

        # Extract remediation
        remediation = ""
        rem_match = re.search(
            r"###?\s*(?:Remediation|Mitigations?|Fix)\s*\n(.*?)(?=\n###?\s|\Z)",
            section, re.DOTALL | re.IGNORECASE,
        )
        if rem_match:
            remediation = rem_match.group(1).strip()[:500]

        return {
            "title": title,
            "severity": severity,
            "vulnerability_type": self._infer_vuln_type(title),
            "cvss_score": cvss,
            "cwe_id": cwe,
            "description": desc,
            "affected_endpoint": endpoint,
            "evidence": evidence,
            "poc_code": poc,
            "impact": impact,
            "remediation": remediation,
            "source_agent": self.definition.display_name,
        }

    @staticmethod
    def _infer_vuln_type(title: str) -> str:
        """Infer vulnerability type from finding title."""
        title_lower = title.lower()
        type_map = {
            "sql injection": "sqli_error",
            "sqli": "sqli_error",
            "xss": "xss_reflected",
            "cross-site scripting": "xss_reflected",
            "stored xss": "xss_stored",
            "dom xss": "xss_dom",
            "command injection": "command_injection",
            "rce": "command_injection",
            "remote code": "command_injection",
            "ssrf": "ssrf",
            "server-side request": "ssrf",
            "csrf": "csrf",
            "cross-site request": "csrf",
            "lfi": "lfi",
            "local file": "lfi",
            "path traversal": "path_traversal",
            "directory traversal": "path_traversal",
            "file upload": "file_upload",
            "xxe": "xxe",
            "xml external": "xxe",
            "ssti": "ssti",
            "template injection": "ssti",
            "open redirect": "open_redirect",
            "redirect": "open_redirect",
            "idor": "idor",
            "insecure direct": "idor",
            "broken access": "bola",
            "access control": "bola",
            "authentication": "auth_bypass",
            "auth bypass": "auth_bypass",
            "brute force": "brute_force",
            "jwt": "jwt_manipulation",
            "session": "session_fixation",
            "clickjacking": "clickjacking",
            "cors": "cors_misconfig",
            "crlf": "crlf_injection",
            "header injection": "header_injection",
            "security header": "security_headers",
            "ssl": "ssl_issues",
            "tls": "ssl_issues",
            "information disclosure": "information_disclosure",
            "sensitive data": "sensitive_data_exposure",
            "directory listing": "directory_listing",
            "debug": "debug_mode",
            "deserialization": "insecure_deserialization",
            "nosql": "nosql_injection",
            "ldap": "ldap_injection",
            "graphql": "graphql_injection",
            "race condition": "race_condition",
            "business logic": "business_logic",
            "rate limit": "rate_limit_bypass",
            "subdomain takeover": "subdomain_takeover",
            "host header": "host_header_injection",
            "prototype pollution": "prototype_pollution",
            "websocket": "websocket_hijacking",
        }
        for keyword, vtype in type_map.items():
            if keyword in title_lower:
                return vtype
        return "unknown"


# ─── MdAgentLibrary: loads all .md agents ────────────────────────────

class MdAgentLibrary:
    """Loads all .md files from prompts/agents/ and indexes them
    as executable agent definitions (100+ vuln-type agents)."""

    def __init__(self, md_dir: str = "prompts/agents"):
        self.md_dir = Path(md_dir)
        self.agents: Dict[str, MdAgentDefinition] = {}
        self._load_all()

    def _load_all(self):
        """Load all .md files as agent definitions."""
        if not self.md_dir.is_dir():
            logger.warning(f"MD agent directory not found: {self.md_dir}")
            return

        for md_file in sorted(self.md_dir.glob("*.md")):
            name = md_file.stem
            if name in SKIP_AGENTS:
                continue

            try:
                content = md_file.read_text(encoding="utf-8")

                # Parse structured format
                user_match = re.search(
                    r"## User Prompt\n(.*?)(?=\n## System Prompt|\Z)",
                    content, re.DOTALL,
                )
                system_match = re.search(
                    r"## System Prompt\n(.*?)(?=\n## User Prompt|\Z)",
                    content, re.DOTALL,
                )

                user_prompt = user_match.group(1).strip() if user_match else ""
                system_prompt = system_match.group(1).strip() if system_match else ""

                if not user_prompt and not system_prompt:
                    system_prompt = content.strip()

                # Detect placeholders
                placeholders = re.findall(r"\{(\w+)\}", user_prompt)

                # Build display name
                display_name = name.replace("_", " ").title()
                title_match = re.search(r"^#\s+(.+)", content)
                if title_match:
                    raw_title = title_match.group(1).strip()
                    # Remove suffixes: "Prompt", "Specialist Agent", "Agent"
                    display_name = re.sub(
                        r"\s*(?:Specialist Agent|Agent|Prompt)\s*$",
                        "", raw_title,
                    ).strip()

                category = AGENT_CATEGORIES.get(name, "offensive")

                self.agents[name] = MdAgentDefinition(
                    name=name,
                    display_name=display_name,
                    category=category,
                    user_prompt_template=user_prompt,
                    system_prompt=system_prompt,
                    file_path=str(md_file.resolve()),
                    placeholders=placeholders,
                )
                logger.debug(f"Loaded MD agent: {name} ({category})")

            except Exception as e:
                logger.warning(f"Failed to load MD agent {md_file.name}: {e}")

        logger.info(
            f"MdAgentLibrary: loaded {len(self.agents)} agents from {self.md_dir}"
        )

    def get_agent(self, name: str) -> Optional[MdAgentDefinition]:
        return self.agents.get(name)

    def get_offensive_agents(self) -> List[MdAgentDefinition]:
        return [a for a in self.agents.values() if a.category == "offensive"]

    def get_by_category(self, category: str) -> List[MdAgentDefinition]:
        return [a for a in self.agents.values() if a.category == category]

    def list_agents(self) -> List[Dict]:
        """Return agent metadata list for API/frontend."""
        return [
            {
                "name": a.name,
                "display_name": a.display_name,
                "category": a.category,
                "placeholders": a.placeholders,
            }
            for a in self.agents.values()
        ]


# ─── MdAgentOrchestrator: runs agents post-recon ────────────────────

class MdAgentOrchestrator:
    """Coordinates execution of .md-based agents after recon.

    Flow:
      1. Select agents (explicit list or defaults)
      2. Build shared context from recon data
      3. Run agents in parallel (bounded concurrency)
      4. Collect and merge findings
    """

    MAX_CONCURRENT = 3

    def __init__(
        self,
        llm=None,
        memory=None,
        budget=None,
        validation_judge=None,
        log_callback: Optional[Callable] = None,
        progress_callback: Optional[Callable] = None,
    ):
        self.llm = llm
        self.memory = memory
        self.budget = budget
        self.validation_judge = validation_judge
        self.log = log_callback
        self.progress_callback = progress_callback
        self.library = MdAgentLibrary()
        self._cancel_event = asyncio.Event()

    async def _log(self, level: str, message: str):
        if self.log:
            await self.log(level, message)

    async def run(
        self,
        target: str,
        recon_data: Any = None,
        existing_findings: List[Any] = None,
        selected_agents: Optional[List[str]] = None,
        headers: Optional[Dict] = None,
        waf_info: str = "",
    ) -> Dict:
        """Execute selected .md agents against target.

        Args:
            target: Target URL.
            recon_data: ReconData object from recon phase.
            existing_findings: Findings discovered so far.
            selected_agents: List of agent names to run. None = defaults.
            headers: Auth/custom headers.
            waf_info: WAF detection info.

        Returns:
            Dict with findings, agent_results, statistics.
        """
        start_time = time.time()
        self._cancel_event.clear()

        # Resolve agent selection
        agents_to_run = self._resolve_agents(selected_agents)
        if not agents_to_run:
            await self._log("warning", "[MD-AGENTS] No agents available to run")
            return {"findings": [], "agent_results": {}, "duration": 0}

        agent_names = [a.display_name for a in agents_to_run]
        await self._log("info", f"[MD-AGENTS] Dispatching {len(agents_to_run)} agents: "
                                 f"{', '.join(agent_names)}")

        # Build shared context
        context = self._build_context(
            target, recon_data, existing_findings, headers, waf_info,
        )

        # Budget per agent
        n_agents = len(agents_to_run)
        per_agent_budget = 1.0 / max(n_agents, 1)

        # Create MdAgent instances
        md_agents: List[MdAgent] = []
        for defn in agents_to_run:
            agent = MdAgent(
                definition=defn,
                llm=self.llm,
                memory=self.memory,
                budget_allocation=per_agent_budget,
                budget=self.budget,
                validation_judge=self.validation_judge,
            )
            md_agents.append(agent)

        # Run agents with bounded concurrency
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)
        all_results: Dict[str, AgentResult] = {}

        async def _run_one(agent: MdAgent) -> AgentResult:
            async with semaphore:
                if self._cancel_event.is_set():
                    return AgentResult(
                        agent_name=agent.name, status="cancelled",
                    )
                await self._log("info",
                    f"  [{agent.definition.display_name}] Starting...")
                result = await agent.execute(context)
                await self._log("info",
                    f"  [{agent.definition.display_name}] Done: "
                    f"{len(result.findings)} findings, "
                    f"{result.duration:.1f}s")
                return result

        tasks = [_run_one(a) for a in md_agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results
        all_findings = []
        for agent, res in zip(md_agents, results):
            if isinstance(res, Exception):
                logger.error(f"MD agent {agent.name} error: {res}")
                all_results[agent.name] = AgentResult(
                    agent_name=agent.name, status="failed", error=str(res),
                )
            else:
                all_results[agent.name] = res
                all_findings.extend(res.findings)

        elapsed = time.time() - start_time
        total_tokens = sum(
            r.tokens_used for r in all_results.values()
            if isinstance(r, AgentResult)
        )

        await self._log("info",
            f"[MD-AGENTS] Complete: {len(all_findings)} findings from "
            f"{len(agents_to_run)} agents in {elapsed:.1f}s")

        return {
            "findings": all_findings,
            "agent_results": {
                name: {
                    "status": r.status,
                    "findings_count": len(r.findings),
                    "tokens_used": r.tokens_used,
                    "duration": round(r.duration, 1),
                    "error": r.error,
                }
                for name, r in all_results.items()
                if isinstance(r, AgentResult)
            },
            "total_findings": len(all_findings),
            "total_tokens": total_tokens,
            "agents_run": len(agents_to_run),
            "duration": round(elapsed, 1),
        }

    def _resolve_agents(
        self, selected: Optional[List[str]],
    ) -> List[MdAgentDefinition]:
        """Resolve agent selection to definitions.

        When no agents are explicitly selected, dispatches ALL
        offensive (vuln-type) agents — the XBOW-style architecture
        runs one specialist per vulnerability type.
        """
        if selected:
            resolved = []
            for name in selected:
                defn = self.library.get_agent(name)
                if defn:
                    resolved.append(defn)
                else:
                    logger.warning(f"MD agent not found: {name}")
            return resolved

        # Default: all offensive (vuln-type) agents
        return self.library.get_offensive_agents()

    def _build_context(
        self,
        target: str,
        recon_data: Any,
        existing_findings: List[Any],
        headers: Optional[Dict],
        waf_info: str,
    ) -> Dict:
        """Build shared context dict from recon data."""
        ctx: Dict[str, Any] = {"target": target}

        if recon_data:
            ctx["endpoints"] = getattr(recon_data, "endpoints", [])
            ctx["technologies"] = getattr(recon_data, "technologies", [])
            ctx["parameters"] = getattr(recon_data, "parameters", {})
            ctx["forms"] = getattr(recon_data, "forms", [])
            ctx["headers"] = getattr(recon_data, "response_headers", {})
        else:
            ctx["endpoints"] = []
            ctx["technologies"] = []
            ctx["parameters"] = {}
            ctx["forms"] = []
            ctx["headers"] = {}

        if headers:
            ctx["headers"].update(headers)

        ctx["existing_findings"] = existing_findings or []
        ctx["waf_info"] = waf_info

        return ctx

    def cancel(self):
        self._cancel_event.set()

    def list_available_agents(self) -> List[Dict]:
        """Return agent list for API/frontend."""
        return self.library.list_agents()
