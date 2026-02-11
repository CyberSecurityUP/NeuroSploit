"""
NeuroSploit v3 - Exploit Chain Engine

Finding correlation, derived target generation, and attack graph
construction for autonomous pentesting. When a vulnerability is
confirmed, this engine generates follow-up targets based on 10
chain rules.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


@dataclass
class ChainableTarget:
    """A derived attack target generated from a confirmed finding."""
    url: str
    param: str
    vuln_type: str
    context: Dict[str, Any] = field(default_factory=dict)
    chain_depth: int = 1
    parent_finding_id: str = ""
    priority: int = 2          # 1=critical, 2=high, 3=medium
    method: str = "GET"
    injection_point: str = "parameter"
    payload_hint: Optional[str] = None
    description: str = ""


@dataclass
class ChainRule:
    """Defines how a finding triggers derived targets."""
    trigger_type: str           # Vuln type that triggers this rule
    derived_types: List[str]    # Types to test on derived targets
    extraction_fn: str          # Method name for target extraction
    priority: int = 2
    max_depth: int = 3
    description: str = ""


# 10 chain rules
CHAIN_RULES: List[ChainRule] = [
    ChainRule(
        trigger_type="ssrf",
        derived_types=["lfi", "xxe", "command_injection", "ssrf"],
        extraction_fn="_extract_internal_urls",
        priority=1,
        description="SSRF \u2192 internal service attacks",
    ),
    ChainRule(
        trigger_type="sqli_error",
        derived_types=["sqli_union", "sqli_blind", "sqli_time"],
        extraction_fn="_extract_db_context",
        priority=1,
        description="SQLi error \u2192 advanced SQLi techniques",
    ),
    ChainRule(
        trigger_type="information_disclosure",
        derived_types=["auth_bypass", "default_credentials"],
        extraction_fn="_extract_credentials",
        priority=1,
        description="Info disclosure \u2192 credential-based attacks",
    ),
    ChainRule(
        trigger_type="idor",
        derived_types=["idor", "bola", "bfla"],
        extraction_fn="_extract_idor_patterns",
        priority=2,
        description="IDOR on one resource \u2192 same pattern on sibling resources",
    ),
    ChainRule(
        trigger_type="lfi",
        derived_types=["sqli", "auth_bypass", "information_disclosure"],
        extraction_fn="_extract_config_paths",
        priority=1,
        description="LFI \u2192 config file extraction \u2192 credential discovery",
    ),
    ChainRule(
        trigger_type="xss_reflected",
        derived_types=["xss_stored", "cors_misconfiguration"],
        extraction_fn="_extract_xss_chain",
        priority=2,
        description="Reflected XSS \u2192 stored XSS / CORS chain for session theft",
    ),
    ChainRule(
        trigger_type="open_redirect",
        derived_types=["ssrf", "oauth_misconfiguration"],
        extraction_fn="_extract_redirect_chain",
        priority=1,
        description="Open redirect \u2192 OAuth token theft chain",
    ),
    ChainRule(
        trigger_type="default_credentials",
        derived_types=["auth_bypass", "privilege_escalation", "idor"],
        extraction_fn="_extract_auth_chain",
        priority=1,
        description="Default creds \u2192 authenticated attacks",
    ),
    ChainRule(
        trigger_type="exposed_admin_panel",
        derived_types=["default_credentials", "auth_bypass", "brute_force"],
        extraction_fn="_extract_admin_chain",
        priority=1,
        description="Exposed admin \u2192 credential attack on admin panel",
    ),
    ChainRule(
        trigger_type="subdomain_takeover",
        derived_types=["xss_reflected", "xss_stored", "ssrf"],
        extraction_fn="_extract_subdomain_targets",
        priority=3,
        description="Subdomain discovery \u2192 new attack surface",
    ),
]


class ChainEngine:
    """Exploit chain engine for finding correlation and derived target generation.

    When a vulnerability is confirmed, this engine:
    1. Checks chain rules for matching trigger types
    2. Extracts derived targets using rule-specific extraction functions
    3. Generates ChainableTarget objects for the agent to test
    4. Tracks chain depth to prevent infinite recursion
    5. Builds an attack graph of finding \u2192 finding relationships

    Usage:
        engine = ChainEngine()
        derived = await engine.on_finding(finding, recon, memory)
        for target in derived:
            # Test target through normal vuln testing pipeline
            pass
    """

    MAX_CHAIN_DEPTH = 3
    MAX_DERIVED_PER_FINDING = 20

    def __init__(self, llm=None):
        self.llm = llm
        self._chain_graph: Dict[str, List[str]] = {}  # finding_id \u2192 [derived_finding_ids]
        self._total_chains = 0
        self._chain_findings: List[str] = []  # finding IDs that came from chaining

    async def on_finding(
        self,
        finding: Any,
        recon: Any = None,
        memory: Any = None,
    ) -> List[ChainableTarget]:
        """Process a confirmed finding and generate derived targets.

        Args:
            finding: The confirmed Finding object
            recon: ReconData with target info
            memory: AgentMemory for dedup

        Returns:
            List of ChainableTarget objects to test
        """
        vuln_type = getattr(finding, "vulnerability_type", "")
        finding_id = getattr(finding, "id", str(id(finding)))
        chain_depth = getattr(finding, "_chain_depth", 0)

        # Prevent infinite chaining
        if chain_depth >= self.MAX_CHAIN_DEPTH:
            return []

        derived_targets = []

        for rule in CHAIN_RULES:
            # Check trigger match (exact or prefix)
            if not self._matches_trigger(vuln_type, rule.trigger_type):
                continue

            # Extract targets using rule's extraction function
            extractor = getattr(self, rule.extraction_fn, None)
            if not extractor:
                continue

            try:
                targets = extractor(finding, recon)
                for target in targets[:self.MAX_DERIVED_PER_FINDING]:
                    target.chain_depth = chain_depth + 1
                    target.parent_finding_id = finding_id
                    target.priority = rule.priority
                    derived_targets.append(target)
            except Exception as e:
                logger.debug(f"Chain extraction failed for {rule.extraction_fn}: {e}")

        # Track in graph
        if derived_targets:
            self._chain_graph[finding_id] = [
                f"{t.vuln_type}:{t.url}" for t in derived_targets
            ]
            self._total_chains += len(derived_targets)
            logger.debug(f"Chain engine: {vuln_type} \u2192 {len(derived_targets)} derived targets")

        return derived_targets[:self.MAX_DERIVED_PER_FINDING]

    def _matches_trigger(self, vuln_type: str, trigger: str) -> bool:
        """Check if vuln_type matches a trigger rule."""
        if vuln_type == trigger:
            return True
        # Allow prefix matching: sqli_error matches sqli_error
        if vuln_type.startswith(trigger + "_") or trigger.startswith(vuln_type + "_"):
            return True
        # Special: any sqli variant triggers sqli_error rule
        if trigger == "sqli_error" and vuln_type.startswith("sqli"):
            return True
        return False

    # \u2500\u2500\u2500 Extraction Functions \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    def _extract_internal_urls(self, finding, recon) -> List[ChainableTarget]:
        """From SSRF: extract internal URLs for further attack."""
        targets = []
        evidence = getattr(finding, "evidence", "")
        url = getattr(finding, "url", "")

        # Find internal IPs in response
        internal_patterns = [
            r'(?:https?://)?(?:127\.\d+\.\d+\.\d+)(?::\d+)?(?:/[^\s"<>]*)?',
            r'(?:https?://)?(?:10\.\d+\.\d+\.\d+)(?::\d+)?(?:/[^\s"<>]*)?',
            r'(?:https?://)?(?:192\.168\.\d+\.\d+)(?::\d+)?(?:/[^\s"<>]*)?',
            r'(?:https?://)?(?:172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?(?:/[^\s"<>]*)?',
            r'(?:https?://)?localhost(?::\d+)?(?:/[^\s"<>]*)?',
        ]

        found_urls = set()
        for pattern in internal_patterns:
            for match in re.finditer(pattern, evidence):
                internal_url = match.group(0)
                if not internal_url.startswith("http"):
                    internal_url = f"http://{internal_url}"
                found_urls.add(internal_url)

        # Common internal service ports
        if not found_urls:
            # Generate targets based on known internal ports
            parsed = urlparse(url)
            base_ips = ["127.0.0.1", "localhost"]
            ports = [80, 8080, 8443, 3000, 5000, 8000, 9200, 6379, 27017]
            for ip in base_ips:
                for port in ports[:4]:  # Limit
                    found_urls.add(f"http://{ip}:{port}/")

        for internal_url in list(found_urls)[:10]:
            for vuln_type in ["lfi", "command_injection", "ssrf"]:
                targets.append(ChainableTarget(
                    url=internal_url,
                    param="url",
                    vuln_type=vuln_type,
                    context={"source": "ssrf_chain", "internal": True},
                    description=f"SSRF chain: {vuln_type} on internal {internal_url}",
                ))

        return targets

    def _extract_db_context(self, finding, recon) -> List[ChainableTarget]:
        """From SQLi error: extract DB type and generate advanced payloads."""
        targets = []
        evidence = getattr(finding, "evidence", "")
        url = getattr(finding, "url", "")
        param = getattr(finding, "parameter", "")

        # Detect database type from error
        db_type = "unknown"
        db_indicators = {
            "mysql": ["mysql", "mariadb", "you have an error in your sql syntax"],
            "postgresql": ["postgresql", "pg_", "unterminated quoted string"],
            "mssql": ["microsoft sql", "mssql", "unclosed quotation mark", "sqlserver"],
            "oracle": ["ora-", "oracle", "quoted string not properly terminated"],
            "sqlite": ["sqlite", "sqlite3"],
        }

        evidence_lower = evidence.lower()
        for db, indicators in db_indicators.items():
            if any(i in evidence_lower for i in indicators):
                db_type = db
                break

        # Generate type-specific advanced SQLi targets
        advanced_types = ["sqli_union", "sqli_blind", "sqli_time"]
        for vuln_type in advanced_types:
            targets.append(ChainableTarget(
                url=url,
                param=param,
                vuln_type=vuln_type,
                context={"db_type": db_type, "source": "sqli_chain"},
                description=f"SQLi chain: {vuln_type} ({db_type}) on {param}",
                payload_hint=f"db_type={db_type}",
            ))

        return targets

    def _extract_credentials(self, finding, recon) -> List[ChainableTarget]:
        """From info disclosure: extract credentials for auth attacks."""
        targets = []
        evidence = getattr(finding, "evidence", "")
        url = getattr(finding, "url", "")

        # Extract potential credentials
        cred_patterns = [
            r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'<>&]+)',
            r'(?:api_key|apikey|api-key)\s*[=:]\s*["\']?([^\s"\'<>&]+)',
            r'(?:token|secret|auth)\s*[=:]\s*["\']?([^\s"\'<>&]+)',
            r'(?:username|user|login)\s*[=:]\s*["\']?([^\s"\'<>&]+)',
        ]

        found_creds = {}
        for pattern in cred_patterns:
            matches = re.findall(pattern, evidence, re.I)
            for match in matches:
                if len(match) > 3:  # Skip trivial matches
                    found_creds[pattern.split("|")[0].strip("(?")] = match

        # Generate auth attack targets
        if recon:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            admin_paths = ["/admin", "/api/admin", "/dashboard", "/management"]

            for path in admin_paths:
                targets.append(ChainableTarget(
                    url=f"{base}{path}",
                    param="",
                    vuln_type="auth_bypass",
                    context={"discovered_creds": found_creds, "source": "info_disclosure_chain"},
                    description=f"Credential chain: auth bypass at {path}",
                ))

        return targets

    def _extract_idor_patterns(self, finding, recon) -> List[ChainableTarget]:
        """From IDOR: apply same pattern to sibling resources."""
        targets = []
        url = getattr(finding, "url", "")
        param = getattr(finding, "parameter", "")

        parsed = urlparse(url)
        path = parsed.path

        # Pattern: /users/{id} \u2192 /orders/{id}, /profiles/{id}
        sibling_resources = [
            "users", "orders", "profiles", "accounts", "invoices",
            "documents", "messages", "transactions", "settings",
            "notifications", "payments", "subscriptions",
        ]

        # Extract the resource pattern
        path_parts = [p for p in path.split("/") if p]
        if len(path_parts) >= 2:
            # Replace the resource name with siblings
            original_resource = path_parts[-2] if path_parts[-1].isdigit() else path_parts[-1]
            resource_id = path_parts[-1] if path_parts[-1].isdigit() else "1"

            base = f"{parsed.scheme}://{parsed.netloc}"
            for sibling in sibling_resources:
                if sibling != original_resource:
                    new_path = path.replace(original_resource, sibling)
                    targets.append(ChainableTarget(
                        url=f"{base}{new_path}",
                        param=param or "id",
                        vuln_type="idor",
                        context={"source": "idor_pattern_chain", "original_resource": original_resource},
                        description=f"IDOR chain: {sibling} (from {original_resource})",
                        method=getattr(finding, "method", "GET"),
                    ))

        return targets[:10]

    def _extract_config_paths(self, finding, recon) -> List[ChainableTarget]:
        """From LFI: generate config file read targets."""
        targets = []
        url = getattr(finding, "url", "")
        param = getattr(finding, "parameter", "")

        # Config files that may contain credentials
        config_files = [
            "/etc/passwd",
            "/etc/shadow",
            "../../../../.env",
            "../../../../config/database.yml",
            "../../../../wp-config.php",
            "../../../../config.php",
            "../../../../.git/config",
            "../../../../config/secrets.yml",
            "/proc/self/environ",
            "../../../../application.properties",
            "../../../../appsettings.json",
            "../../../../web.config",
        ]

        for config_path in config_files:
            targets.append(ChainableTarget(
                url=url,
                param=param,
                vuln_type="lfi",
                context={"config_file": config_path, "source": "lfi_chain"},
                description=f"LFI chain: read {config_path}",
                payload_hint=config_path,
            ))

        return targets

    def _extract_xss_chain(self, finding, recon) -> List[ChainableTarget]:
        """From reflected XSS: look for stored XSS and CORS chain opportunities."""
        targets = []
        url = getattr(finding, "url", "")
        param = getattr(finding, "parameter", "")

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Look for form submission endpoints (potential stored XSS)
        if recon and hasattr(recon, "forms"):
            for form in getattr(recon, "forms", [])[:5]:
                form_url = form.get("action", "") if isinstance(form, dict) else getattr(form, "action", "")
                if form_url:
                    targets.append(ChainableTarget(
                        url=form_url,
                        param=param,
                        vuln_type="xss_stored",
                        context={"source": "xss_chain"},
                        description=f"XSS chain: stored XSS via form at {form_url}",
                        method="POST",
                    ))

        # Check for CORS misconfiguration chain
        targets.append(ChainableTarget(
            url=base + "/api/",
            param="",
            vuln_type="cors_misconfiguration",
            context={"source": "xss_cors_chain"},
            description="XSS+CORS chain: check CORS for session theft scenario",
        ))

        return targets

    def _extract_redirect_chain(self, finding, recon) -> List[ChainableTarget]:
        """From open redirect: chain to OAuth token theft."""
        targets = []
        url = getattr(finding, "url", "")
        param = getattr(finding, "parameter", "")

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # OAuth endpoints to test
        oauth_paths = [
            "/oauth/authorize", "/auth/authorize", "/oauth2/authorize",
            "/connect/authorize", "/.well-known/openid-configuration",
            "/api/oauth/callback",
        ]

        for path in oauth_paths:
            targets.append(ChainableTarget(
                url=f"{base}{path}",
                param="redirect_uri",
                vuln_type="open_redirect",
                context={"source": "redirect_oauth_chain"},
                description=f"Redirect chain: OAuth token theft via {path}",
            ))

        # SSRF via redirect
        targets.append(ChainableTarget(
            url=url,
            param=param,
            vuln_type="ssrf",
            context={"source": "redirect_ssrf_chain"},
            description="Redirect \u2192 SSRF chain",
        ))

        return targets

    def _extract_auth_chain(self, finding, recon) -> List[ChainableTarget]:
        """From default credentials: test all endpoints as authenticated user."""
        targets = []
        url = getattr(finding, "url", "")

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Privileged paths to test with obtained session
        privileged_paths = [
            "/admin", "/admin/users", "/admin/settings",
            "/api/admin", "/api/users", "/api/v1/admin",
            "/management", "/internal", "/debug",
        ]

        for path in privileged_paths:
            targets.append(ChainableTarget(
                url=f"{base}{path}",
                param="",
                vuln_type="privilege_escalation",
                context={"source": "auth_chain", "authenticated": True},
                description=f"Auth chain: privilege escalation at {path}",
            ))

        return targets

    def _extract_admin_chain(self, finding, recon) -> List[ChainableTarget]:
        """From exposed admin panel: try default credentials and auth bypass."""
        targets = []
        url = getattr(finding, "url", "")

        targets.append(ChainableTarget(
            url=url,
            param="",
            vuln_type="default_credentials",
            context={"source": "admin_chain"},
            description=f"Admin chain: default credentials at {url}",
        ))

        targets.append(ChainableTarget(
            url=url,
            param="",
            vuln_type="auth_bypass",
            context={"source": "admin_chain"},
            description=f"Admin chain: auth bypass at {url}",
        ))

        return targets

    def _extract_subdomain_targets(self, finding, recon) -> List[ChainableTarget]:
        """From subdomain discovery: add as new attack targets."""
        targets = []
        evidence = getattr(finding, "evidence", "")

        # Extract subdomains from evidence
        subdomain_pattern = r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[-a-zA-Z0-9.]+)'
        found_domains = set(re.findall(subdomain_pattern, evidence))

        for domain in list(found_domains)[:5]:
            if not domain.startswith("http"):
                domain_url = f"https://{domain}"
            else:
                domain_url = domain

            targets.append(ChainableTarget(
                url=domain_url,
                param="",
                vuln_type="xss_reflected",
                context={"source": "subdomain_chain"},
                description=f"Subdomain chain: test {domain}",
                priority=3,
            ))

        return targets

    # \u2500\u2500\u2500 AI Correlation \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    async def ai_correlate(self, findings: List[Any], llm=None) -> List[Dict]:
        """AI-driven correlation of multiple findings into attack chains.

        Analyzes all findings together to identify multi-step attack scenarios.
        """
        llm = llm or self.llm
        if not llm or not hasattr(llm, "generate"):
            return []

        if len(findings) < 2:
            return []

        try:
            findings_summary = []
            for f in findings[:20]:
                findings_summary.append(
                    f"- {getattr(f, 'vulnerability_type', '?')}: "
                    f"{getattr(f, 'url', '?')} "
                    f"(param: {getattr(f, 'parameter', '?')}, "
                    f"confidence: {getattr(f, 'confidence_score', '?')})"
                )

            prompt = f"""Analyze these confirmed vulnerability findings for potential exploit chains.

FINDINGS:
{chr(10).join(findings_summary)}

For each chain you identify, describe:
1. The attack scenario (2-3 sentences)
2. Which findings are linked
3. The impact if chained together
4. Priority (critical/high/medium)

Return ONLY realistic chains where one finding directly enables or amplifies another.
If no meaningful chains exist, say "No chains identified."
Format each chain as: CHAIN: [scenario] | FINDINGS: [types] | IMPACT: [impact] | PRIORITY: [level]"""

            result = await llm.generate(prompt)
            if not result:
                return []

            # Parse chains
            chains = []
            for line in result.strip().split("\n"):
                if line.startswith("CHAIN:"):
                    parts = line.split("|")
                    chain = {
                        "scenario": parts[0].replace("CHAIN:", "").strip() if len(parts) > 0 else "",
                        "findings": parts[1].replace("FINDINGS:", "").strip() if len(parts) > 1 else "",
                        "impact": parts[2].replace("IMPACT:", "").strip() if len(parts) > 2 else "",
                        "priority": parts[3].replace("PRIORITY:", "").strip() if len(parts) > 3 else "medium",
                    }
                    chains.append(chain)

            return chains

        except Exception as e:
            logger.debug(f"AI chain correlation failed: {e}")
            return []

    # \u2500\u2500\u2500 Reporting \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    def get_attack_graph(self) -> Dict[str, List[str]]:
        """Get the attack chain graph."""
        return dict(self._chain_graph)

    def get_chain_stats(self) -> Dict:
        """Get chain statistics for reporting."""
        return {
            "total_chains_generated": self._total_chains,
            "graph_nodes": len(self._chain_graph),
            "chain_findings": len(self._chain_findings),
        }
