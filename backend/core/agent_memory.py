"""
NeuroSploit v3 - Agent Memory Management

Bounded, deduplicated memory architecture for the autonomous agent.
Replaces ad-hoc self.findings / self.tested_payloads with structured,
eviction-aware data stores.

Inspired by XBOW benchmark methodology: every finding must have
real HTTP evidence, duplicates are suppressed, baselines are cached.
"""

import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from collections import OrderedDict
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TestedCombination:
    """Record of a (url, param, vuln_type) test attempt"""
    url: str
    param: str
    vuln_type: str
    payloads_used: List[str] = field(default_factory=list)
    was_vulnerable: bool = False
    tested_at: str = ""

    def __post_init__(self):
        if not self.tested_at:
            self.tested_at = datetime.utcnow().isoformat()


@dataclass
class EndpointFingerprint:
    """Fingerprint of an endpoint's normal response"""
    url: str
    status_code: int = 0
    content_type: str = ""
    body_length: int = 0
    body_hash: str = ""
    server_header: str = ""
    powered_by: str = ""
    error_patterns: List[str] = field(default_factory=list)
    tech_headers: Dict[str, str] = field(default_factory=dict)
    fingerprinted_at: str = ""

    def __post_init__(self):
        if not self.fingerprinted_at:
            self.fingerprinted_at = datetime.utcnow().isoformat()


@dataclass
class RejectedFinding:
    """Audit trail for rejected findings"""
    finding_hash: str
    vuln_type: str
    endpoint: str
    param: str
    reason: str
    rejected_at: str = ""

    def __post_init__(self):
        if not self.rejected_at:
            self.rejected_at = datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Speculative language patterns (anti-hallucination)
# ---------------------------------------------------------------------------

SPECULATIVE_PATTERNS = re.compile(
    r"\b(could be|might be|may be|theoretically|potentially vulnerable|"
    r"possibly|appears to be vulnerable|suggests? (a )?vulnerab|"
    r"it is possible|in theory|hypothetically)\b",
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# AgentMemory
# ---------------------------------------------------------------------------

class AgentMemory:
    """
    Bounded memory store for the autonomous agent.

    All containers have hard caps. When a cap is reached, the oldest 25%
    of entries are evicted (LRU-style).
    """

    # Capacity limits
    MAX_TESTED = 10_000
    MAX_BASELINES = 500
    MAX_FINGERPRINTS = 500
    MAX_CONFIRMED = 200
    MAX_REJECTED = 500

    # Domain-scoped types: only 1 finding per domain (not per URL)
    DOMAIN_SCOPED_TYPES = {
        # Infrastructure / headers
        "security_headers", "clickjacking", "insecure_http_headers",
        "missing_xcto", "missing_csp", "missing_hsts",
        "missing_referrer_policy", "missing_permissions_policy",
        "cors_misconfig", "insecure_cors_policy", "ssl_issues", "weak_tls_config",
        "http_methods", "unrestricted_http_methods",
        # Server config
        "debug_mode", "debug_mode_enabled", "verbose_error_messages",
        "directory_listing", "directory_listing_enabled",
        "exposed_admin_panel", "exposed_api_docs", "insecure_cookie_flags",
        # Data exposure
        "cleartext_transmission", "sensitive_data_exposure",
        "information_disclosure", "version_disclosure",
        "weak_encryption", "weak_hashing", "weak_random",
        # Auth config
        "missing_mfa", "weak_password_policy", "weak_password",
        # Cloud/API
        "graphql_introspection", "rest_api_versioning", "api_rate_limiting",
    }

    def __init__(self):
        # Core stores (OrderedDict for eviction order)
        self.tested_combinations: OrderedDict[str, TestedCombination] = OrderedDict()
        self.baseline_responses: OrderedDict[str, dict] = OrderedDict()
        self.endpoint_fingerprints: OrderedDict[str, EndpointFingerprint] = OrderedDict()

        # Findings
        self.confirmed_findings: List[Any] = []  # List[Finding] - uses agent's Finding dataclass
        self._finding_hashes: Set[str] = set()    # fast dedup lookup

        # Audit trail
        self.rejected_findings: List[RejectedFinding] = []

        # Technology stack detected across all endpoints
        self.technology_stack: Dict[str, str] = {}  # e.g. {"server": "Apache", "x-powered-by": "PHP/8.1"}

    # ------------------------------------------------------------------
    # Tested-combination tracking
    # ------------------------------------------------------------------

    @staticmethod
    def _test_key(url: str, param: str, vuln_type: str) -> str:
        """Deterministic key for a (url, param, vuln_type) tuple"""
        return hashlib.sha256(f"{url}|{param}|{vuln_type}".encode()).hexdigest()

    def was_tested(self, url: str, param: str, vuln_type: str) -> bool:
        """Check whether this combination was already tested"""
        return self._test_key(url, param, vuln_type) in self.tested_combinations

    def record_test(
        self, url: str, param: str, vuln_type: str,
        payloads: List[str], was_vulnerable: bool = False
    ):
        """Record a completed test"""
        key = self._test_key(url, param, vuln_type)
        self.tested_combinations[key] = TestedCombination(
            url=url, param=param, vuln_type=vuln_type,
            payloads_used=payloads[:10],  # store up to 10 payloads
            was_vulnerable=was_vulnerable,
        )
        self._enforce_limit(self.tested_combinations, self.MAX_TESTED)

    # ------------------------------------------------------------------
    # Baseline caching
    # ------------------------------------------------------------------

    @staticmethod
    def _baseline_key(url: str) -> str:
        """Key for baseline storage (strip query params for reuse)"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def store_baseline(self, url: str, response: dict):
        """Cache a baseline (clean) response for a URL"""
        key = self._baseline_key(url)
        body = response.get("body", "")
        self.baseline_responses[key] = {
            "status": response.get("status", 0),
            "content_type": response.get("content_type", ""),
            "body_length": len(body),
            "body_hash": hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest(),
            "body": body[:5000],  # store first 5k chars for comparison
            "headers": response.get("headers", {}),
            "fetched_at": datetime.utcnow().isoformat(),
        }
        self._enforce_limit(self.baseline_responses, self.MAX_BASELINES)

    def get_baseline(self, url: str) -> Optional[dict]:
        """Retrieve cached baseline for a URL"""
        key = self._baseline_key(url)
        baseline = self.baseline_responses.get(key)
        if baseline:
            # Move to end (mark as recently used)
            self.baseline_responses.move_to_end(key)
        return baseline

    # ------------------------------------------------------------------
    # Endpoint fingerprinting
    # ------------------------------------------------------------------

    def store_fingerprint(self, url: str, response: dict):
        """Extract and store endpoint fingerprint from a response"""
        key = self._baseline_key(url)
        headers = response.get("headers", {})
        body = response.get("body", "")

        # Detect error patterns in the body
        error_patterns = []
        error_regexes = [
            r"(?:sql|database|query)\s*(?:error|syntax|exception)",
            r"(?:warning|fatal|parse)\s*(?:error|exception)",
            r"stack\s*trace",
            r"traceback\s*\(most recent",
            r"<b>(?:Warning|Fatal error|Notice)</b>",
            r"Internal Server Error",
        ]
        body_lower = body.lower() if body else ""
        for pat in error_regexes:
            if re.search(pat, body_lower):
                error_patterns.append(pat)

        fp = EndpointFingerprint(
            url=url,
            status_code=response.get("status", 0),
            content_type=response.get("content_type", ""),
            body_length=len(body),
            body_hash=hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest(),
            server_header=headers.get("server", headers.get("Server", "")),
            powered_by=headers.get("x-powered-by", headers.get("X-Powered-By", "")),
            error_patterns=error_patterns,
            tech_headers={
                k: v for k, v in headers.items()
                if k.lower() in (
                    "server", "x-powered-by", "x-aspnet-version",
                    "x-generator", "x-drupal-cache", "x-framework",
                )
            },
        )
        self.endpoint_fingerprints[key] = fp
        self._enforce_limit(self.endpoint_fingerprints, self.MAX_FINGERPRINTS)

        # Update global tech stack
        if fp.server_header:
            self.technology_stack["server"] = fp.server_header
        if fp.powered_by:
            self.technology_stack["x-powered-by"] = fp.powered_by
        for k, v in fp.tech_headers.items():
            self.technology_stack[k.lower()] = v

    def get_fingerprint(self, url: str) -> Optional[EndpointFingerprint]:
        """Retrieve fingerprint for a URL"""
        key = self._baseline_key(url)
        return self.endpoint_fingerprints.get(key)

    # ------------------------------------------------------------------
    # Finding management (dedup + bounded)
    # ------------------------------------------------------------------

    @staticmethod
    def _finding_hash(finding) -> str:
        """Compute dedup hash for a finding.
        For domain-scoped types, uses scheme://netloc instead of full URL
        so the same missing header isn't reported per-URL.
        """
        vuln_type = finding.vulnerability_type
        endpoint = finding.affected_endpoint
        if vuln_type in AgentMemory.DOMAIN_SCOPED_TYPES:
            parsed = urlparse(endpoint)
            scope_key = f"{parsed.scheme}://{parsed.netloc}"
        else:
            scope_key = endpoint
        raw = f"{vuln_type}|{scope_key}|{finding.parameter}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _find_existing(self, finding) -> Optional[Any]:
        """Find an existing confirmed finding with the same dedup hash."""
        fh = self._finding_hash(finding)
        if fh not in self._finding_hashes:
            return None
        for f in self.confirmed_findings:
            if self._finding_hash(f) == fh:
                return f
        return None

    def add_finding(self, finding) -> bool:
        """
        Add a confirmed finding. Returns False if:
        - duplicate (same vuln_type + endpoint + param)
        - at capacity
        - evidence is missing or speculative

        For domain-scoped types, duplicates append the URL to
        the existing finding's affected_urls list instead.
        """
        fh = self._finding_hash(finding)

        # Dedup check — for domain-scoped types, merge URLs
        if fh in self._finding_hashes:
            if finding.vulnerability_type in self.DOMAIN_SCOPED_TYPES:
                existing = self._find_existing(finding)
                if existing and hasattr(existing, "affected_urls"):
                    url = finding.affected_endpoint
                    if url and url not in existing.affected_urls:
                        existing.affected_urls.append(url)
            return False

        # Capacity check
        if len(self.confirmed_findings) >= self.MAX_CONFIRMED:
            return False

        # Evidence quality check
        if not finding.evidence and not finding.response:
            return False

        # Speculative language check
        if finding.evidence and SPECULATIVE_PATTERNS.search(finding.evidence):
            self.reject_finding(finding, "Speculative language in evidence")
            return False

        self.confirmed_findings.append(finding)
        self._finding_hashes.add(fh)
        return True

    def reject_finding(self, finding, reason: str):
        """Record a rejected finding for audit"""
        self.rejected_findings.append(RejectedFinding(
            finding_hash=self._finding_hash(finding),
            vuln_type=getattr(finding, "vulnerability_type", "unknown"),
            endpoint=getattr(finding, "affected_endpoint", ""),
            param=getattr(finding, "parameter", ""),
            reason=reason,
        ))
        if len(self.rejected_findings) > self.MAX_REJECTED:
            # Evict oldest 25%
            cut = self.MAX_REJECTED // 4
            self.rejected_findings = self.rejected_findings[cut:]

    def has_finding_for(self, vuln_type: str, endpoint: str, param: str = "") -> bool:
        """Check if a confirmed finding already exists for this combo.
        Uses domain-scoped key for domain-scoped types.
        """
        if vuln_type in self.DOMAIN_SCOPED_TYPES:
            parsed = urlparse(endpoint)
            scope_key = f"{parsed.scheme}://{parsed.netloc}"
        else:
            scope_key = endpoint
        raw = f"{vuln_type}|{scope_key}|{param}"
        fh = hashlib.sha256(raw.encode()).hexdigest()
        return fh in self._finding_hashes

    # ------------------------------------------------------------------
    # Eviction helper
    # ------------------------------------------------------------------

    @staticmethod
    def _enforce_limit(od: OrderedDict, limit: int):
        """Evict oldest 25% when limit is exceeded"""
        if len(od) <= limit:
            return
        to_remove = limit // 4
        for _ in range(to_remove):
            od.popitem(last=False)  # pop oldest

    # ------------------------------------------------------------------
    # Stats / introspection
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        """Return memory usage statistics"""
        return {
            "tested_combinations": len(self.tested_combinations),
            "baseline_responses": len(self.baseline_responses),
            "endpoint_fingerprints": len(self.endpoint_fingerprints),
            "confirmed_findings": len(self.confirmed_findings),
            "rejected_findings": len(self.rejected_findings),
            "technology_stack": dict(self.technology_stack),
            "limits": {
                "tested": self.MAX_TESTED,
                "baselines": self.MAX_BASELINES,
                "fingerprints": self.MAX_FINGERPRINTS,
                "confirmed": self.MAX_CONFIRMED,
                "rejected": self.MAX_REJECTED,
            },
        }

    def clear(self):
        """Reset all memory stores"""
        self.tested_combinations.clear()
        self.baseline_responses.clear()
        self.endpoint_fingerprints.clear()
        self.confirmed_findings.clear()
        self._finding_hashes.clear()
        self.rejected_findings.clear()
        self.technology_stack.clear()
