"""
NeuroSploit v3 - Proof of Execution Framework

Per-vulnerability-type verification that a payload was actually PROCESSED
by the application, not just reflected or ignored. Each vuln type has specific
proof requirements — a finding without proof of execution scores 0.

This replaces the fragmented evidence checking in _cross_validate_ai_claim()
and _strict_technical_verify() with a unified, per-type proof system.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared patterns (from response_verifier.py)
# ---------------------------------------------------------------------------

DB_ERROR_PATTERNS = [
    r"(?:sql|database|query)\s*(?:error|syntax|exception)",
    r"mysql_(?:fetch|query|num_rows|connect)",
    r"mysqli_",
    r"pg_(?:query|exec|prepare|connect)",
    r"sqlite3?\.\w+error",
    r"ora-\d{4,5}",
    r"mssql_query",
    r"sqlstate\[",
    r"odbc\s+driver",
    r"jdbc\s+exception",
    r"unclosed\s+quotation",
    r"you have an error in your sql",
    r"syntax error.*at line \d+",
]

FILE_CONTENT_MARKERS = [
    "root:x:0:0:",
    "daemon:x:1:1:",
    "bin:x:2:2:",
    "www-data:",
    "[boot loader]",
    "[operating systems]",
    "[extensions]",
]

COMMAND_OUTPUT_PATTERNS = [
    r"uid=\d+\(",
    r"gid=\d+\(",
    r"root:\w+:0:0:",
    r"/bin/(?:ba)?sh",
    r"Linux\s+\S+\s+\d+\.\d+",
]

SSTI_EXPRESSIONS = {
    "7*7": "49",
    "7*'7'": "7777777",
    "3*3": "9",
}

# Cloud metadata markers for SSRF
SSRF_METADATA_MARKERS = [
    "ami-id", "ami-launch-index", "instance-id", "instance-type",
    "local-hostname", "local-ipv4", "public-hostname", "public-ipv4",
    "security-groups", "iam/info", "iam/security-credentials",
    "computeMetadata/v1", "metadata.google.internal",
    "169.254.169.254",  # Only if actual metadata content follows
]

# Internal content markers for SSRF
SSRF_INTERNAL_MARKERS = [
    "root:x:0:0:",      # /etc/passwd via SSRF
    "localhost",         # Internal service response
    "127.0.0.1",
    "internal server",
    "private network",
]


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class ProofResult:
    """Result of proof-of-execution check."""
    proven: bool               # Was execution proven?
    proof_type: str            # Type of proof found (e.g., "db_error", "xss_auto_fire")
    detail: str                # Human-readable description
    score: int                 # Confidence score contribution (0-60)
    impact_demonstrated: bool = False  # Was impact beyond mere detection shown?


# ---------------------------------------------------------------------------
# Proof Engine
# ---------------------------------------------------------------------------

_compiled_db_errors = [re.compile(p, re.IGNORECASE) for p in DB_ERROR_PATTERNS]
_compiled_cmd_patterns = [re.compile(p, re.IGNORECASE) for p in COMMAND_OUTPUT_PATTERNS]


class ProofOfExecution:
    """Per-vulnerability-type proof that the payload was executed/processed.

    Each vuln type has specific criteria. If the proof method returns
    score=0, the finding has NO proof of execution and should score low.
    """

    def check(self, vuln_type: str, payload: str, response: Dict,
              baseline: Optional[Dict] = None) -> ProofResult:
        """Check for proof of execution for the given vulnerability type.

        Args:
            vuln_type: Vulnerability type key
            payload: The attack payload used
            response: HTTP response dict {status, headers, body}
            baseline: Optional baseline response for comparison

        Returns:
            ProofResult with proven flag, proof type, detail, and score
        """
        body = response.get("body", "")
        status = response.get("status", 0)
        headers = response.get("headers", {})

        # Route to type-specific proof method
        method_name = f"_proof_{vuln_type}"
        if not hasattr(self, method_name):
            # Try base type (e.g., sqli_error -> sqli)
            base = vuln_type.split("_")[0]
            method_name = f"_proof_{base}"
            if not hasattr(self, method_name):
                return self._proof_default(vuln_type, payload, body, status,
                                          headers, baseline)

        return getattr(self, method_name)(payload, body, status, headers, baseline)

    # ------------------------------------------------------------------
    # XSS Proofs
    # ------------------------------------------------------------------

    def _proof_xss(self, payload: str, body: str, status: int,
                   headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_xss_reflected(payload, body, status, headers, baseline)

    def _proof_xss_reflected(self, payload: str, body: str, status: int,
                             headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """XSS proof: payload in executable/interactive HTML context."""
        if not payload or not body:
            return ProofResult(False, "", "No payload or body", 0)

        # Check if payload is reflected at all
        if payload not in body and payload.lower() not in body.lower():
            return ProofResult(False, "not_reflected",
                             "Payload not reflected in response", 0)

        # Use XSS context analyzer for definitive proof
        try:
            from backend.core.xss_context_analyzer import analyze_xss_execution_context
            ctx = analyze_xss_execution_context(body, payload)

            if ctx["executable"]:
                return ProofResult(
                    True, "xss_auto_fire",
                    f"Payload in auto-executing context: {ctx['detail']}",
                    60, impact_demonstrated=True
                )
            if ctx["interactive"]:
                return ProofResult(
                    True, "xss_interactive",
                    f"Payload in interactive context: {ctx['detail']}",
                    40, impact_demonstrated=False
                )
        except ImportError:
            pass

        # Fallback: raw reflection without context analysis
        return ProofResult(
            False, "reflected_only",
            "Payload reflected but context not confirmed executable",
            10
        )

    def _proof_xss_stored(self, payload: str, body: str, status: int,
                          headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """Stored XSS: same as reflected but requires payload on display page."""
        return self._proof_xss_reflected(payload, body, status, headers, baseline)

    def _proof_xss_dom(self, payload: str, body: str, status: int,
                       headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """DOM XSS: payload in DOM sink (harder to verify without browser)."""
        return self._proof_xss_reflected(payload, body, status, headers, baseline)

    # ------------------------------------------------------------------
    # SQLi Proofs
    # ------------------------------------------------------------------

    def _proof_sqli(self, payload: str, body: str, status: int,
                    headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """SQLi proof: DB error message caused by payload."""
        body_lower = body.lower()

        # Check for DB error patterns
        for pat in _compiled_db_errors:
            m = pat.search(body_lower)
            if m:
                # Verify error wasn't in baseline
                if baseline:
                    baseline_body = baseline.get("body", "").lower()
                    if pat.search(baseline_body):
                        continue  # Error exists in baseline — not induced
                return ProofResult(
                    True, "db_error",
                    f"SQL error induced: {m.group()[:80]}",
                    60, impact_demonstrated=True
                )

        # Check for boolean-based blind: significant response diff
        if baseline:
            baseline_len = len(baseline.get("body", ""))
            body_len = len(body)
            baseline_status = baseline.get("status", 0)

            if status != baseline_status and body_len != baseline_len:
                diff_pct = abs(body_len - baseline_len) / max(baseline_len, 1) * 100
                if diff_pct > 30:
                    return ProofResult(
                        True, "boolean_diff",
                        f"Boolean-based blind: {diff_pct:.0f}% response diff "
                        f"(status {baseline_status}->{status})",
                        50, impact_demonstrated=False
                    )

        return ProofResult(False, "", "No SQL error or boolean diff detected", 0)

    def _proof_sqli_error(self, payload: str, body: str, status: int,
                          headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_sqli(payload, body, status, headers, baseline)

    def _proof_sqli_union(self, payload: str, body: str, status: int,
                          headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_sqli(payload, body, status, headers, baseline)

    def _proof_sqli_blind(self, payload: str, body: str, status: int,
                          headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_sqli(payload, body, status, headers, baseline)

    def _proof_sqli_time(self, payload: str, body: str, status: int,
                         headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """Time-based SQLi: needs external timing measurement (lower score)."""
        # Time-based proof requires timing data not available in response alone
        # The timeout exception handler in the agent provides this signal
        if status == 0:  # Timeout
            return ProofResult(
                True, "time_based",
                "Request timeout consistent with time-based injection",
                40, impact_demonstrated=False
            )
        return ProofResult(False, "", "No timing anomaly detected", 0)

    # ------------------------------------------------------------------
    # SSRF Proofs
    # ------------------------------------------------------------------

    def _proof_ssrf(self, payload: str, body: str, status: int,
                    headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """SSRF proof: response contains actual internal/cloud resource content.

        IMPORTANT: Status/length diff alone is NOT proof of SSRF.
        Must show actual internal resource content.
        """
        body_lower = body.lower()

        # Check for cloud metadata content
        metadata_found = []
        for marker in SSRF_METADATA_MARKERS:
            if marker.lower() in body_lower:
                # Additional check: marker must NOT be in baseline
                if baseline:
                    baseline_lower = baseline.get("body", "").lower()
                    if marker.lower() in baseline_lower:
                        continue
                metadata_found.append(marker)

        if len(metadata_found) >= 2:
            # Multiple metadata fields = strong SSRF proof
            return ProofResult(
                True, "cloud_metadata",
                f"Cloud metadata content: {', '.join(metadata_found[:5])}",
                60, impact_demonstrated=True
            )
        if len(metadata_found) == 1:
            return ProofResult(
                True, "partial_metadata",
                f"Partial metadata: {metadata_found[0]}",
                40, impact_demonstrated=False
            )

        # Check for /etc/passwd via SSRF
        for marker in FILE_CONTENT_MARKERS:
            if marker.lower() in body_lower:
                if baseline:
                    if marker.lower() in baseline.get("body", "").lower():
                        continue
                return ProofResult(
                    True, "internal_file",
                    f"Internal file content via SSRF: {marker}",
                    60, impact_demonstrated=True
                )

        # Status/length diff alone is NOT SSRF proof
        return ProofResult(
            False, "",
            "No internal resource content found (status/length diff alone is insufficient)",
            0
        )

    def _proof_ssrf_cloud(self, payload: str, body: str, status: int,
                          headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_ssrf(payload, body, status, headers, baseline)

    # ------------------------------------------------------------------
    # LFI / Path Traversal Proofs
    # ------------------------------------------------------------------

    def _proof_lfi(self, payload: str, body: str, status: int,
                   headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """LFI proof: actual file content markers in response."""
        body_lower = body.lower()

        for marker in FILE_CONTENT_MARKERS:
            if marker.lower() in body_lower:
                if baseline:
                    if marker.lower() in baseline.get("body", "").lower():
                        continue  # Marker in baseline
                return ProofResult(
                    True, "file_content",
                    f"File content marker: {marker}",
                    60, impact_demonstrated=True
                )

        return ProofResult(False, "", "No file content markers found", 0)

    def _proof_path_traversal(self, payload: str, body: str, status: int,
                              headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_lfi(payload, body, status, headers, baseline)

    def _proof_path(self, payload: str, body: str, status: int,
                    headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_lfi(payload, body, status, headers, baseline)

    # ------------------------------------------------------------------
    # SSTI Proofs
    # ------------------------------------------------------------------

    def _proof_ssti(self, payload: str, body: str, status: int,
                    headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """SSTI proof: template expression was evaluated."""
        for expr, result in SSTI_EXPRESSIONS.items():
            if expr in (payload or ""):
                if result in body and expr not in body:
                    return ProofResult(
                        True, "expression_evaluated",
                        f"Template expression {expr}={result} evaluated",
                        60, impact_demonstrated=True
                    )

        return ProofResult(False, "", "No template expression evaluation detected", 0)

    # ------------------------------------------------------------------
    # RCE / Command Injection Proofs
    # ------------------------------------------------------------------

    def _proof_rce(self, payload: str, body: str, status: int,
                   headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """RCE proof: command output markers in response."""
        for pat in _compiled_cmd_patterns:
            m = pat.search(body)
            if m:
                if baseline:
                    if pat.search(baseline.get("body", "")):
                        continue
                return ProofResult(
                    True, "command_output",
                    f"Command output: {m.group()[:80]}",
                    60, impact_demonstrated=True
                )

        return ProofResult(False, "", "No command output markers found", 0)

    def _proof_command(self, payload: str, body: str, status: int,
                       headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_rce(payload, body, status, headers, baseline)

    def _proof_command_injection(self, payload: str, body: str, status: int,
                                headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_rce(payload, body, status, headers, baseline)

    # ------------------------------------------------------------------
    # Open Redirect Proofs
    # ------------------------------------------------------------------

    def _proof_open(self, payload: str, body: str, status: int,
                    headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_open_redirect(payload, body, status, headers, baseline)

    def _proof_open_redirect(self, payload: str, body: str, status: int,
                             headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """Open redirect proof: Location header points to attacker-controlled domain."""
        if status not in (301, 302, 303, 307, 308):
            return ProofResult(False, "", "No redirect status code", 0)

        location = headers.get("Location", headers.get("location", ""))
        if not location:
            return ProofResult(False, "", "No Location header", 0)

        # Check if Location contains the injected external domain
        if payload and any(domain in location.lower() for domain in
                          ["evil.com", "attacker.com", "example.com"]
                          if domain in payload.lower()):
            return ProofResult(
                True, "redirect_to_external",
                f"Redirect to attacker domain: {location[:200]}",
                60, impact_demonstrated=True
            )

        # Protocol-relative redirect
        if location.startswith("//") and any(
            domain in location for domain in ["evil.com", "attacker.com"]
            if domain in (payload or "")
        ):
            return ProofResult(
                True, "protocol_relative_redirect",
                f"Protocol-relative redirect: {location[:200]}",
                60, impact_demonstrated=True
            )

        # Meta-refresh redirect in body
        meta_pattern = r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*url=([^"\'>\s]+)'
        meta_match = re.search(meta_pattern, body, re.IGNORECASE)
        if meta_match:
            redirect_url = meta_match.group(1)
            if any(domain in redirect_url.lower() for domain in
                   ["evil.com", "attacker.com"] if domain in (payload or "").lower()):
                return ProofResult(
                    True, "meta_refresh_redirect",
                    f"Meta-refresh redirect: {redirect_url[:200]}",
                    30, impact_demonstrated=False
                )

        return ProofResult(False, "", "No external redirect detected", 0)

    # ------------------------------------------------------------------
    # CRLF / Header Injection Proofs
    # ------------------------------------------------------------------

    def _proof_crlf(self, payload: str, body: str, status: int,
                    headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_crlf_injection(payload, body, status, headers, baseline)

    def _proof_crlf_injection(self, payload: str, body: str, status: int,
                              headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """CRLF proof: injected header appears in response headers."""
        injected_header_names = ["X-Injected", "X-CRLF-Test", "Set-Cookie"]

        for hdr_name in injected_header_names:
            if hdr_name.lower() in (payload or "").lower():
                val = headers.get(hdr_name, headers.get(hdr_name.lower(), ""))
                if val and ("injected" in val.lower() or "crlf" in val.lower()
                           or "test" in val.lower()):
                    return ProofResult(
                        True, "header_injected",
                        f"Injected header: {hdr_name}: {val[:100]}",
                        60, impact_demonstrated=True
                    )

        return ProofResult(False, "", "No injected headers found", 0)

    def _proof_header(self, payload: str, body: str, status: int,
                      headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_crlf_injection(payload, body, status, headers, baseline)

    def _proof_header_injection(self, payload: str, body: str, status: int,
                                headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_crlf_injection(payload, body, status, headers, baseline)

    # ------------------------------------------------------------------
    # XXE Proofs
    # ------------------------------------------------------------------

    def _proof_xxe(self, payload: str, body: str, status: int,
                   headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """XXE proof: file content or SSRF response from entity expansion."""
        body_lower = body.lower()

        for marker in FILE_CONTENT_MARKERS:
            if marker.lower() in body_lower:
                if baseline and marker.lower() in baseline.get("body", "").lower():
                    continue
                return ProofResult(
                    True, "xxe_file_read",
                    f"XXE entity expansion: {marker}",
                    60, impact_demonstrated=True
                )

        # XXE SSRF: metadata markers
        for marker in SSRF_METADATA_MARKERS:
            if marker.lower() in body_lower:
                if baseline and marker.lower() in baseline.get("body", "").lower():
                    continue
                return ProofResult(
                    True, "xxe_ssrf",
                    f"XXE SSRF: {marker}",
                    60, impact_demonstrated=True
                )

        return ProofResult(False, "", "No XXE entity expansion detected", 0)

    # ------------------------------------------------------------------
    # NoSQL Injection Proofs
    # ------------------------------------------------------------------

    def _proof_nosql(self, payload: str, body: str, status: int,
                     headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_nosql_injection(payload, body, status, headers, baseline)

    def _proof_nosql_injection(self, payload: str, body: str, status: int,
                               headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """NoSQL injection proof: MongoDB/NoSQL error or boolean response diff."""
        body_lower = body.lower()

        nosql_errors = [
            r"MongoError", r"mongo.*(?:syntax|parse|query).*error",
            r"BSONTypeError", r"CastError.*ObjectId",
        ]
        for pat_str in nosql_errors:
            m = re.search(pat_str, body, re.IGNORECASE)
            if m:
                if baseline and re.search(pat_str, baseline.get("body", ""), re.IGNORECASE):
                    continue
                return ProofResult(
                    True, "nosql_error",
                    f"NoSQL error: {m.group()[:80]}",
                    60, impact_demonstrated=True
                )

        # Boolean-based blind NoSQL
        if baseline and ("$gt" in (payload or "") or "$ne" in (payload or "")):
            baseline_len = len(baseline.get("body", ""))
            diff_pct = abs(len(body) - baseline_len) / max(baseline_len, 1) * 100
            if diff_pct > 20:
                return ProofResult(
                    True, "nosql_boolean",
                    f"NoSQL boolean diff: {diff_pct:.0f}%",
                    45, impact_demonstrated=False
                )

        return ProofResult(False, "", "No NoSQL error or boolean diff", 0)

    # ------------------------------------------------------------------
    # IDOR Proofs
    # ------------------------------------------------------------------

    def _proof_idor(self, payload: str, body: str, status: int,
                    headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """IDOR proof: accessing another user's resource with data comparison.

        CRITICAL: HTTP status codes are NOT reliable for access control.
        We verify by checking actual response DATA, not just status/length.
        """
        return self._proof_access_control(payload, body, status, headers, baseline, "idor")

    def _proof_bola(self, payload: str, body: str, status: int,
                    headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """BOLA proof: API object-level authorization with data comparison."""
        return self._proof_access_control(payload, body, status, headers, baseline, "bola")

    def _proof_bfla(self, payload: str, body: str, status: int,
                    headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """BFLA proof: function-level authorization with data comparison."""
        return self._proof_access_control(payload, body, status, headers, baseline, "bfla")

    def _proof_privilege_escalation(self, payload: str, body: str, status: int,
                                     headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """Privilege escalation proof with data comparison."""
        return self._proof_access_control(payload, body, status, headers, baseline, "privilege_escalation")

    def _proof_auth_bypass(self, payload: str, body: str, status: int,
                           headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """Auth bypass proof: verify authenticated content is actually returned."""
        return self._proof_access_control(payload, body, status, headers, baseline, "auth_bypass")

    def _proof_forced_browsing(self, payload: str, body: str, status: int,
                               headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """Forced browsing proof with data comparison."""
        return self._proof_access_control(payload, body, status, headers, baseline, "forced_browsing")

    def _proof_access_control(self, payload: str, body: str, status: int,
                              headers: Dict, baseline: Optional[Dict],
                              vuln_subtype: str) -> ProofResult:
        """Unified access control proof with smart data comparison.

        NEVER trusts status codes alone. Checks:
        1. Response body is NOT an error/empty/login page (false positive indicators)
        2. Response body contains ACTUAL data (JSON objects, user fields, etc.)
        3. Response body DIFFERS from baseline (different user's data)
        4. Response body does NOT contain denial indicators
        """
        body_lower = body.lower().strip()
        body_len = len(body)

        # ------- FALSE POSITIVE: Empty or trivially small response -------
        if body_len < 10:
            return ProofResult(False, "", "Empty response body — no data returned", 0)

        # ------- FALSE POSITIVE: Error/denial messages in body -------
        denial_indicators = [
            "unauthorized", "forbidden", "access denied", "not authorized",
            "permission denied", "authentication required", "login required",
            "please log in", "please sign in", "invalid token", "token expired",
            "session expired", "not found", "does not exist", "no permission",
            "insufficient privileges", "you do not have access",
            '"error":', '"status":"error"', '"success":false', '"success": false',
        ]
        denial_count = sum(1 for d in denial_indicators if d in body_lower)
        if denial_count >= 2:
            return ProofResult(
                False, "",
                f"Response contains {denial_count} denial indicators — access was denied despite status {status}",
                0
            )

        # ------- FALSE POSITIVE: Login/redirect page -------
        login_indicators = [
            "<form", "type=\"password\"", "type='password'",
            'name="password"', "name='password'",
            "sign in", "log in", "login", "<title>login",
        ]
        login_count = sum(1 for l in login_indicators if l in body_lower)
        if login_count >= 3:
            return ProofResult(
                False, "",
                f"Response appears to be a login page ({login_count} login indicators)",
                0
            )

        # ------- POSITIVE: Check for actual data content -------
        data_indicators = [
            # JSON data fields (common in API responses)
            '"email":', '"name":', '"username":', '"phone":', '"address":',
            '"role":', '"balance":', '"password":', '"token":', '"secret":',
            '"orders":', '"items":', '"created_at":', '"updated_at":',
            '"first_name":', '"last_name":', '"profile":', '"account":',
            # HTML data (for web pages)
            "user-profile", "account-details", "order-history",
        ]
        data_count = sum(1 for d in data_indicators if d in body_lower)

        # ------- Compare with baseline if available -------
        if baseline:
            baseline_body = baseline.get("body", "")
            baseline_len = len(baseline_body)

            # If response is nearly identical to baseline, likely same-behavior
            if baseline_len > 0:
                diff_pct = abs(body_len - baseline_len) / max(baseline_len, 1) * 100
                baseline_lower = baseline_body.lower().strip()

                # Check if body content actually differs (not just length)
                if body_lower == baseline_lower:
                    return ProofResult(
                        False, "",
                        "Response identical to baseline — server ignores the ID parameter",
                        0
                    )

                # Content-based comparison: for access control vulns,
                # different users have similar-length responses but different data
                # Count how many data field VALUES differ between attack and baseline
                content_diff_score = self._compare_data_content(body, baseline_body)

                # Strong content difference with data indicators
                if content_diff_score >= 3 and data_count >= 2:
                    return ProofResult(
                        True, f"{vuln_subtype}_data_diff",
                        f"Different data content returned ({content_diff_score} field values differ, "
                        f"{data_count} data fields found) — likely another user's data",
                        40, impact_demonstrated=True
                    )

                # Significant length difference with data indicators
                if diff_pct > 10 and data_count >= 2:
                    return ProofResult(
                        True, f"{vuln_subtype}_data_diff",
                        f"Different data returned ({diff_pct:.0f}% content diff, "
                        f"{data_count} data fields found) — likely another user's data",
                        40, impact_demonstrated=True
                    )

                # Moderate content or length difference
                if (content_diff_score >= 2 or diff_pct > 5) and data_count >= 1:
                    return ProofResult(
                        True, f"{vuln_subtype}_content_diff",
                        f"Content differs from baseline ({content_diff_score} values differ, "
                        f"{diff_pct:.0f}% len diff, {data_count} data fields) — possible cross-user access",
                        30, impact_demonstrated=False
                    )

        # No baseline — check if response has meaningful data
        if data_count >= 3:
            return ProofResult(
                True, f"{vuln_subtype}_data_present",
                f"Response contains {data_count} data fields (no baseline for comparison)",
                25, impact_demonstrated=False
            )

        if data_count >= 1 and status == 200 and denial_count == 0:
            return ProofResult(
                True, f"{vuln_subtype}_possible",
                f"Response has data ({data_count} fields) and no denial — needs manual verification",
                15, impact_demonstrated=False
            )

        return ProofResult(
            False, "",
            f"Cannot verify {vuln_subtype}: {data_count} data fields, "
            f"{denial_count} denial indicators, status {status}",
            0
        )

    @staticmethod
    def _compare_data_content(body_a: str, body_b: str) -> int:
        """Compare two response bodies for data-level differences.

        Extracts JSON-like key:value pairs and counts how many values differ
        between the two responses. This is essential for access control testing
        where response LENGTHS are similar but the actual DATA differs
        (e.g., different user profiles).

        Returns number of differing field values (0 = identical data).
        """
        import json as _json

        # Try JSON parsing first
        try:
            data_a = _json.loads(body_a)
            data_b = _json.loads(body_b)
            if isinstance(data_a, dict) and isinstance(data_b, dict):
                diff_count = 0
                all_keys = set(data_a.keys()) | set(data_b.keys())
                for key in all_keys:
                    val_a = str(data_a.get(key, ""))
                    val_b = str(data_b.get(key, ""))
                    if val_a != val_b:
                        diff_count += 1
                return diff_count
        except (ValueError, TypeError):
            pass

        # Fallback: regex-based extraction of "key":"value" pairs
        kv_pattern = re.compile(r'"(\w+)":\s*"([^"]*)"')
        pairs_a = dict(kv_pattern.findall(body_a))
        pairs_b = dict(kv_pattern.findall(body_b))

        if not pairs_a and not pairs_b:
            # Not JSON-like; do simple line-level comparison
            lines_a = set(body_a.strip().splitlines())
            lines_b = set(body_b.strip().splitlines())
            return len(lines_a.symmetric_difference(lines_b))

        all_keys = set(pairs_a.keys()) | set(pairs_b.keys())
        return sum(1 for k in all_keys if pairs_a.get(k) != pairs_b.get(k))

    # ------------------------------------------------------------------
    # Host Header Injection
    # ------------------------------------------------------------------

    def _proof_host(self, payload: str, body: str, status: int,
                    headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_host_header_injection(payload, body, status, headers, baseline)

    def _proof_host_header_injection(self, payload: str, body: str, status: int,
                                     headers: Dict,
                                     baseline: Optional[Dict]) -> ProofResult:
        """Host header injection: injected host reflected in response body/links."""
        evil_hosts = ["evil.com", "attacker.com", "injected.host"]
        body_lower = body.lower()

        for host in evil_hosts:
            if host in (payload or "").lower() and host in body_lower:
                if baseline and host in baseline.get("body", "").lower():
                    continue
                return ProofResult(
                    True, "host_reflected",
                    f"Injected host '{host}' reflected in response",
                    50, impact_demonstrated=False
                )

        return ProofResult(False, "", "Injected host not reflected", 0)

    # ------------------------------------------------------------------
    # Inspection types (no execution proof needed)
    # ------------------------------------------------------------------

    def _proof_security(self, payload: str, body: str, status: int,
                        headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_inspection(payload, body, status, headers, baseline)

    def _proof_cors(self, payload: str, body: str, status: int,
                    headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_inspection(payload, body, status, headers, baseline)

    def _proof_clickjacking(self, payload: str, body: str, status: int,
                            headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_inspection(payload, body, status, headers, baseline)

    def _proof_directory(self, payload: str, body: str, status: int,
                         headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_inspection(payload, body, status, headers, baseline)

    def _proof_debug(self, payload: str, body: str, status: int,
                     headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_inspection(payload, body, status, headers, baseline)

    def _proof_information(self, payload: str, body: str, status: int,
                           headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_inspection(payload, body, status, headers, baseline)

    def _proof_insecure(self, payload: str, body: str, status: int,
                        headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        return self._proof_inspection(payload, body, status, headers, baseline)

    def _proof_inspection(self, payload: str, body: str, status: int,
                          headers: Dict, baseline: Optional[Dict]) -> ProofResult:
        """Inspection types: proof is the header/config itself being present/absent."""
        return ProofResult(
            True, "inspection",
            "Inspection-type finding — proof is configuration state",
            50, impact_demonstrated=False
        )

    # ------------------------------------------------------------------
    # Default / Unknown types
    # ------------------------------------------------------------------

    def _proof_default(self, vuln_type: str, payload: str, body: str,
                       status: int, headers: Dict,
                       baseline: Optional[Dict]) -> ProofResult:
        """Default: conservative scoring for unknown vuln types."""
        # Check basic payload effect (reflected + different from baseline)
        if payload and payload.lower() in body.lower():
            if baseline:
                baseline_body = baseline.get("body", "")
                if payload.lower() not in baseline_body.lower():
                    return ProofResult(
                        True, "payload_reflected",
                        f"Payload reflected (not in baseline) for {vuln_type}",
                        25, impact_demonstrated=False
                    )
            return ProofResult(
                False, "reflected_no_baseline",
                f"Payload reflected but no baseline to compare for {vuln_type}",
                10
            )

        return ProofResult(
            False, "",
            f"No proof of execution for {vuln_type}",
            0
        )
