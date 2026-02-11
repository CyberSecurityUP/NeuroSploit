"""
NeuroSploit v3 - XBOW-Inspired Response Verification Framework

Multi-signal verification system that confirms vulnerabilities
through 4 independent signals, reducing false positives dramatically.

Inspired by XBOW benchmark methodology:
- Binary verification (flag-based in CTF, evidence-based here)
- Health checks before testing
- Baseline diffing for behavioral anomaly detection
- Multi-signal confirmation (2+ signals = confirmed without AI)
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple, Any


# ---------------------------------------------------------------------------
# Error / indicator patterns used across multiple checkers
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

TEMPLATE_ERROR_PATTERNS = [
    r"jinja2\.exceptions\.\w+",
    r"mako\.exceptions\.\w+",
    r"twig.*error",
    r"freemarker.*error",
    r"smarty.*error",
    r"django\.template\.\w+",
    r"template syntax error",
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

SSTI_EVALUATIONS = {
    "7*7": "49",
    "7*'7'": "7777777",
    "3*3": "9",
}

COMMAND_OUTPUT_MARKERS = [
    r"uid=\d+\(",
    r"gid=\d+\(",
    r"root:\w+:0:0:",
    r"/bin/(?:ba)?sh",
    r"Linux\s+\S+\s+\d+\.\d+",
    r"total\s+\d+\s*\n",
]

NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"mongo.*(?:syntax|parse|query).*error",
    r"\$(?:gt|lt|ne|in|nin|regex|where|exists)\b",
    r"CastError.*ObjectId",
    r"BSONTypeError",
    r"operator.*\$(?:gt|lt|ne|regex)",
]

LDAP_ERROR_PATTERNS = [
    r"javax\.naming\.(?:directory\.)?InvalidSearchFilterException",
    r"Bad search filter",
    r"ldap_search.*error",
    r"invalid.*(?:dn|distinguished name|ldap filter)",
    r"unbalanced.*parenthes[ei]s",
    r"NamingException",
]

XPATH_ERROR_PATTERNS = [
    r"XPathException",
    r"Invalid XPath",
    r"xmlXPathEval.*error",
    r"DOMXPath.*(?:evaluate|query).*error",
    r"SimpleXMLElement.*xpath",
    r"unterminated.*(?:string|expression).*xpath",
    r"XPATH syntax error",
]

GRAPHQL_ERROR_PATTERNS = [
    r'"errors"\s*:\s*\[',
    r"Syntax Error.*GraphQL",
    r"Cannot query field",
    r"Unknown argument",
    r"Expected Name",
    r"graphql.*parse.*error",
]

DESERIALIZATION_ERROR_PATTERNS = [
    r"java\.io\.(?:InvalidClass|StreamCorrupted)Exception",
    r"ClassNotFoundException",
    r"unserialize\(\).*error",
    r"pickle\.UnpicklingError",
    r"yaml\.(?:scanner|parser)\.ScannerError",
    r"__wakeup\(\).*failed",
    r"ObjectInputStream",
    r"readObject\(\).*exception",
]

EL_INJECTION_PATTERNS = [
    r"javax\.el\.ELException",
    r"org\.springframework\.expression\.spel",
    r"EL Expression.*error",
    r"OGNL.*exception",
]


# ---------------------------------------------------------------------------
# Health checking
# ---------------------------------------------------------------------------

UNHEALTHY_PATTERNS = [
    "502 bad gateway",
    "503 service unavailable",
    "service unavailable",
    "maintenance mode",
    "under maintenance",
    "temporarily unavailable",
    "server is starting",
    "connection refused",
]


class ResponseVerifier:
    """
    Multi-signal verification framework for vulnerability confirmation.

    4 independent signals are checked:
    1. VulnEngine tester pattern match (structured analyze_response)
    2. Baseline diff (status / length / hash change)
    3. Payload effect (reflection, evaluation, file content)
    4. New error patterns (present in test but absent in baseline)

    Confidence rules:
    - 2+ signals → confirmed (skip AI)
    - 1 signal + confidence >= 0.8 → confirmed
    - 1 signal + confidence < 0.8 → needs AI confirmation
    - 0 signals → rejected
    """

    def __init__(self):
        self._compiled_db_errors = [re.compile(p, re.IGNORECASE) for p in DB_ERROR_PATTERNS]
        self._compiled_template_errors = [re.compile(p, re.IGNORECASE) for p in TEMPLATE_ERROR_PATTERNS]
        self._compiled_cmd_markers = [re.compile(p, re.IGNORECASE) for p in COMMAND_OUTPUT_MARKERS]
        self._compiled_nosql_errors = [re.compile(p, re.IGNORECASE) for p in NOSQL_ERROR_PATTERNS]
        self._compiled_ldap_errors = [re.compile(p, re.IGNORECASE) for p in LDAP_ERROR_PATTERNS]
        self._compiled_xpath_errors = [re.compile(p, re.IGNORECASE) for p in XPATH_ERROR_PATTERNS]
        self._compiled_graphql_errors = [re.compile(p, re.IGNORECASE) for p in GRAPHQL_ERROR_PATTERNS]
        self._compiled_deser_errors = [re.compile(p, re.IGNORECASE) for p in DESERIALIZATION_ERROR_PATTERNS]
        self._compiled_el_errors = [re.compile(p, re.IGNORECASE) for p in EL_INJECTION_PATTERNS]

    # ------------------------------------------------------------------
    # Target health check
    # ------------------------------------------------------------------

    async def check_target_health(self, session, url: str) -> Tuple[bool, dict]:
        """
        Verify the target is alive and functional before testing.

        Returns:
            (is_healthy, info_dict)
        """
        try:
            async with session.get(url, timeout=15, allow_redirects=True) as resp:
                body = await resp.text()
                status = resp.status
                headers = dict(resp.headers)

                info = {
                    "status": status,
                    "content_length": len(body),
                    "content_type": headers.get("Content-Type", ""),
                    "server": headers.get("Server", ""),
                }

                # Reject server errors
                if status >= 500:
                    info["reason"] = f"Server error (HTTP {status})"
                    return False, info

                # Reject empty/minimal pages
                if len(body) < 50:
                    info["reason"] = "Response too short (< 50 chars)"
                    return False, info

                # Check for unhealthy content
                body_lower = body.lower()
                for pattern in UNHEALTHY_PATTERNS:
                    if pattern in body_lower:
                        info["reason"] = f"Unhealthy response: '{pattern}'"
                        return False, info

                info["healthy"] = True
                return True, info

        except Exception as e:
            return False, {"reason": f"Connection error: {str(e)[:200]}"}

    # ------------------------------------------------------------------
    # Baseline diffing
    # ------------------------------------------------------------------

    def compute_response_diff(self, baseline: dict, test_response: dict) -> dict:
        """
        Compare test response against cached baseline.

        Returns dict with diff metrics.
        """
        baseline_body = baseline.get("body", "")
        test_body = test_response.get("body", "")

        baseline_len = len(baseline_body) if isinstance(baseline_body, str) else baseline.get("body_length", 0)
        test_len = len(test_body)

        length_diff = abs(test_len - baseline_len)
        length_pct = (length_diff / max(baseline_len, 1)) * 100

        baseline_hash = baseline.get("body_hash") or hashlib.md5(
            baseline_body.encode("utf-8", errors="replace")
        ).hexdigest()
        test_hash = hashlib.md5(
            test_body.encode("utf-8", errors="replace")
        ).hexdigest()

        # Detect new error patterns in test but not baseline
        baseline_lower = (baseline_body if isinstance(baseline_body, str) else "").lower()
        test_lower = test_body.lower()

        new_errors = []
        for pat in self._compiled_db_errors:
            if pat.search(test_lower) and not pat.search(baseline_lower):
                new_errors.append(pat.pattern)
        for pat in self._compiled_template_errors:
            if pat.search(test_lower) and not pat.search(baseline_lower):
                new_errors.append(pat.pattern)

        return {
            "status_changed": baseline.get("status", 0) != test_response.get("status", 0),
            "baseline_status": baseline.get("status", 0),
            "test_status": test_response.get("status", 0),
            "length_diff": length_diff,
            "length_diff_pct": round(length_pct, 1),
            "body_hash_changed": baseline_hash != test_hash,
            "new_error_patterns": new_errors,
        }

    # ------------------------------------------------------------------
    # Payload effect verification
    # ------------------------------------------------------------------

    def _check_payload_effect(self, vuln_type: str, payload: str,
                               test_body: str, test_status: int,
                               test_headers: dict,
                               baseline_body: str = "",
                               baseline_status: int = 0) -> Tuple[bool, Optional[str]]:
        """
        Check if the payload produced a detectable effect in the response.

        This is signal #3 in multi-signal verification.
        Weak checks (NoSQL blind, parameter pollution, type juggling,
        HTML injection, JWT, blind XSS, mutation XSS) require baseline
        comparison to eliminate false positives.
        """
        body_lower = test_body.lower()
        baseline_lower = baseline_body.lower() if baseline_body else ""

        # ---- XSS ----
        if vuln_type in ("xss", "xss_reflected", "xss_stored", "xss_dom"):
            payload_lower = payload.lower()
            # Unescaped reflection — use context-aware analysis
            if payload in test_body or payload_lower in body_lower:
                from backend.core.xss_context_analyzer import analyze_xss_execution_context
                ctx = analyze_xss_execution_context(test_body, payload)
                if ctx["executable"]:
                    return True, f"XSS payload in auto-executing context: {ctx['detail']}"
                if ctx["interactive"]:
                    return True, f"XSS payload in interactive context: {ctx['detail']}"
            return False, None

        # ---- SQLi ----
        if vuln_type in ("sqli", "sqli_error", "sqli_union", "sqli_blind", "sqli_time"):
            for pat in self._compiled_db_errors:
                m = pat.search(body_lower)
                if m:
                    return True, f"SQL error induced by payload: {m.group()}"
            return False, None

        # ---- SSTI ----
        if vuln_type == "ssti":
            for expr, result in SSTI_EVALUATIONS.items():
                if expr in payload and result in test_body:
                    # Confirm the raw expression is NOT present (evaluated)
                    if expr not in test_body:
                        return True, f"Template expression evaluated: {expr}={result}"
            return False, None

        # ---- LFI / Path Traversal ----
        if vuln_type in ("lfi", "path_traversal"):
            for marker in FILE_CONTENT_MARKERS:
                if marker.lower() in body_lower:
                    return True, f"File content detected: {marker}"
            return False, None

        # ---- Command Injection / RCE ----
        if vuln_type in ("rce", "command_injection"):
            for pat in self._compiled_cmd_markers:
                m = pat.search(test_body)
                if m:
                    return True, f"Command output detected: {m.group()}"
            return False, None

        # ---- SSRF ----
        if vuln_type in ("ssrf", "ssrf_cloud"):
            ssrf_markers = ["ami-id", "instance-type", "iam/info", "meta-data",
                           "computeMetadata", "root:x:0:0"]
            for marker in ssrf_markers:
                if marker.lower() in body_lower:
                    return True, f"Internal resource content: {marker}"
            return False, None

        # ---- Open Redirect ----
        if vuln_type == "open_redirect":
            if test_status in (301, 302, 303, 307, 308):
                location = test_headers.get("Location", test_headers.get("location", ""))
                if "evil.com" in location or location.startswith("//"):
                    return True, f"Redirect to external: {location}"
            return False, None

        # ---- XXE ----
        if vuln_type == "xxe":
            for marker in FILE_CONTENT_MARKERS:
                if marker.lower() in body_lower:
                    return True, f"XXE file read: {marker}"
            return False, None

        # ---- NoSQL Injection ----
        if vuln_type == "nosql_injection":
            for pat in self._compiled_nosql_errors:
                m = pat.search(body_lower)
                if m:
                    return True, f"NoSQL error induced: {m.group()}"
            # Boolean-based blind NoSQL: require response DIFFERS from baseline
            if "$gt" in payload or "$ne" in payload or "$regex" in payload:
                if baseline_body and test_status == 200:
                    len_diff = abs(len(test_body) - len(baseline_body))
                    len_pct = (len_diff / max(len(baseline_body), 1)) * 100
                    status_diff = test_status != baseline_status
                    if len_pct > 20 or status_diff:
                        return True, f"NoSQL blind: Response differs from baseline (delta {len_diff} chars, {len_pct:.0f}%)"
            return False, None

        # ---- LDAP Injection ----
        if vuln_type == "ldap_injection":
            for pat in self._compiled_ldap_errors:
                m = pat.search(test_body)
                if m:
                    return True, f"LDAP error induced: {m.group()}"
            return False, None

        # ---- XPath Injection ----
        if vuln_type == "xpath_injection":
            for pat in self._compiled_xpath_errors:
                m = pat.search(test_body)
                if m:
                    return True, f"XPath error induced: {m.group()}"
            return False, None

        # ---- CRLF Injection ----
        if vuln_type == "crlf_injection":
            # Check if injected header appears in response headers
            injected_headers = ["X-Injected", "Set-Cookie", "X-CRLF-Test"]
            for hdr in injected_headers:
                if hdr.lower() in payload.lower():
                    header_val = test_headers.get(hdr, test_headers.get(hdr.lower(), ""))
                    if header_val and ("injected" in header_val.lower() or "crlf" in header_val.lower()):
                        return True, f"CRLF: Injected header appeared: {hdr}: {header_val[:100]}"
            # Check for header splitting in body
            if "\r\n" in payload and test_status in (200, 302):
                if "x-injected" in body_lower or "set-cookie" in body_lower:
                    return True, "CRLF: Injected headers visible in response body"
            return False, None

        # ---- Header Injection ----
        if vuln_type == "header_injection":
            # Similar to CRLF but broader
            if "\r\n" in payload or "%0d%0a" in payload.lower():
                for hdr_name in ["X-Injected", "X-Custom"]:
                    if test_headers.get(hdr_name) or test_headers.get(hdr_name.lower()):
                        return True, f"Header injection: {hdr_name} injected via payload"
            return False, None

        # ---- Expression Language Injection ----
        if vuln_type == "expression_language_injection":
            for pat in self._compiled_el_errors:
                m = pat.search(test_body)
                if m:
                    return True, f"EL error induced: {m.group()}"
            # Check for EL evaluation (similar to SSTI)
            for expr, result in SSTI_EVALUATIONS.items():
                if expr in payload and result in test_body and expr not in test_body:
                    return True, f"EL expression evaluated: {expr}={result}"
            return False, None

        # ---- Log Injection ----
        if vuln_type == "log_injection":
            # Check for injected log line content reflected back
            log_markers = ["INJECTED_LOG_ENTRY", "FAKE_ADMIN_LOGIN", "log-injection-test"]
            for marker in log_markers:
                if marker in payload and marker in test_body:
                    return True, f"Log injection: Marker '{marker}' reflected in response"
            return False, None

        # ---- HTML Injection ----
        if vuln_type == "html_injection":
            payload_lower = payload.lower()
            # Check for unescaped HTML tags reflected
            html_tags = ["<h1", "<div", "<marquee", "<b>", "<u>", "<font", "<form"]
            for tag in html_tags:
                if tag in payload_lower and tag in body_lower:
                    # Verify not HTML-encoded
                    escaped = tag.replace("<", "&lt;")
                    if escaped not in body_lower:
                        # Require tag is NOT already present in baseline (pre-existing)
                        if baseline_lower and tag in baseline_lower:
                            continue  # Tag exists in baseline — not injected
                        return True, f"HTML injection: Tag {tag} reflected unescaped (not in baseline)"
            return False, None

        # ---- CSV Injection ----
        if vuln_type == "csv_injection":
            csv_prefixes = ["=CMD", "=HYPERLINK", "+CMD", "-CMD", "@SUM"]
            content_type = test_headers.get("Content-Type", test_headers.get("content-type", ""))
            if "csv" in content_type.lower() or "spreadsheet" in content_type.lower():
                for prefix in csv_prefixes:
                    if prefix in payload and prefix in test_body:
                        return True, f"CSV injection: Formula '{prefix}' in CSV output"
            return False, None

        # ---- GraphQL Injection ----
        if vuln_type == "graphql_injection":
            for pat in self._compiled_graphql_errors:
                m = pat.search(test_body)
                if m:
                    return True, f"GraphQL error: {m.group()}"
            return False, None

        # ---- ORM Injection ----
        if vuln_type == "orm_injection":
            orm_errors = [
                r"hibernate.*exception", r"sequelize.*error", r"typeorm.*error",
                r"ActiveRecord.*(?:Statement)?Invalid", r"django\.db.*error",
                r"prisma.*error", r"sqlalchemy.*error",
            ]
            for pat_str in orm_errors:
                if re.search(pat_str, test_body, re.IGNORECASE):
                    return True, f"ORM error induced: {pat_str}"
            return False, None

        # ---- Blind XSS ----
        if vuln_type == "blind_xss":
            # Blind XSS payloads typically use external callbacks
            # We can only detect if the payload was stored (reflected later)
            if payload.lower() in body_lower:
                if "src=" in payload.lower() or "onerror=" in payload.lower():
                    # Require payload NOT already in baseline
                    if baseline_lower and payload.lower() in baseline_lower:
                        return False, None
                    return True, "Blind XSS payload stored in response"
            return False, None

        # ---- Mutation XSS ----
        if vuln_type == "mutation_xss":
            # mXSS exploits browser HTML parsing mutations
            mxss_markers = ["<svg", "<math", "<xmp", "<noembed", "<listing"]
            for marker in mxss_markers:
                if marker in payload.lower() and marker in body_lower:
                    # Require element NOT already in baseline
                    if baseline_lower and marker in baseline_lower:
                        continue
                    return True, f"Mutation XSS: Mutatable element {marker} reflected (not in baseline)"
            return False, None

        # ---- RFI ----
        if vuln_type == "rfi":
            rfi_indicators = ["<?php", "<%", "#!/", "import os"]
            for indicator in rfi_indicators:
                if indicator.lower() in body_lower:
                    return True, f"RFI: Remote file content marker: {indicator}"
            return False, None

        # ---- File Upload ----
        if vuln_type == "file_upload":
            upload_success = [
                r"(?:file|upload).*(?:success|saved|stored|created)",
                r"(?:uploaded|saved) to.*(?:\/|\\)",
            ]
            for pat_str in upload_success:
                if re.search(pat_str, body_lower):
                    return True, f"File upload succeeded: {pat_str}"
            return False, None

        # ---- Arbitrary File Read ----
        if vuln_type == "arbitrary_file_read":
            for marker in FILE_CONTENT_MARKERS:
                if marker.lower() in body_lower:
                    return True, f"Arbitrary file read: {marker}"
            return False, None

        # ---- Arbitrary File Delete ----
        if vuln_type == "arbitrary_file_delete":
            delete_indicators = [
                r"(?:file|resource).*(?:deleted|removed|not found after)",
                r"successfully.*(?:deleted|removed)",
            ]
            for pat_str in delete_indicators:
                if re.search(pat_str, body_lower):
                    return True, f"File delete confirmed: {pat_str}"
            return False, None

        # ---- Zip Slip ----
        if vuln_type == "zip_slip":
            zip_indicators = [
                r"extracted to.*/\.\./",
                r"path traversal.*(?:zip|archive)",
            ]
            for pat_str in zip_indicators:
                if re.search(pat_str, body_lower):
                    return True, f"Zip slip: {pat_str}"
            for marker in FILE_CONTENT_MARKERS:
                if marker.lower() in body_lower:
                    return True, f"Zip slip - file overwrite evidence: {marker}"
            return False, None

        # ---- JWT Manipulation ----
        if vuln_type == "jwt_manipulation":
            # Tampered JWT accepted — require auth markers NOT in baseline
            if test_status == 200 and ("alg" in payload.lower() or "none" in payload.lower()):
                jwt_auth_markers = ["authorized", "welcome", "admin"]
                for marker in jwt_auth_markers:
                    if marker in body_lower:
                        # If baseline also has this marker, it's normal behavior
                        if baseline_lower and marker in baseline_lower:
                            continue
                        return True, f"JWT manipulation: Tampered token granted access ({marker} not in baseline)"
            return False, None

        # ---- Prototype Pollution ----
        if vuln_type == "prototype_pollution":
            if "__proto__" in payload or "constructor" in payload:
                pollution_markers = ["polluted", "__proto__", "isAdmin", "true"]
                match_count = sum(1 for m in pollution_markers if m.lower() in body_lower)
                if match_count >= 2:
                    return True, "Prototype pollution: Injected properties reflected"
            return False, None

        # ---- Host Header Injection ----
        if vuln_type == "host_header_injection":
            # Check if injected host is reflected in response
            evil_hosts = ["evil.com", "attacker.com", "injected.host"]
            for host in evil_hosts:
                if host in payload and host in body_lower:
                    return True, f"Host header injection: {host} reflected in response"
            # Password reset poisoning
            if "evil.com" in payload:
                if "reset" in body_lower or "password" in body_lower:
                    if "evil.com" in body_lower:
                        return True, "Host header injection: Evil host in password reset link"
            return False, None

        # ---- HTTP Smuggling ----
        if vuln_type == "http_smuggling":
            smuggling_indicators = [
                test_status == 400 and "transfer-encoding" in payload.lower(),
                "unrecognized transfer-coding" in body_lower,
                "request smuggling" in body_lower,
            ]
            if any(smuggling_indicators):
                return True, "HTTP smuggling: Desync indicators detected"
            return False, None

        # ---- Cache Poisoning ----
        if vuln_type == "cache_poisoning":
            # Check if injected value appears in cached response
            cache_headers = ["X-Cache", "CF-Cache-Status", "Age", "X-Cache-Hit"]
            is_cached = any(
                test_headers.get(h, test_headers.get(h.lower(), ""))
                for h in cache_headers
            )
            if is_cached and payload.lower() in body_lower:
                return True, "Cache poisoning: Payload reflected in cached response"
            return False, None

        # ---- Insecure Deserialization ----
        if vuln_type == "insecure_deserialization":
            for pat in self._compiled_deser_errors:
                m = pat.search(test_body)
                if m:
                    return True, f"Deserialization error: {m.group()}"
            # Check for command execution via deser
            for pat in self._compiled_cmd_markers:
                m = pat.search(test_body)
                if m:
                    return True, f"Deserialization RCE: {m.group()}"
            return False, None

        # ---- Parameter Pollution ----
        if vuln_type == "parameter_pollution":
            # HPP only confirmed if response DIFFERS significantly from baseline
            if "&" in payload and baseline_body:
                len_diff = abs(len(test_body) - len(baseline_body))
                len_pct = (len_diff / max(len(baseline_body), 1)) * 100
                status_diff = test_status != baseline_status
                if len_pct > 20 or status_diff:
                    return True, f"Parameter pollution: Response differs from baseline (delta {len_diff} chars, {len_pct:.0f}%)"
            return False, None

        # ---- Type Juggling ----
        if vuln_type == "type_juggling":
            if test_status == 200:
                if "0" in payload or "true" in payload.lower() or "[]" in payload:
                    auth_markers = ["authenticated", "authorized", "welcome", "admin", "success"]
                    for marker in auth_markers:
                        if marker in body_lower:
                            # Require marker NOT in baseline — otherwise it's normal behavior
                            if baseline_lower and marker in baseline_lower:
                                continue
                            return True, f"Type juggling: Auth bypass ({marker} appears only with juggled type)"
            return False, None

        # ---- SOAP Injection ----
        if vuln_type == "soap_injection":
            soap_errors = [
                r"soap.*(?:fault|error|exception)",
                r"xml.*(?:parse|syntax).*error",
                r"<faultcode>",
                r"<faultstring>",
            ]
            for pat_str in soap_errors:
                if re.search(pat_str, body_lower):
                    return True, f"SOAP injection: {pat_str}"
            return False, None

        # ---- Subdomain Takeover ----
        if vuln_type == "subdomain_takeover":
            takeover_markers = [
                "there isn't a github pages site here",
                "herokucdn.com/error-pages",
                "the request could not be satisfied",
                "no such app",
                "project not found",
                "this page is parked free",
                "does not exist in the app platform",
                "NoSuchBucket",
            ]
            for marker in takeover_markers:
                if marker.lower() in body_lower:
                    return True, f"Subdomain takeover: {marker}"
            return False, None

        return False, None

    # ------------------------------------------------------------------
    # Multi-signal verification (core method)
    # ------------------------------------------------------------------

    def multi_signal_verify(
        self,
        vuln_type: str,
        payload: str,
        test_response: dict,
        baseline: Optional[dict],
        tester_result: Tuple[bool, float, Optional[str]],
    ) -> Tuple[bool, str, int]:
        """
        Combine 4 signals to determine if a vulnerability is confirmed.

        Args:
            vuln_type: Vulnerability type (registry key or legacy name)
            payload: The payload used
            test_response: The HTTP response from the payload test
            baseline: Cached baseline response (can be None)
            tester_result: (is_vuln, confidence, evidence) from VulnEngine tester

        Returns:
            (is_confirmed, evidence_summary, signal_count)
        """
        signals: List[str] = []
        evidence_parts: List[str] = []
        max_confidence = 0.0

        test_body = test_response.get("body", "")
        test_status = test_response.get("status", 0)
        test_headers = test_response.get("headers", {})

        # --- Signal 1: VulnEngine tester pattern match ---
        tester_vuln, tester_conf, tester_evidence = tester_result
        if tester_vuln and tester_conf >= 0.7:
            signals.append("tester_match")
            evidence_parts.append(tester_evidence or "Pattern match")
            max_confidence = max(max_confidence, tester_conf)

        # --- Signal 2: Baseline diff ---
        if baseline:
            diff = self.compute_response_diff(baseline, test_response)

            # Type-specific diff thresholds
            significant_diff = False
            if vuln_type in ("sqli", "sqli_error", "sqli_blind"):
                significant_diff = diff["length_diff"] > 300 and diff["status_changed"]
            elif vuln_type in ("lfi", "path_traversal", "xxe"):
                significant_diff = diff["length_diff_pct"] > 50
            elif vuln_type in ("ssti", "command_injection", "rce"):
                significant_diff = diff["body_hash_changed"] and diff["length_diff"] > 100
            else:
                significant_diff = diff["status_changed"] and diff["length_diff"] > 500

            if significant_diff:
                signals.append("baseline_diff")
                evidence_parts.append(
                    f"Response diff: status {diff['baseline_status']}->{diff['test_status']}, "
                    f"length delta {diff['length_diff']} ({diff['length_diff_pct']}%)"
                )

            # New error patterns is an independent sub-signal
            if diff["new_error_patterns"]:
                signals.append("new_errors")
                evidence_parts.append(
                    f"New error patterns: {', '.join(diff['new_error_patterns'][:3])}"
                )

        # --- Signal 3: Payload effect ---
        baseline_body = baseline.get("body", "") if baseline else ""
        baseline_status = baseline.get("status", 0) if baseline else 0
        effect_found, effect_evidence = self._check_payload_effect(
            vuln_type, payload, test_body, test_status, test_headers,
            baseline_body=baseline_body, baseline_status=baseline_status
        )
        if effect_found:
            signals.append("payload_effect")
            evidence_parts.append(effect_evidence)

        # --- Confidence rules ---
        signal_count = len(signals)
        evidence_summary = " | ".join(evidence_parts) if evidence_parts else ""

        if signal_count >= 2:
            # 2+ signals → confirmed (skip AI)
            return True, evidence_summary, signal_count
        elif signal_count == 1 and max_confidence >= 0.8:
            # 1 signal + high confidence → confirmed
            return True, evidence_summary, signal_count
        elif signal_count == 1:
            # 1 signal + lower confidence → needs AI confirmation
            # Return False but with evidence so caller can decide to ask AI
            return False, evidence_summary, signal_count
        else:
            # 0 signals → rejected
            return False, "", 0
