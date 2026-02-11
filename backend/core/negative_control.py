"""
NeuroSploit v3 - Negative Control Engine

Sends benign/control payloads and compares responses to detect false positives
from same-behavior patterns. If the application responds the same way to a
benign value as it does to an attack payload, the finding is likely a false positive.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ControlTestResult:
    """Result of a single control test."""
    control_type: str          # "benign", "empty", "no_param"
    control_value: str         # The control payload used
    status_match: bool         # Did status code match attack response?
    length_similar: bool       # Body length within threshold?
    hash_match: bool           # Exact body match?
    same_behavior: bool        # Overall: does this control look the same?
    detail: str = ""


@dataclass
class NegativeControlResult:
    """Aggregated result of all negative control tests."""
    same_behavior: bool        # True if ANY control shows same behavior as attack
    controls_run: int          # How many controls were executed
    controls_matching: int     # How many showed same behavior
    confidence_adjustment: int  # Penalty to apply (typically -60 if same_behavior)
    results: List[ControlTestResult] = field(default_factory=list)
    detail: str = ""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class NegativeControlEngine:
    """Sends control payloads to detect false positives from same-behavior responses.

    The key insight: if the application responds identically to "test123" and
    to "<script>alert(1)</script>", then the XSS payload was NOT processed —
    the application simply ignores or sanitizes the parameter entirely.
    """

    # Benign values that should NEVER trigger a vulnerability
    BENIGN_PAYLOADS: Dict[str, List[str]] = {
        # XSS: plain text, no special chars
        "xss_reflected": ["test123", "hello world"],
        "xss_stored": ["test123", "hello world"],
        "xss_dom": ["test123", "hello world"],
        "xss": ["test123", "hello world"],

        # SQLi: normal numeric/text values
        "sqli": ["1", "test"],
        "sqli_error": ["1", "test"],
        "sqli_union": ["1", "test"],
        "sqli_blind": ["1", "test"],
        "sqli_time": ["1", "test"],

        # SSRF: safe external URL or plain text
        "ssrf": ["https://www.example.com", "test"],
        "ssrf_cloud": ["https://www.example.com", "test"],

        # LFI: safe existing page or plain text
        "lfi": ["index.html", "test.txt"],
        "path_traversal": ["index.html", "test.txt"],

        # SSTI: plain text, no template syntax
        "ssti": ["hello", "12345"],

        # RCE: plain text, no shell metacharacters
        "rce": ["test", "hello"],
        "command_injection": ["test", "hello"],

        # Open redirect: safe internal URL
        "open_redirect": ["/", "/index.html"],

        # CRLF: normal header value
        "crlf_injection": ["test-value", "normal"],
        "header_injection": ["test-value", "normal"],

        # XXE: plain text (no XML entities)
        "xxe": ["test", "hello"],

        # NoSQL: normal value
        "nosql_injection": ["test", "1"],

        # Host header: normal hostname
        "host_header_injection": ["localhost", "example.com"],

        # Default for any unlisted type
        "default": ["test123", "benign_value"],
    }

    # Body length similarity threshold (percentage)
    LENGTH_THRESHOLD_PCT = 5.0  # Within 5% = "same"

    async def run_controls(
        self,
        url: str,
        param: str,
        method: str,
        vuln_type: str,
        attack_response: Dict,
        make_request_fn: Callable,
        baseline: Optional[Dict] = None,
        injection_point: str = "parameter",
    ) -> NegativeControlResult:
        """Run negative control tests and compare with the attack response.

        Args:
            url: Target URL
            param: Parameter name being tested
            method: HTTP method
            vuln_type: Vulnerability type
            attack_response: The response from the attack payload
            make_request_fn: Async function to make HTTP requests
            baseline: Optional baseline response
            injection_point: Where payload is injected (parameter, header, body, path)

        Returns:
            NegativeControlResult with same_behavior flag and details
        """
        results: List[ControlTestResult] = []
        controls_matching = 0

        attack_status = attack_response.get("status", 0)
        attack_body = attack_response.get("body", "")
        attack_length = len(attack_body)
        attack_hash = hashlib.md5(
            attack_body.encode("utf-8", errors="replace")
        ).hexdigest()

        # Get benign payloads for this vuln type
        base_type = vuln_type.split("_")[0] if "_" in vuln_type else vuln_type
        benign_values = self.BENIGN_PAYLOADS.get(
            vuln_type,
            self.BENIGN_PAYLOADS.get(base_type, self.BENIGN_PAYLOADS["default"])
        )

        # Control 1: Benign payload
        for benign in benign_values[:2]:
            try:
                control_resp = await self._send_control(
                    url, param, method, benign, make_request_fn, injection_point
                )
                if control_resp:
                    result = self._compare_responses(
                        "benign", benign, attack_status, attack_length,
                        attack_hash, control_resp
                    )
                    results.append(result)
                    if result.same_behavior:
                        controls_matching += 1
            except Exception as e:
                logger.debug(f"Negative control (benign) failed: {e}")

        # Control 2: Empty value
        try:
            control_resp = await self._send_control(
                url, param, method, "", make_request_fn, injection_point
            )
            if control_resp:
                result = self._compare_responses(
                    "empty", "", attack_status, attack_length,
                    attack_hash, control_resp
                )
                results.append(result)
                if result.same_behavior:
                    controls_matching += 1
        except Exception as e:
            logger.debug(f"Negative control (empty) failed: {e}")

        # Control 3: Request without the parameter entirely (if applicable)
        if injection_point == "parameter" and param:
            try:
                control_resp = await self._send_without_param(
                    url, param, method, make_request_fn
                )
                if control_resp:
                    result = self._compare_responses(
                        "no_param", "(omitted)", attack_status, attack_length,
                        attack_hash, control_resp
                    )
                    results.append(result)
                    if result.same_behavior:
                        controls_matching += 1
            except Exception as e:
                logger.debug(f"Negative control (no_param) failed: {e}")

        # Determine overall same_behavior
        controls_run = len(results)
        same_behavior = controls_matching > 0

        # Build detail string
        if same_behavior:
            matching_types = [r.control_type for r in results if r.same_behavior]
            detail = (f"NEGATIVE CONTROL FAILED: {controls_matching}/{controls_run} "
                     f"controls show same behavior as attack ({', '.join(matching_types)})")
        else:
            detail = f"Negative controls passed: 0/{controls_run} controls match attack response"

        return NegativeControlResult(
            same_behavior=same_behavior,
            controls_run=controls_run,
            controls_matching=controls_matching,
            confidence_adjustment=-60 if same_behavior else 20,
            results=results,
            detail=detail,
        )

    async def _send_control(
        self,
        url: str,
        param: str,
        method: str,
        value: str,
        make_request_fn: Callable,
        injection_point: str,
    ) -> Optional[Dict]:
        """Send a control request with the given value."""
        if injection_point == "parameter":
            return await make_request_fn(url, method, {param: value})
        elif injection_point == "header":
            # For header injection, we'd need to pass custom headers
            # Fall back to parameter injection for control testing
            return await make_request_fn(url, method, {param: value})
        elif injection_point == "path":
            # For path injection, append benign value to path
            parsed = urlparse(url)
            control_url = urlunparse(parsed._replace(
                path=parsed.path.rstrip("/") + "/" + value
            ))
            return await make_request_fn(control_url, method, {})
        elif injection_point == "body":
            return await make_request_fn(url, method, {param: value})
        else:
            return await make_request_fn(url, method, {param: value})

    async def _send_without_param(
        self,
        url: str,
        param: str,
        method: str,
        make_request_fn: Callable,
    ) -> Optional[Dict]:
        """Send request without the tested parameter."""
        # Strip the param from URL query string if present
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            params.pop(param, None)
            new_query = urlencode(params, doseq=True)
            clean_url = urlunparse(parsed._replace(query=new_query))
        else:
            clean_url = url

        return await make_request_fn(clean_url, method, {})

    def _compare_responses(
        self,
        control_type: str,
        control_value: str,
        attack_status: int,
        attack_length: int,
        attack_hash: str,
        control_response: Dict,
    ) -> ControlTestResult:
        """Compare a control response against the attack response."""
        control_status = control_response.get("status", 0)
        control_body = control_response.get("body", "")
        control_length = len(control_body)
        control_hash = hashlib.md5(
            control_body.encode("utf-8", errors="replace")
        ).hexdigest()

        # Status code match
        status_match = (attack_status == control_status)

        # Body hash exact match
        hash_match = (attack_hash == control_hash)

        # Body length similarity
        if attack_length == 0 and control_length == 0:
            length_similar = True
        elif attack_length == 0 or control_length == 0:
            length_similar = False
        else:
            diff_pct = abs(attack_length - control_length) / max(attack_length, 1) * 100
            length_similar = diff_pct <= self.LENGTH_THRESHOLD_PCT

        # Same behavior if status matches AND (exact hash match OR length similar)
        same_behavior = status_match and (hash_match or length_similar)

        detail = (f"{control_type}('{control_value[:30]}'): "
                 f"status {'=' if status_match else '!'}= {control_status}, "
                 f"len {control_length} "
                 f"({'same' if length_similar else 'different'} from {attack_length})"
                 f"{', EXACT MATCH' if hash_match else ''}")

        return ControlTestResult(
            control_type=control_type,
            control_value=control_value[:50],
            status_match=status_match,
            length_similar=length_similar,
            hash_match=hash_match,
            same_behavior=same_behavior,
            detail=detail,
        )
