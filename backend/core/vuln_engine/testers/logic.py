"""
NeuroSploit v3 - Logic and Protocol Vulnerability Testers

Testers for race conditions, business logic, rate limiting, parameter pollution,
type juggling, timing attacks, host header injection, HTTP smuggling, cache poisoning.
"""
import re
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class RaceConditionTester(BaseTester):
    """Tester for Race Condition vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "race_condition"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for duplicate operation success indicators"""
        body_lower = response_body.lower()

        # Multiple success responses from concurrent requests
        if context.get("concurrent_successes", 0) > 1:
            return True, 0.85, f"Race condition: {context['concurrent_successes']} concurrent requests succeeded"

        # Double-spend / duplicate operation indicators
        duplicate_indicators = [
            "already processed", "duplicate", "already exists",
            "already applied", "already redeemed",
        ]
        # If we got a success despite expected duplicate check
        if response_status in [200, 201]:
            success_words = ["success", "created", "processed", "applied", "completed", "confirmed"]
            if any(w in body_lower for w in success_words):
                if context.get("request_count", 0) > 1:
                    return True, 0.7, "Race condition: operation succeeded multiple times"

        # Check for resource count discrepancy
        if "balance" in body_lower or "quantity" in body_lower or "count" in body_lower:
            numbers = re.findall(r'"(?:balance|quantity|count|amount)"\s*:\s*(-?\d+\.?\d*)', response_body)
            if numbers and context.get("expected_value") is not None:
                try:
                    actual = float(numbers[0])
                    expected = float(context["expected_value"])
                    if actual != expected:
                        return True, 0.75, f"Race condition: value mismatch (expected {expected}, got {actual})"
                except (ValueError, IndexError):
                    pass

        return False, 0.0, None


class BusinessLogicTester(BaseTester):
    """Tester for Business Logic vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "business_logic"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for business logic bypass indicators"""
        body_lower = response_body.lower()

        # Negative value acceptance
        if re.search(r"-\d+", payload):
            if response_status == 200:
                if any(w in body_lower for w in ["success", "accepted", "processed", "approved"]):
                    return True, 0.8, "Business logic: negative value accepted"
                # Check for negative pricing
                if re.search(r'"(?:total|price|amount)"\s*:\s*-\d+', response_body):
                    return True, 0.9, "Business logic: negative price/amount in response"

        # Zero-value bypass
        if payload.strip() in ["0", "0.00", "0.0"]:
            if response_status == 200 and "success" in body_lower:
                return True, 0.75, "Business logic: zero value accepted for transaction"

        # Workflow step skip
        if context.get("skipped_step"):
            if response_status == 200:
                return True, 0.7, f"Business logic: step '{context['skipped_step']}' was skippable"

        # Discount/coupon abuse
        if "coupon" in payload.lower() or "discount" in payload.lower():
            if re.search(r'"discount"\s*:\s*(?:100|[1-9]\d{2,})', response_body):
                return True, 0.8, "Business logic: excessive discount applied"

        # Role/privilege escalation via parameter
        if any(w in payload.lower() for w in ["admin", "role=admin", "is_admin=true", "privilege"]):
            if response_status == 200 and "admin" in body_lower:
                return True, 0.6, "Business logic: privilege escalation parameter accepted"

        return False, 0.0, None


class RateLimitBypassTester(BaseTester):
    """Tester for Rate Limit Bypass vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "rate_limit_bypass"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for continued success after many requests (bypass)"""
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        # After many requests, still getting 200
        request_count = context.get("request_count", 0)
        if request_count > 50 and response_status == 200:
            # Check rate limit headers
            remaining = headers_lower.get("x-ratelimit-remaining",
                        headers_lower.get("x-rate-limit-remaining",
                        headers_lower.get("ratelimit-remaining")))
            if remaining is not None:
                try:
                    if int(remaining) > 0:
                        return True, 0.6, f"Rate limit not enforced after {request_count} requests (remaining: {remaining})"
                except ValueError:
                    pass
            else:
                # No rate limit headers at all
                return True, 0.7, f"No rate limiting detected after {request_count} requests"

        # Rate limit bypass via header manipulation
        bypass_headers = ["x-forwarded-for", "x-real-ip", "x-originating-ip", "x-client-ip"]
        if any(h in payload.lower() for h in bypass_headers):
            if response_status == 200 and context.get("was_rate_limited"):
                return True, 0.85, "Rate limit bypassed via IP spoofing header"

        # Check if 429 was expected but got 200
        if context.get("expected_429") and response_status == 200:
            return True, 0.8, "Expected 429 (rate limited) but received 200"

        return False, 0.0, None


class ParameterPollutionTester(BaseTester):
    """Tester for HTTP Parameter Pollution vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "parameter_pollution"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for different behavior with duplicate parameters"""
        # Compare response with baseline (single param)
        if "baseline_body" in context and "baseline_status" in context:
            baseline_len = len(context["baseline_body"])
            current_len = len(response_body)
            diff = abs(current_len - baseline_len)

            # Significant response difference
            if diff > 200:
                return True, 0.7, f"Parameter pollution: response differs by {diff} bytes from baseline"

            # Status code difference
            if response_status != context["baseline_status"]:
                return True, 0.75, f"Parameter pollution: status changed from {context['baseline_status']} to {response_status}"

        # Check if attacker-controlled value was used
        if "neurosploit" in payload and "neurosploit" in response_body:
            if context.get("original_value") and context["original_value"] not in response_body:
                return True, 0.8, "Parameter pollution: attacker value used instead of original"

        # WAF bypass via duplicate params
        if context.get("waf_blocked_original") and response_status == 200:
            return True, 0.8, "Parameter pollution: WAF bypass - blocked payload succeeded with duplicate params"

        return False, 0.0, None


class TypeJugglingTester(BaseTester):
    """Tester for Type Juggling / Type Coercion vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "type_juggling"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for auth bypass with type coercion"""
        body_lower = response_body.lower()

        # Type juggling payloads
        juggling_values = ["0", "true", "false", "null", "[]", "{}", "0e123", "0e999"]

        if payload.strip() in juggling_values or payload.strip().startswith("0e"):
            # Auth bypass
            if response_status == 200:
                auth_success = [
                    "authenticated", "logged in", "welcome", "dashboard",
                    "token", "session", "success",
                ]
                for indicator in auth_success:
                    if indicator in body_lower:
                        return True, 0.8, f"Type juggling: auth bypass with '{payload.strip()}' - '{indicator}' in response"

            # JWT/token accepted
            if "jwt" in body_lower or "bearer" in body_lower:
                if response_status == 200:
                    return True, 0.7, f"Type juggling: token accepted with value '{payload.strip()}'"

        # Magic hash comparison bypass (0e strings)
        if re.match(r"0e\d+", payload.strip()):
            if response_status == 200 and any(w in body_lower for w in ["match", "equal", "valid", "correct"]):
                return True, 0.85, f"Type juggling: magic hash bypass with '{payload.strip()}'"

        # Array vs string comparison
        if payload.strip() in ["[]", "Array"]:
            if response_status == 200 and "success" in body_lower:
                return True, 0.7, "Type juggling: array comparison bypass"

        return False, 0.0, None


class TimingAttackTester(BaseTester):
    """Tester for Timing Attack vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "timing_attack"

    def check_timeout_vulnerability(self, vuln_type: str) -> bool:
        """Timing attacks are detected via response time differences"""
        return True

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check response time differences for timing side channels"""
        # Primary detection is via response timing (handled by engine)
        response_time = context.get("response_time_ms", 0)
        baseline_time = context.get("baseline_time_ms", 0)

        if response_time > 0 and baseline_time > 0:
            diff = response_time - baseline_time
            # Significant timing difference (> 100ms)
            if diff > 100:
                return True, 0.7, f"Timing attack: {diff}ms difference (baseline: {baseline_time}ms, actual: {response_time}ms)"
            # Very significant (> 500ms)
            if diff > 500:
                return True, 0.9, f"Timing attack: {diff}ms difference strongly indicates character-by-character comparison"

        # Check for timing via multiple measurements
        if "timing_samples" in context:
            samples = context["timing_samples"]
            if len(samples) >= 2:
                max_diff = max(samples) - min(samples)
                if max_diff > 200:
                    return True, 0.65, f"Timing attack: {max_diff}ms variance across samples"

        return False, 0.0, None


class HostHeaderInjectionTester(BaseTester):
    """Tester for Host Header Injection vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "host_header_injection"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for Host value reflected in response links/URLs"""
        body_lower = response_body.lower()

        # Injected host appearing in response
        evil_hosts = ["evil.com", "attacker.com", "neurosploit.test", "canary.host"]
        for host in evil_hosts:
            if host in payload.lower() and host in body_lower:
                # High confidence if in URL context
                url_contexts = [
                    rf'https?://{re.escape(host)}',
                    rf'href\s*=\s*["\'][^"\']*{re.escape(host)}',
                    rf'action\s*=\s*["\'][^"\']*{re.escape(host)}',
                    rf'redirect.*{re.escape(host)}',
                ]
                for pattern in url_contexts:
                    if re.search(pattern, response_body, re.IGNORECASE):
                        return True, 0.9, f"Host header injection: '{host}' reflected in URL context"

                return True, 0.7, f"Host header injection: '{host}' reflected in response body"

        # X-Forwarded-Host injection
        if "x-forwarded-host" in payload.lower():
            headers_lower = {k.lower(): v for k, v in response_headers.items()}
            location = headers_lower.get("location", "")
            if any(h in location.lower() for h in evil_hosts):
                return True, 0.9, "Host header injection: X-Forwarded-Host reflected in redirect"

        # Password reset link poisoning
        if context.get("is_password_reset") and response_status == 200:
            for host in evil_hosts:
                if host in body_lower:
                    return True, 0.95, f"Host header injection in password reset: link points to '{host}'"

        return False, 0.0, None


class HttpSmugglingTester(BaseTester):
    """Tester for HTTP Request Smuggling vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "http_smuggling"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for HTTP smuggling indicators"""
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        # Response splitting - two HTTP responses in one
        if re.search(r"HTTP/\d\.\d\s+\d{3}", response_body):
            return True, 0.85, "HTTP smuggling: embedded HTTP response in body (response splitting)"

        # Conflicting Content-Length and Transfer-Encoding
        has_cl = "content-length" in headers_lower
        has_te = "transfer-encoding" in headers_lower
        if has_cl and has_te:
            return True, 0.7, "HTTP smuggling: both Content-Length and Transfer-Encoding present"

        # CL.TE or TE.CL desync indicators
        if context.get("desync_detected"):
            return True, 0.9, "HTTP smuggling: request desync confirmed"

        # Unexpected response to smuggled second request
        if "smuggle_marker" in context:
            marker = context["smuggle_marker"]
            if marker in response_body:
                return True, 0.85, f"HTTP smuggling: smuggled request marker '{marker}' in response"

        # Different status than expected (frontend vs backend disagreement)
        if context.get("expected_status") and response_status != context["expected_status"]:
            if response_status in [400, 403] and context["expected_status"] == 200:
                return True, 0.5, f"HTTP smuggling: status mismatch (expected {context['expected_status']}, got {response_status})"

        # Timeout on second request (queued/poisoned)
        if context.get("second_request_timeout"):
            return True, 0.7, "HTTP smuggling: second request timed out (possible queue poisoning)"

        return False, 0.0, None

    def check_timeout_vulnerability(self, vuln_type: str) -> bool:
        """Smuggling can cause timeouts on subsequent requests"""
        return True


class CachePoisoningTester(BaseTester):
    """Tester for Web Cache Poisoning vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "cache_poisoning"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for cache poisoning - injected content served from cache"""
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        # Check for cache hit with injected content
        cache_hit = False
        cache_headers = ["x-cache", "cf-cache-status", "x-varnish", "x-drupal-cache",
                         "x-proxy-cache", "x-cdn-cache"]
        for header in cache_headers:
            value = headers_lower.get(header, "").lower()
            if "hit" in value:
                cache_hit = True
                break

        # Age header indicates cached response
        age = headers_lower.get("age")
        if age and age != "0":
            cache_hit = True

        if cache_hit:
            # Check if our injected content is in the cached response
            injection_markers = ["neurosploit", "xss", "evil.com", "attacker"]
            for marker in injection_markers:
                if marker in payload.lower() and marker in response_body.lower():
                    return True, 0.9, f"Cache poisoning: injected content '{marker}' served from cache"

        # Unkeyed header reflected in response (potential cache poison vector)
        unkeyed_headers = ["x-forwarded-host", "x-forwarded-scheme", "x-original-url",
                           "x-rewrite-url", "x-forwarded-prefix"]
        for header in unkeyed_headers:
            if header in payload.lower():
                # Check if the value appears in response
                for marker in ["evil.com", "neurosploit", "attacker"]:
                    if marker in payload.lower() and marker in response_body.lower():
                        cache_status = "cached" if cache_hit else "uncached"
                        confidence = 0.85 if cache_hit else 0.5
                        return True, confidence, f"Cache poisoning: unkeyed header '{header}' reflected ({cache_status})"

        # Cache deception check
        if context.get("is_cache_deception_test"):
            if cache_hit and ("token" in response_body.lower() or "session" in response_body.lower()):
                return True, 0.8, "Cache deception: sensitive data cached via path confusion"

        return False, 0.0, None
