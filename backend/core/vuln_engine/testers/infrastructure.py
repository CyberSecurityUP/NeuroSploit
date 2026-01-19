"""
NeuroSploit v3 - Infrastructure Vulnerability Testers

Testers for Security Headers, SSL/TLS, HTTP Methods
"""
import re
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class SecurityHeadersTester(BaseTester):
    """Tester for Missing Security Headers"""

    def __init__(self):
        super().__init__()
        self.name = "security_headers"
        self.required_headers = {
            "Strict-Transport-Security": "HSTS not configured",
            "X-Content-Type-Options": "X-Content-Type-Options not set",
            "X-Frame-Options": "X-Frame-Options not set",
            "Content-Security-Policy": "CSP not configured",
            "X-XSS-Protection": "X-XSS-Protection not set (legacy but still useful)",
            "Referrer-Policy": "Referrer-Policy not configured"
        }

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for missing security headers"""
        missing = []
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        for header, message in self.required_headers.items():
            if header.lower() not in headers_lower:
                missing.append(message)

        # Check for weak CSP
        csp = headers_lower.get("content-security-policy", "")
        if csp:
            weak_csp = []
            if "unsafe-inline" in csp:
                weak_csp.append("unsafe-inline")
            if "unsafe-eval" in csp:
                weak_csp.append("unsafe-eval")
            if "*" in csp:
                weak_csp.append("wildcard sources")
            if weak_csp:
                missing.append(f"Weak CSP: {', '.join(weak_csp)}")

        if missing:
            confidence = min(0.3 + len(missing) * 0.1, 0.8)
            return True, confidence, f"Missing/weak headers: {'; '.join(missing[:3])}"

        return False, 0.0, None


class SSLTester(BaseTester):
    """Tester for SSL/TLS Issues"""

    def __init__(self):
        super().__init__()
        self.name = "ssl_issues"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for SSL/TLS issues"""
        issues = []

        # Check HSTS
        hsts = response_headers.get("Strict-Transport-Security", "")
        if not hsts:
            issues.append("HSTS not enabled")
        else:
            # Check HSTS max-age
            max_age_match = re.search(r'max-age=(\d+)', hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # Less than 1 year
                    issues.append(f"HSTS max-age too short: {max_age}s")

            if "includeSubDomains" not in hsts:
                issues.append("HSTS missing includeSubDomains")

        # Check for HTTP resources on HTTPS page
        if "https://" in (context.get("url", "") or ""):
            http_resources = re.findall(r'(?:src|href)=["\']http://[^"\']+', response_body)
            if http_resources:
                issues.append(f"Mixed content: {len(http_resources)} HTTP resources")

        if issues:
            return True, 0.6, f"SSL/TLS issues: {'; '.join(issues)}"

        return False, 0.0, None


class HTTPMethodsTester(BaseTester):
    """Tester for Dangerous HTTP Methods"""

    def __init__(self):
        super().__init__()
        self.name = "http_methods"
        self.dangerous_methods = ["TRACE", "TRACK", "PUT", "DELETE", "CONNECT"]

    def build_request(self, endpoint, payload: str) -> Tuple[str, Dict, Dict, Optional[str]]:
        """Build OPTIONS request to check allowed methods"""
        headers = {
            "User-Agent": "NeuroSploit/3.0"
        }
        # payload is the HTTP method to test
        return endpoint.url, {}, headers, None

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for dangerous HTTP methods"""
        # Check Allow header from OPTIONS response
        allow = response_headers.get("Allow", "")
        dangerous_found = []

        for method in self.dangerous_methods:
            if method in allow.upper():
                dangerous_found.append(method)

        # TRACE method enables XST attacks
        if "TRACE" in dangerous_found or "TRACK" in dangerous_found:
            return True, 0.7, f"Dangerous methods enabled: {', '.join(dangerous_found)} (XST risk)"

        if dangerous_found:
            return True, 0.5, f"Potentially dangerous methods: {', '.join(dangerous_found)}"

        # Check if specific method test succeeded
        if payload.upper() in self.dangerous_methods:
            if response_status == 200:
                return True, 0.6, f"{payload} method accepted"

        return False, 0.0, None
