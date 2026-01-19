"""
NeuroSploit v3 - Request Forgery Vulnerability Testers

Testers for SSRF and CSRF
"""
import re
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class SSRFTester(BaseTester):
    """Tester for Server-Side Request Forgery"""

    def __init__(self):
        super().__init__()
        self.name = "ssrf"
        # Cloud metadata indicators
        self.cloud_indicators = [
            r"ami-[a-z0-9]+",  # AWS AMI ID
            r"instance-id",
            r"iam/security-credentials",
            r"compute/v1",  # GCP
            r"metadata/instance",
            r"169\.254\.169\.254"
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for SSRF indicators"""
        # Check for cloud metadata
        for pattern in self.cloud_indicators:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.95, f"SSRF to cloud metadata: {pattern}"

        # Check for internal service indicators
        internal_indicators = [
            r"localhost",
            r"127\.0\.0\.1",
            r"192\.168\.\d+\.\d+",
            r"10\.\d+\.\d+\.\d+",
            r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
        ]
        for pattern in internal_indicators:
            if pattern in payload and re.search(pattern, response_body):
                return True, 0.8, f"SSRF accessing internal resource: {pattern}"

        # Check for different response when internal URL requested
        if response_status == 200 and len(response_body) > 100:
            if "169.254" in payload or "localhost" in payload or "127.0.0.1" in payload:
                return True, 0.6, "Response received from internal URL - possible SSRF"

        return False, 0.0, None


class CSRFTester(BaseTester):
    """Tester for Cross-Site Request Forgery"""

    def __init__(self):
        super().__init__()
        self.name = "csrf"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for CSRF vulnerability indicators"""
        # Check for missing CSRF protections
        csrf_protections = [
            r'name=["\']?csrf',
            r'name=["\']?_token',
            r'name=["\']?authenticity_token',
            r'X-CSRF-TOKEN',
            r'X-XSRF-TOKEN'
        ]

        has_protection = any(
            re.search(pattern, response_body, re.IGNORECASE)
            for pattern in csrf_protections
        )

        # Check SameSite cookie
        has_samesite = "samesite" in str(response_headers).lower()

        # State-changing request without protection
        if not has_protection and not has_samesite:
            if response_status in [200, 302]:
                return True, 0.7, "No CSRF token found in form - possible CSRF"

        return False, 0.0, None
