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


class GraphqlIntrospectionTester(BaseTester):
    """Tester for GraphQL Introspection exposure"""

    def __init__(self):
        super().__init__()
        self.name = "graphql_introspection"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for __schema data in response indicating introspection is enabled"""
        if response_status == 200:
            # Direct __schema indicators
            schema_patterns = [
                r'"__schema"\s*:\s*\{',
                r'"__type"\s*:\s*\{',
                r'"queryType"\s*:\s*\{',
                r'"mutationType"\s*:\s*\{',
                r'"subscriptionType"\s*:',
                r'"types"\s*:\s*\[.*"name"\s*:\s*"__',
                r'"directives"\s*:\s*\[.*"name"\s*:',
            ]

            for pattern in schema_patterns:
                if re.search(pattern, response_body, re.IGNORECASE | re.DOTALL):
                    return True, 0.9, "GraphQL introspection: Full schema exposed via __schema query"

            # Check for type listings
            type_listing_patterns = [
                r'"kind"\s*:\s*"(?:OBJECT|SCALAR|ENUM|INPUT_OBJECT|INTERFACE|UNION)"',
                r'"fields"\s*:\s*\[.*"name"\s*:.*"type"\s*:',
                r'"inputFields"\s*:\s*\[',
                r'"enumValues"\s*:\s*\[',
            ]

            type_match_count = sum(
                1 for p in type_listing_patterns
                if re.search(p, response_body, re.IGNORECASE | re.DOTALL)
            )
            if type_match_count >= 2:
                return True, 0.85, "GraphQL introspection: Type schema data exposed"

            # Check for field suggestions (partial introspection)
            if re.search(r'"(?:message|errors)".*"Did you mean.*"', response_body):
                return True, 0.6, "GraphQL introspection: Field suggestions leak schema information"

        return False, 0.0, None


class GraphqlDosTester(BaseTester):
    """Tester for GraphQL Denial of Service via deeply nested queries"""

    def __init__(self):
        super().__init__()
        self.name = "graphql_dos"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for slow response with deeply nested queries indicating DoS potential"""
        # Check response time for nested query DoS
        response_time_ms = context.get("response_time_ms", 0)

        # Nested query indicators in payload
        nesting_indicators = [
            payload.count("{") > 5,
            "__typename" in payload and payload.count("__typename") > 3,
            "fragment" in payload.lower() and "..." in payload,
        ]
        is_nested_payload = any(nesting_indicators)

        if is_nested_payload:
            # Very slow response indicates resource exhaustion
            if response_time_ms > 10000:  # > 10 seconds
                return True, 0.85, f"GraphQL DoS: Deeply nested query caused {response_time_ms}ms response time"

            if response_time_ms > 5000:  # > 5 seconds
                return True, 0.7, f"GraphQL DoS: Nested query caused slow response ({response_time_ms}ms)"

        # Check for timeout/error responses
        if response_status in [408, 504, 502]:
            if is_nested_payload:
                return True, 0.8, "GraphQL DoS: Server timeout on deeply nested query"

        # Check for resource limit errors (server has some protection but confirms issue)
        resource_errors = [
            r"query.*(?:too complex|too deep|exceeds.*(?:depth|complexity))",
            r"max.*(?:depth|complexity).*(?:exceeded|reached)",
            r"(?:depth|complexity)\s+limit",
            r"query.*(?:cost|weight).*exceeded",
        ]
        for pattern in resource_errors:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.5, "GraphQL DoS: Depth/complexity limits exist but confirm nested queries are processed"

        # Server error on complex query
        if response_status == 500 and is_nested_payload:
            return True, 0.65, "GraphQL DoS: Server error on deeply nested query"

        return False, 0.0, None
