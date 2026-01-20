"""
NeuroSploit v3 - Base Vulnerability Tester

Base class for all vulnerability testers.
"""
from typing import Tuple, Dict, List, Optional, Any
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


class BaseTester:
    """Base class for vulnerability testers"""

    def __init__(self):
        self.name = "base"

    def build_request(
        self,
        endpoint,
        payload: str
    ) -> Tuple[str, Dict, Dict, Optional[str]]:
        """
        Build a test request with the payload.

        Returns:
            Tuple of (url, params, headers, body)
        """
        url = endpoint.url
        params = {}
        headers = {"User-Agent": "NeuroSploit/3.0"}
        body = None

        # Inject payload into parameters if endpoint has them
        if endpoint.parameters:
            for param in endpoint.parameters:
                param_name = param.get("name", param) if isinstance(param, dict) else param
                params[param_name] = payload
        else:
            # Try to inject into URL query string
            parsed = urlparse(url)
            if parsed.query:
                query_params = parse_qs(parsed.query)
                for key in query_params:
                    query_params[key] = [payload]
                new_query = urlencode(query_params, doseq=True)
                url = urlunparse(parsed._replace(query=new_query))
            else:
                # Add as query parameter
                params["test"] = payload

        return url, params, headers, body

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """
        Analyze response to determine if vulnerable.

        Returns:
            Tuple of (is_vulnerable, confidence, evidence)
        """
        return False, 0.0, None

    def check_timeout_vulnerability(self, vuln_type: str) -> bool:
        """Check if timeout indicates vulnerability for this type"""
        return False

    def get_injection_points(self, endpoint) -> List[Dict]:
        """Get all injection points for an endpoint"""
        points = []

        # URL parameters
        if endpoint.parameters:
            for param in endpoint.parameters:
                param_name = param.get("name", param) if isinstance(param, dict) else param
                points.append({
                    "type": "parameter",
                    "name": param_name,
                    "location": "query"
                })

        # Parse URL for query params
        parsed = urlparse(endpoint.url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for key in query_params:
                if not any(p.get("name") == key for p in points):
                    points.append({
                        "type": "parameter",
                        "name": key,
                        "location": "query"
                    })

        # Headers that might be injectable
        injectable_headers = ["User-Agent", "Referer", "X-Forwarded-For", "Cookie"]
        for header in injectable_headers:
            points.append({
                "type": "header",
                "name": header,
                "location": "header"
            })

        return points
