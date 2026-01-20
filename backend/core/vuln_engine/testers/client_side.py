"""
NeuroSploit v3 - Client-Side Vulnerability Testers

Testers for CORS, Clickjacking, Open Redirect
"""
import re
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class CORSTester(BaseTester):
    """Tester for CORS Misconfiguration"""

    def __init__(self):
        super().__init__()
        self.name = "cors_misconfig"

    def build_request(self, endpoint, payload: str) -> Tuple[str, Dict, Dict, Optional[str]]:
        """Build CORS test request with Origin header"""
        headers = {
            "User-Agent": "NeuroSploit/3.0",
            "Origin": payload  # payload is the test origin
        }
        return endpoint.url, {}, headers, None

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for CORS misconfiguration"""
        acao = response_headers.get("Access-Control-Allow-Origin", "")
        acac = response_headers.get("Access-Control-Allow-Credentials", "")

        # Wildcard with credentials
        if acao == "*" and acac.lower() == "true":
            return True, 0.95, "CORS: Wildcard origin with credentials allowed"

        # Origin reflection
        if acao == payload:
            if acac.lower() == "true":
                return True, 0.9, f"CORS: Arbitrary origin '{payload}' reflected with credentials"
            return True, 0.7, f"CORS: Arbitrary origin '{payload}' reflected"

        # Wildcard (without credentials still risky)
        if acao == "*":
            return True, 0.5, "CORS: Wildcard origin allowed"

        # Null origin accepted
        if acao == "null":
            return True, 0.8, "CORS: Null origin accepted"

        return False, 0.0, None


class ClickjackingTester(BaseTester):
    """Tester for Clickjacking vulnerability"""

    def __init__(self):
        super().__init__()
        self.name = "clickjacking"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for clickjacking protection"""
        # Check X-Frame-Options
        xfo = response_headers.get("X-Frame-Options", "").upper()

        # Check CSP frame-ancestors
        csp = response_headers.get("Content-Security-Policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if not xfo and not has_frame_ancestors:
            return True, 0.8, "Clickjacking: No X-Frame-Options or frame-ancestors CSP"

        if xfo and xfo not in ["DENY", "SAMEORIGIN"]:
            return True, 0.7, f"Clickjacking: Weak X-Frame-Options: {xfo}"

        # Check for JS frame busting that can be bypassed
        frame_busters = [
            r"if\s*\(\s*top\s*[!=]=",
            r"if\s*\(\s*self\s*[!=]=\s*top",
            r"if\s*\(\s*parent\s*[!=]="
        ]
        for pattern in frame_busters:
            if re.search(pattern, response_body):
                if not xfo and not has_frame_ancestors:
                    return True, 0.6, "Clickjacking: Only JS frame-busting (bypassable)"

        return False, 0.0, None


class OpenRedirectTester(BaseTester):
    """Tester for Open Redirect vulnerability"""

    def __init__(self):
        super().__init__()
        self.name = "open_redirect"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for open redirect"""
        # Check redirect status and Location header
        if response_status in [301, 302, 303, 307, 308]:
            location = response_headers.get("Location", "")

            # Check if our payload URL is in Location
            if payload in location:
                return True, 0.9, f"Open redirect: Redirecting to {location}"

            # Check for partial match (domain)
            if "evil.com" in payload and "evil.com" in location:
                return True, 0.9, "Open redirect: External domain in redirect"

        # Check for meta refresh redirect
        meta_refresh = re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=([^"\'>\s]+)',
            response_body, re.IGNORECASE
        )
        if meta_refresh:
            redirect_url = meta_refresh.group(1)
            if payload in redirect_url:
                return True, 0.8, f"Open redirect via meta refresh: {redirect_url}"

        # Check for JavaScript redirect
        js_redirects = [
            rf'location\.href\s*=\s*["\']?{re.escape(payload)}',
            rf'location\.assign\s*\(["\']?{re.escape(payload)}',
            rf'location\.replace\s*\(["\']?{re.escape(payload)}'
        ]
        for pattern in js_redirects:
            if re.search(pattern, response_body):
                return True, 0.7, "Open redirect via JavaScript"

        return False, 0.0, None
