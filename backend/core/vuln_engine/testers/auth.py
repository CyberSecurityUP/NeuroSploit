"""
NeuroSploit v3 - Authentication Vulnerability Testers

Testers for Auth Bypass, JWT, Session Fixation
"""
import re
import base64
import json
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class AuthBypassTester(BaseTester):
    """Tester for Authentication Bypass"""

    def __init__(self):
        super().__init__()
        self.name = "auth_bypass"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for authentication bypass"""
        # Check for successful auth indicators after bypass payload
        auth_success = [
            "welcome", "dashboard", "logged in", "authenticated",
            "success", "admin", "profile"
        ]

        if response_status == 200:
            body_lower = response_body.lower()
            for indicator in auth_success:
                if indicator in body_lower:
                    # Check if this was with a bypass payload
                    bypass_indicators = ["' or '1'='1", "admin'--", "' or 1=1"]
                    if any(bp in payload.lower() for bp in bypass_indicators):
                        return True, 0.8, f"Auth bypass possible: '{indicator}' found after injection"

        # Check for redirect to authenticated area
        location = response_headers.get("Location", "")
        if response_status in [301, 302]:
            if "dashboard" in location or "admin" in location or "home" in location:
                return True, 0.7, f"Auth bypass: Redirect to {location}"

        return False, 0.0, None


class JWTManipulationTester(BaseTester):
    """Tester for JWT Token Manipulation"""

    def __init__(self):
        super().__init__()
        self.name = "jwt_manipulation"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for JWT manipulation vulnerabilities"""
        # Check if manipulated JWT was accepted
        if response_status == 200:
            # Algorithm none attack
            if '"alg":"none"' in payload or '"alg": "none"' in payload:
                return True, 0.9, "JWT 'none' algorithm accepted"

            # Check for elevated privileges response
            elevated_indicators = ["admin", "administrator", "role.*admin"]
            for pattern in elevated_indicators:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.8, "JWT manipulation: Elevated privileges detected"

        # Check for JWT-specific errors
        jwt_errors = [
            r"invalid.*token", r"jwt.*expired", r"signature.*invalid",
            r"token.*malformed", r"unauthorized"
        ]
        for pattern in jwt_errors:
            if re.search(pattern, response_body, re.IGNORECASE):
                # Error means it's checking - note for further testing
                return False, 0.0, None

        return False, 0.0, None


class SessionFixationTester(BaseTester):
    """Tester for Session Fixation"""

    def __init__(self):
        super().__init__()
        self.name = "session_fixation"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for session fixation vulnerability"""
        # Check Set-Cookie header
        set_cookie = response_headers.get("Set-Cookie", "")

        # If session ID in URL was accepted
        if "JSESSIONID=" in payload or "PHPSESSID=" in payload:
            if response_status == 200:
                # Check if session was NOT regenerated
                if not set_cookie or "JSESSIONID" not in set_cookie:
                    return True, 0.7, "Session ID from URL accepted without regeneration"

        # Check for session in URL
        if re.search(r'[?&](?:session|sid|PHPSESSID|JSESSIONID)=', response_body):
            return True, 0.6, "Session ID exposed in URL"

        return False, 0.0, None
