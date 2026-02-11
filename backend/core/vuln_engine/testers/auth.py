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


class WeakPasswordTester(BaseTester):
    """Tester for Weak Password acceptance"""

    def __init__(self):
        super().__init__()
        self.name = "weak_password"
        self.weak_passwords = [
            "123456", "password", "12345678", "qwerty", "abc123",
            "111111", "123123", "admin", "letmein", "welcome",
            "1234", "1", "a"
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for successful login/registration with weak passwords"""
        body_lower = response_body.lower()

        # Check if payload contains a weak password
        payload_has_weak = any(wp in payload for wp in self.weak_passwords)
        if not payload_has_weak:
            return False, 0.0, None

        # Check for successful auth with weak password
        if response_status in [200, 201, 302]:
            success_indicators = [
                r'"(?:access_)?token"\s*:', r'"session"\s*:',
                r"(?:login|registration|signup)\s+successful",
                r'"authenticated"\s*:\s*true', r'"success"\s*:\s*true',
                r"welcome", r"dashboard", r"logged\s*in",
            ]
            for pattern in success_indicators:
                if re.search(pattern, response_body, re.IGNORECASE):
                    matched_pw = next((wp for wp in self.weak_passwords if wp in payload), "unknown")
                    return True, 0.85, f"Weak password accepted: '{matched_pw}' allowed for authentication"

            # Redirect to authenticated area
            location = response_headers.get("Location", "")
            if response_status == 302 and any(x in location.lower() for x in ["dashboard", "home", "profile", "account"]):
                matched_pw = next((wp for wp in self.weak_passwords if wp in payload), "unknown")
                return True, 0.8, f"Weak password accepted: Redirect to authenticated area with '{matched_pw}'"

        return False, 0.0, None


class DefaultCredentialsTester(BaseTester):
    """Tester for Default Credentials acceptance"""

    def __init__(self):
        super().__init__()
        self.name = "default_credentials"
        self.default_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
            ("root", "root"), ("root", "toor"), ("root", "password"),
            ("administrator", "administrator"), ("admin", "1234"),
            ("test", "test"), ("guest", "guest"), ("user", "user"),
            ("admin", "changeme"), ("admin", "default"),
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for successful login with default credentials"""
        body_lower = response_body.lower()

        # Check if payload matches default creds
        payload_lower = payload.lower()
        matched_cred = None
        for username, password in self.default_creds:
            if username in payload_lower and password in payload_lower:
                matched_cred = f"{username}/{password}"
                break

        if not matched_cred:
            return False, 0.0, None

        # Check for successful login
        if response_status in [200, 201, 302]:
            auth_success = [
                r'"(?:access_)?token"\s*:', r'"session"\s*:',
                r"(?:login|auth)\s+successful", r'"success"\s*:\s*true',
                r'"authenticated"\s*:\s*true', r"welcome",
                r"dashboard", r"admin\s*panel",
            ]
            for pattern in auth_success:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.9, f"Default credentials accepted: {matched_cred}"

            # Redirect to admin/dashboard
            location = response_headers.get("Location", "")
            if response_status == 302 and any(x in location.lower() for x in ["dashboard", "admin", "home", "panel"]):
                return True, 0.85, f"Default credentials accepted: {matched_cred} (redirect to {location})"

        return False, 0.0, None


class TwoFactorBypassTester(BaseTester):
    """Tester for Two-Factor Authentication Bypass"""

    def __init__(self):
        super().__init__()
        self.name = "two_factor_bypass"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for authenticated access without completing 2FA"""
        body_lower = response_body.lower()

        # Check if we reached authenticated content without 2FA
        if response_status == 200:
            # Authenticated area indicators
            auth_area_patterns = [
                r"dashboard", r"my\s*account", r"profile",
                r"settings", r"admin\s*panel", r'"user"\s*:\s*\{',
                r'"email"\s*:\s*"[^"]+"', r'"role"\s*:',
            ]
            # 2FA page indicators (we should NOT see these if bypassed)
            twofa_page_patterns = [
                r"(?:enter|verify)\s+(?:your\s+)?(?:otp|code|token|2fa)",
                r"two.?factor", r"verification\s+code",
                r"authenticator", r"sms\s+code",
            ]

            has_auth_content = any(re.search(p, response_body, re.IGNORECASE) for p in auth_area_patterns)
            is_twofa_page = any(re.search(p, response_body, re.IGNORECASE) for p in twofa_page_patterns)

            if has_auth_content and not is_twofa_page:
                # Check if payload suggests 2FA bypass attempt
                bypass_indicators = [
                    "2fa", "otp", "mfa", "verify", "code",
                    "step2", "second", "challenge",
                ]
                if any(bi in payload.lower() for bi in bypass_indicators):
                    return True, 0.85, "2FA bypass: Authenticated area accessed without completing 2FA"

                # Direct navigation bypass
                if context.get("skip_2fa") or context.get("direct_access"):
                    return True, 0.9, "2FA bypass: Direct navigation to authenticated page bypassed 2FA"

        # Redirect skipping 2FA step
        if response_status in [301, 302]:
            location = response_headers.get("Location", "").lower()
            if any(x in location for x in ["dashboard", "home", "account"]):
                if "verify" not in location and "2fa" not in location and "otp" not in location:
                    return True, 0.7, "2FA bypass: Redirect to authenticated area skipping verification"

        return False, 0.0, None


class OauthMisconfigTester(BaseTester):
    """Tester for OAuth Misconfiguration"""

    def __init__(self):
        super().__init__()
        self.name = "oauth_misconfig"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for OAuth misconfiguration (open redirect, token leakage)"""
        # Check for open redirect in OAuth flow
        if response_status in [301, 302, 303, 307]:
            location = response_headers.get("Location", "")

            # External redirect in OAuth callback
            if "redirect_uri" in payload.lower() or "callback" in payload.lower():
                # Check if redirecting to attacker-controlled domain
                evil_domains = ["evil.com", "attacker.com", "malicious.com"]
                if any(domain in location for domain in evil_domains):
                    return True, 0.9, f"OAuth misconfig: Open redirect in OAuth flow to {location}"

                # Check if arbitrary redirect_uri accepted
                if payload in location:
                    return True, 0.85, "OAuth misconfig: Arbitrary redirect_uri accepted"

        # Check for token in URL parameters (should be in fragment or POST)
        if response_status in [200, 302]:
            location = response_headers.get("Location", "")
            # Token in query string instead of fragment
            token_in_url = re.search(
                r'[?&](?:access_token|token|code)=([A-Za-z0-9._-]+)',
                location
            )
            if token_in_url:
                return True, 0.8, "OAuth misconfig: Token/code exposed in URL query parameters"

            # Token in response body URL
            token_in_body = re.search(
                r'(?:redirect|callback|return)["\']?\s*[:=]\s*["\']?https?://[^"\'>\s]*[?&]access_token=',
                response_body, re.IGNORECASE
            )
            if token_in_body:
                return True, 0.75, "OAuth misconfig: Access token in redirect URL"

        # Check for missing state parameter (CSRF in OAuth)
        if "state=" not in response_body and "state=" not in response_headers.get("Location", ""):
            if re.search(r"(?:authorize|oauth|auth)\?", response_body, re.IGNORECASE):
                return True, 0.6, "OAuth misconfig: Missing state parameter (CSRF risk)"

        return False, 0.0, None
