"""
NeuroSploit v3 - Authorization Vulnerability Testers

Testers for IDOR, BOLA, Privilege Escalation
"""
import re
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class IDORTester(BaseTester):
    """Tester for Insecure Direct Object Reference"""

    def __init__(self):
        super().__init__()
        self.name = "idor"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for IDOR vulnerability"""
        # Check if we got data for a different ID
        if response_status == 200:
            # Look for user data indicators
            user_data_patterns = [
                r'"user_?id"\s*:\s*\d+',
                r'"email"\s*:\s*"[^"]+"',
                r'"name"\s*:\s*"[^"]+"',
                r'"account"\s*:',
                r'"profile"\s*:'
            ]

            for pattern in user_data_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    # Check if ID in payload differs from context user
                    if "original_id" in context:
                        if context["original_id"] not in payload:
                            return True, 0.8, f"IDOR: Accessed different user's data"

            # Generic data access check
            if len(response_body) > 50:
                return True, 0.6, "IDOR: Response contains data - verify authorization"

        return False, 0.0, None


class BOLATester(BaseTester):
    """Tester for Broken Object Level Authorization"""

    def __init__(self):
        super().__init__()
        self.name = "bola"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for BOLA in APIs"""
        # BOLA in REST APIs
        if response_status == 200:
            # Check for successful data access
            data_indicators = [
                r'"data"\s*:\s*\{',
                r'"items"\s*:\s*\[',
                r'"result"\s*:\s*\{',
                r'"id"\s*:\s*\d+'
            ]

            for pattern in data_indicators:
                if re.search(pattern, response_body):
                    return True, 0.7, "BOLA: API returned object data - verify authorization"

        # Check for enumeration possibilities
        if response_status in [200, 404]:
            # Different status for valid vs invalid IDs indicates BOLA risk
            return True, 0.5, "BOLA: Different responses for IDs - enumeration possible"

        return False, 0.0, None


class PrivilegeEscalationTester(BaseTester):
    """Tester for Privilege Escalation"""

    def __init__(self):
        super().__init__()
        self.name = "privilege_escalation"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for privilege escalation"""
        if response_status == 200:
            # Check for admin/elevated access indicators
            elevated_access = [
                r'"role"\s*:\s*"admin"',
                r'"is_?admin"\s*:\s*true',
                r'"admin"\s*:\s*true',
                r'"privilege"\s*:\s*"(?:admin|root|superuser)"',
                r'"permissions"\s*:\s*\[.*"admin".*\]'
            ]

            for pattern in elevated_access:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.9, f"Privilege escalation: Elevated role in response"

            # Check for admin functionality access
            admin_functions = [
                "user management", "delete user", "admin panel",
                "system settings", "all users", "user list"
            ]
            body_lower = response_body.lower()
            for func in admin_functions:
                if func in body_lower:
                    return True, 0.7, f"Privilege escalation: Admin functionality '{func}' accessible"

        return False, 0.0, None


class BflaTester(BaseTester):
    """Tester for Broken Function Level Authorization (BFLA)"""

    def __init__(self):
        super().__init__()
        self.name = "bfla"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for admin functionality accessible to regular user"""
        if response_status == 200:
            # Admin-specific data patterns
            admin_data_patterns = [
                r'"users"\s*:\s*\[',
                r'"all_users"\s*:',
                r'"admin_settings"\s*:',
                r'"system_config"\s*:',
                r'"audit_log"\s*:',
                r'"role"\s*:\s*"admin"',
                r'"permissions"\s*:\s*\[',
                r'"api_keys"\s*:\s*\[',
            ]

            for pattern in admin_data_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    # Check if this was an admin endpoint accessed as regular user
                    admin_url_indicators = [
                        "/admin", "/manage", "/users", "/settings",
                        "/config", "/system", "/audit", "/logs",
                    ]
                    if any(ind in payload.lower() for ind in admin_url_indicators):
                        return True, 0.85, f"BFLA: Admin data returned for non-admin request"

            # Admin page content
            admin_content = [
                "user management", "system configuration", "admin dashboard",
                "manage users", "all accounts", "server status",
                "delete user", "create admin",
            ]
            body_lower = response_body.lower()
            for content in admin_content:
                if content in body_lower:
                    return True, 0.8, f"BFLA: Admin functionality '{content}' accessible to regular user"

        # Admin endpoint should return 403 for non-admin
        if response_status not in [401, 403] and context.get("is_admin_endpoint"):
            if response_status == 200:
                return True, 0.7, "BFLA: Admin endpoint returned 200 instead of 403"

        return False, 0.0, None


class MassAssignmentTester(BaseTester):
    """Tester for Mass Assignment vulnerability"""

    def __init__(self):
        super().__init__()
        self.name = "mass_assignment"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for extra parameters being accepted and modifying model state"""
        if response_status in [200, 201]:
            # Check if privileged fields were accepted
            privileged_fields = [
                (r'"(?:is_)?admin"\s*:\s*true', "admin flag"),
                (r'"role"\s*:\s*"admin"', "admin role"),
                (r'"role"\s*:\s*"superuser"', "superuser role"),
                (r'"verified"\s*:\s*true', "verified status"),
                (r'"is_staff"\s*:\s*true', "staff flag"),
                (r'"is_superuser"\s*:\s*true', "superuser flag"),
                (r'"balance"\s*:\s*\d{4,}', "balance modification"),
                (r'"credits"\s*:\s*\d{3,}', "credits modification"),
                (r'"discount"\s*:\s*\d+', "discount field"),
                (r'"price"\s*:\s*0', "price zeroed"),
            ]

            # Check if payload attempted mass assignment
            mass_assign_indicators = [
                "admin", "role", "is_staff", "is_superuser",
                "verified", "balance", "credits", "price", "discount",
            ]
            payload_has_mass_assign = any(ind in payload.lower() for ind in mass_assign_indicators)

            if payload_has_mass_assign:
                for pattern, field_name in privileged_fields:
                    if re.search(pattern, response_body, re.IGNORECASE):
                        return True, 0.85, f"Mass assignment: Privileged field '{field_name}' accepted and reflected"

                # Check if response changed compared to baseline
                if context.get("baseline_body"):
                    baseline = context["baseline_body"]
                    if response_body != baseline and len(response_body) > len(baseline):
                        return True, 0.6, "Mass assignment: Response differs from baseline after extra parameters"

        return False, 0.0, None


class ForcedBrowsingTester(BaseTester):
    """Tester for Forced Browsing (direct access to restricted URLs)"""

    def __init__(self):
        super().__init__()
        self.name = "forced_browsing"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for direct access to restricted URLs without proper authorization"""
        # Should get 401/403/302 for restricted content, not 200
        if response_status == 200:
            # Sensitive content indicators
            sensitive_patterns = [
                (r"(?:admin|management)\s+(?:panel|dashboard|console)", "admin panel"),
                (r'"(?:password|secret|api_key|token)"\s*:\s*"[^"]+"', "sensitive data"),
                (r"(?:backup|dump|export)\s+(?:file|data|database)", "backup files"),
                (r"phpinfo\(\)", "PHP info page"),
                (r"(?:configuration|config)\s+(?:file|settings)", "configuration page"),
                (r"(?:internal|private)\s+(?:api|endpoint|documentation)", "internal docs"),
                (r"(?:debug|diagnostic)\s+(?:info|page|console)", "debug page"),
                (r"(?:user|customer)\s+(?:list|database|records)", "user records"),
            ]

            for pattern, desc in sensitive_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.8, f"Forced browsing: Restricted content accessible - {desc}"

            # Check for restricted URL patterns in payload
            restricted_paths = [
                "/admin", "/backup", "/config", "/internal",
                "/debug", "/private", "/management", "/phpinfo",
                "/.git", "/.env", "/wp-admin", "/server-status",
            ]
            if any(path in payload.lower() for path in restricted_paths):
                if len(response_body) > 200:
                    return True, 0.7, "Forced browsing: Restricted URL returned content (200 OK)"

        # Check that redirect isn't to the same restricted page (false positive)
        if response_status in [301, 302]:
            location = response_headers.get("Location", "").lower()
            if "login" in location or "signin" in location or "auth" in location:
                return False, 0.0, None  # Properly redirecting to login

        return False, 0.0, None
