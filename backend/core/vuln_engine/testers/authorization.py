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
