"""
NeuroSploit v3 - Injection Vulnerability Testers

Testers for XSS, SQL Injection, Command Injection, SSTI, etc.
"""
import re
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class XSSReflectedTester(BaseTester):
    """Tester for Reflected XSS vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "xss_reflected"
        # Unique markers for detection
        self.markers = [
            "neurosploit",
            "xsstest123",
            "alert(1)"
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check if XSS payload is reflected in response"""
        if response_status >= 400:
            return False, 0.0, None

        # Check if payload is reflected
        if payload in response_body:
            # Use context-aware analysis to determine execution position
            from backend.core.xss_context_analyzer import analyze_xss_execution_context
            ctx = analyze_xss_execution_context(response_body, payload)
            if ctx["executable"]:
                return True, 0.95, f"XSS payload in auto-executing context: {ctx['detail']}"
            elif ctx["interactive"]:
                return True, 0.85, f"XSS payload in interactive context: {ctx['detail']}"
            # Reflected but not in executable position
            return True, 0.5, f"XSS payload reflected but {ctx['context']}: {ctx['detail']}"

        # Check for partial reflection (script tags, etc.)
        for marker in self.markers:
            if marker in payload and marker in response_body:
                return True, 0.6, f"XSS marker '{marker}' found in response"

        return False, 0.0, None


class XSSStoredTester(BaseTester):
    """Tester for Stored XSS vulnerabilities.

    Supports two-phase verification:
    Phase 1: analyze_response() - Check if submission succeeded (data stored)
    Phase 2: analyze_display_response() - Check if payload executes on display page
    """

    def __init__(self):
        super().__init__()
        self.name = "xss_stored"
        self.storage_indicators = [
            "success", "created", "saved", "posted", "submitted",
            "thank", "comment", "added", "published", "updated",
            "your comment", "your post", "your message",
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Phase 1: Check if payload was likely stored.

        Returns confidence 0.3-0.5 for storage-only confirmation.
        Full confirmation requires Phase 2 (analyze_display_response).
        """
        body_lower = response_body.lower()

        # Redirect after POST is a common form submission pattern
        if response_status in [301, 302, 303]:
            return True, 0.4, "Redirect after submission - payload likely stored"

        if response_status in [200, 201]:
            # Check for storage success indicators
            for indicator in self.storage_indicators:
                if indicator in body_lower:
                    return True, 0.4, f"Storage indicator found: '{indicator}'"

            # Check if payload is reflected in the same response (immediate display)
            if payload in response_body:
                dangerous = [
                    "<script", "onerror=", "onload=", "onclick=", "onfocus=",
                    "onmouseover=", "<svg", "<img", "<iframe", "javascript:"
                ]
                payload_lower = payload.lower()
                for ctx in dangerous:
                    if ctx in payload_lower:
                        return True, 0.8, f"Stored XSS: payload reflected in dangerous context ({ctx})"
                return True, 0.6, "Payload reflected in submission response"

        # POST returning 200 often means submission accepted
        if response_status == 200 and context.get("method") == "POST":
            return True, 0.3, "POST returned 200 - submission possibly accepted"

        return False, 0.0, None

    def analyze_display_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Phase 2: Verify payload executes on the display page.

        Called after navigating to the page where stored content is rendered.
        """
        if response_status >= 400:
            return False, 0.0, None

        # Check if payload exists unescaped in display page
        if payload in response_body:
            # Use context-aware analysis to determine execution position
            from backend.core.xss_context_analyzer import analyze_xss_execution_context
            ctx = analyze_xss_execution_context(response_body, payload)
            if ctx["executable"]:
                return True, 0.95, f"Stored XSS confirmed: {ctx['detail']}"
            elif ctx["interactive"]:
                return True, 0.90, f"Stored XSS (interaction required): {ctx['detail']}"
            # Payload present but not executable
            return True, 0.5, f"Stored payload on display page but {ctx['context']}: {ctx['detail']}"

        # Check for core execution markers even if full payload is modified
        core_markers = [
            "alert(1)", "alert(document.domain)", "onerror=alert",
            "onload=alert", "onfocus=alert", "ontoggle=alert",
        ]
        body_lower = response_body.lower()
        for marker in core_markers:
            if marker in payload.lower() and marker in body_lower:
                return True, 0.85, f"Stored XSS: execution marker '{marker}' found on display page"

        return False, 0.0, None


class XSSDomTester(BaseTester):
    """Tester for DOM-based XSS vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "xss_dom"
        self.dom_sinks = [
            "innerHTML", "outerHTML", "document.write", "document.writeln",
            "eval(", "setTimeout(", "setInterval(", "location.href",
            "location.assign", "location.replace"
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for DOM XSS indicators"""
        # Look for dangerous DOM sinks in JavaScript
        for sink in self.dom_sinks:
            pattern = rf'{sink}[^;]*(?:location|document\.URL|document\.referrer|window\.name)'
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.7, f"Potential DOM XSS sink found: {sink}"

        # Check if URL parameters are used in JavaScript
        if re.search(r'(?:location\.search|location\.hash|document\.URL)', response_body):
            if any(sink in response_body for sink in self.dom_sinks):
                return True, 0.6, "URL input flows to DOM sink"

        return False, 0.0, None


class SQLiErrorTester(BaseTester):
    """Tester for Error-based SQL Injection"""

    def __init__(self):
        super().__init__()
        self.name = "sqli_error"
        self.error_patterns = [
            # MySQL
            r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
            r"valid MySQL result", r"check the manual that corresponds to your MySQL",
            # PostgreSQL
            r"PostgreSQL.*ERROR", r"Warning.*pg_", r"valid PostgreSQL result",
            r"Npgsql\.", r"PG::SyntaxError",
            # SQL Server
            r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.*SQL Server",
            r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"Microsoft SQL Native Client error",
            # Oracle
            r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver",
            r"Warning.*oci_", r"Warning.*ora_",
            # SQLite
            r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_", r"Warning.*SQLite3::",
            # Generic
            r"SQL syntax.*", r"syntax error.*SQL", r"unclosed quotation mark",
            r"quoted string not properly terminated"
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for SQL error messages in response"""
        for pattern in self.error_patterns:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                return True, 0.9, f"SQL error detected: {match.group(0)[:100]}"

        return False, 0.0, None


class SQLiUnionTester(BaseTester):
    """Tester for Union-based SQL Injection"""

    def __init__(self):
        super().__init__()
        self.name = "sqli_union"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for union-based SQLi indicators"""
        # Look for injected data markers
        union_markers = ["neurosploit", "uniontest", "concat(", "version()"]

        for marker in union_markers:
            if marker in payload.lower() and marker in response_body.lower():
                return True, 0.8, f"Union injection marker '{marker}' found in response"

        # Check for database version strings
        version_patterns = [
            r"MySQL.*\d+\.\d+", r"PostgreSQL.*\d+\.\d+",
            r"Microsoft SQL Server.*\d+", r"Oracle.*\d+",
            r"\d+\.\d+\.\d+-MariaDB"
        ]
        for pattern in version_patterns:
            if re.search(pattern, response_body):
                return True, 0.7, "Database version string found - possible union SQLi"

        return False, 0.0, None


class SQLiBlindTester(BaseTester):
    """Tester for Boolean-based Blind SQL Injection"""

    def __init__(self):
        super().__init__()
        self.name = "sqli_blind"
        self.baseline_length = None

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for boolean-based blind SQLi"""
        # This requires comparing responses - simplified check
        response_length = len(response_body)

        # Check for significant difference in response
        if "baseline_length" in context:
            diff = abs(response_length - context["baseline_length"])
            if diff > 100:  # Significant difference
                return True, 0.6, f"Response length differs by {diff} bytes - possible blind SQLi"

        # Check for conditional responses
        if "1=1" in payload and response_status == 200:
            return True, 0.5, "True condition returned 200 - possible blind SQLi"

        return False, 0.0, None


class SQLiTimeTester(BaseTester):
    """Tester for Time-based Blind SQL Injection"""

    def __init__(self):
        super().__init__()
        self.name = "sqli_time"

    def check_timeout_vulnerability(self, vuln_type: str) -> bool:
        """Time-based SQLi is indicated by timeout"""
        return True

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Time-based detection relies on timeout"""
        # Response time analysis would be done in the engine
        return False, 0.0, None


class CommandInjectionTester(BaseTester):
    """Tester for OS Command Injection"""

    def __init__(self):
        super().__init__()
        self.name = "command_injection"
        self.command_outputs = [
            # Linux
            r"root:.*:0:0:", r"bin:.*:1:1:",  # /etc/passwd
            r"uid=\d+.*gid=\d+",  # id command
            r"Linux.*\d+\.\d+\.\d+",  # uname
            r"total \d+.*drwx",  # ls -la
            # Windows
            r"Volume Serial Number",
            r"Directory of [A-Z]:\\",
            r"Windows.*\[Version",
            r"Microsoft Windows"
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for command execution evidence"""
        for pattern in self.command_outputs:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                return True, 0.95, f"Command output detected: {match.group(0)[:100]}"

        # Check for our marker
        if "neurosploit" in payload and "neurosploit" in response_body:
            return True, 0.8, "Command injection marker echoed"

        return False, 0.0, None


class SSTITester(BaseTester):
    """Tester for Server-Side Template Injection"""

    def __init__(self):
        super().__init__()
        self.name = "ssti"
        # Mathematical expressions that prove code execution
        self.math_results = {
            "{{7*7}}": "49",
            "${7*7}": "49",
            "#{7*7}": "49",
            "<%= 7*7 %>": "49",
            "{{7*'7'}}": "7777777",  # Jinja2
        }

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for SSTI indicators"""
        # Check mathematical results
        for expr, result in self.math_results.items():
            if expr in payload and result in response_body:
                return True, 0.95, f"SSTI confirmed: {expr} = {result}"

        # Check for template errors
        template_errors = [
            r"TemplateSyntaxError", r"Jinja2", r"Twig_Error",
            r"freemarker\.core\.", r"velocity\.exception",
            r"org\.apache\.velocity", r"Smarty"
        ]
        for pattern in template_errors:
            if re.search(pattern, response_body):
                return True, 0.7, f"Template engine error: {pattern}"

        return False, 0.0, None


class NoSQLInjectionTester(BaseTester):
    """Tester for NoSQL Injection"""

    def __init__(self):
        super().__init__()
        self.name = "nosql_injection"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for NoSQL injection indicators"""
        # MongoDB errors
        nosql_errors = [
            r"MongoError", r"MongoDB", r"bson",
            r"\$where", r"\$gt", r"\$ne",
            r"SyntaxError.*JSON"
        ]

        for pattern in nosql_errors:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.7, f"NoSQL error indicator: {pattern}"

        # Check for authentication bypass
        if "$ne" in payload or "$gt" in payload:
            if response_status == 200 and "success" in response_body.lower():
                return True, 0.6, "Possible NoSQL authentication bypass"

        return False, 0.0, None
