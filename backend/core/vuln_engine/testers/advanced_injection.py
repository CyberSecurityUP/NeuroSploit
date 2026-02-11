"""
NeuroSploit v3 - Advanced Injection Vulnerability Testers

Testers for LDAP, XPath, GraphQL, CRLF, Header, Email, EL, Log, HTML, CSV, and ORM injection.
"""
import re
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class LdapInjectionTester(BaseTester):
    """Tester for LDAP Injection vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "ldap_injection"
        self.error_patterns = [
            r"javax\.naming\.NamingException",
            r"LDAPException",
            r"ldap_search\(\)",
            r"ldap_bind\(\)",
            r"Invalid DN syntax",
            r"Bad search filter",
            r"DSA is unavailable",
            r"LDAP error code \d+",
            r"cn=.*,\s*ou=.*,\s*dc=",
            r"objectClass=",
            r"No such object",
            r"invalid attribute description",
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for LDAP injection indicators"""
        # Check for LDAP error messages
        for pattern in self.error_patterns:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                return True, 0.8, f"LDAP error detected: {match.group(0)[:100]}"

        # Wildcard injection - check if directory listing returned
        if "*" in payload:
            # Multiple DN entries suggest directory enumeration
            dn_count = len(re.findall(r"dn:\s+\S+", response_body, re.IGNORECASE))
            if dn_count > 1:
                return True, 0.85, f"LDAP wildcard returned {dn_count} directory entries"

        # Filter manipulation - check for unexpected data volume
        if ")(|" in payload or "*)(objectClass" in payload:
            if response_status == 200 and len(response_body) > 5000:
                return True, 0.6, "LDAP filter manipulation may have returned extra data"

        return False, 0.0, None


class XpathInjectionTester(BaseTester):
    """Tester for XPath Injection vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "xpath_injection"
        self.error_patterns = [
            r"XPathException",
            r"Invalid XPath",
            r"xpath syntax error",
            r"javax\.xml\.xpath",
            r"XPathEvalError",
            r"xmlXPathEval:",
            r"XPATH syntax error",
            r"DOMXPath",
            r"SimpleXMLElement::xpath\(\)",
            r"lxml\.etree\.XPathEvalError",
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for XPath injection indicators"""
        # XPath error messages
        for pattern in self.error_patterns:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                return True, 0.85, f"XPath error detected: {match.group(0)[:100]}"

        # Boolean-based XPath injection - true condition returning data
        if ("' or '1'='1" in payload or "or 1=1" in payload):
            if response_status == 200:
                # Check for XML-like data in response
                xml_tags = re.findall(r"<[a-zA-Z][^>]*>", response_body)
                if len(xml_tags) > 5:
                    return True, 0.65, "XPath boolean injection may have returned XML data"

        # Check for exposed XML node data
        if "' | //" in payload or "extractvalue(" in payload.lower():
            if re.search(r"<\?xml\s+version=", response_body):
                return True, 0.7, "XML document exposed via XPath injection"

        return False, 0.0, None


class GraphqlInjectionTester(BaseTester):
    """Tester for GraphQL Injection / Introspection vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "graphql_injection"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for GraphQL introspection and injection indicators"""
        body_lower = response_body.lower()

        # Introspection query response - schema exposure
        if "__schema" in payload or "__type" in payload or "introspection" in payload.lower():
            if '"__schema"' in response_body or '"__type"' in response_body:
                return True, 0.9, "GraphQL introspection enabled - schema exposed"
            if '"types"' in response_body and '"queryType"' in response_body:
                return True, 0.9, "GraphQL schema types exposed via introspection"

        # GraphQL error messages revealing structure
        graphql_errors = [
            r'"errors"\s*:\s*\[',
            r"Cannot query field",
            r"Unknown argument",
            r"Field .* not found in type",
            r"Syntax Error.*GraphQL",
            r"GraphQL error",
        ]
        for pattern in graphql_errors:
            if re.search(pattern, response_body, re.IGNORECASE):
                # Error messages can reveal field/type names
                if re.search(r'"message"\s*:\s*".*(?:field|type|argument)', response_body, re.IGNORECASE):
                    return True, 0.7, "GraphQL error reveals schema information"

        # Mutation that returned success unexpectedly
        if "mutation" in payload.lower() and response_status == 200:
            if '"data"' in response_body and '"errors"' not in response_body:
                return True, 0.5, "GraphQL mutation succeeded - verify authorization"

        return False, 0.0, None


class CrlfInjectionTester(BaseTester):
    """Tester for CRLF Injection vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "crlf_injection"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for CRLF injection - injected headers appearing in response"""
        # Check if our injected header appeared in response headers
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        if "x-test" in headers_lower:
            return True, 0.95, f"CRLF injection confirmed: X-Test header injected with value '{headers_lower['x-test']}'"

        if "x-injected" in headers_lower:
            return True, 0.95, f"CRLF injection confirmed: X-Injected header present"

        # Check for Set-Cookie injection
        if "set-cookie" in headers_lower and "neurosploit" in str(headers_lower.get("set-cookie", "")).lower():
            return True, 0.9, "CRLF injection: injected Set-Cookie header detected"

        # Check if payload characters are reflected unencoded in Location header
        if "location" in headers_lower:
            location = headers_lower["location"]
            if "\r\n" in location or "%0d%0a" in location.lower():
                return True, 0.8, "CRLF characters in Location header"

        return False, 0.0, None


class HeaderInjectionTester(BaseTester):
    """Tester for Host Header Injection vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "header_injection"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for Host header reflected in response URLs"""
        body_lower = response_body.lower()

        # Check if injected host value appears in response links
        evil_markers = ["evil.com", "attacker.com", "neurosploit.test"]
        for marker in evil_markers:
            if marker in payload.lower():
                if marker in body_lower:
                    # Check if it appears in URLs, links, or redirects
                    url_pattern = rf'(?:href|src|action|url|link|redirect)\s*[=:]\s*["\']?[^"\']*{re.escape(marker)}'
                    if re.search(url_pattern, response_body, re.IGNORECASE):
                        return True, 0.9, f"Host header injected into response URL: {marker}"
                    return True, 0.7, f"Injected host value '{marker}' reflected in response"

        # Password reset poisoning check
        if "password" in body_lower and "reset" in body_lower:
            headers_lower = {k.lower(): v for k, v in response_headers.items()}
            if response_status in [200, 302]:
                return True, 0.5, "Password reset response may use Host header for link generation"

        return False, 0.0, None


class EmailInjectionTester(BaseTester):
    """Tester for Email Header Injection vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "email_injection"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for email header injection success indicators"""
        body_lower = response_body.lower()

        # Check for CC/BCC injection indicators
        if any(h in payload.lower() for h in ["cc:", "bcc:", "\r\nto:", "%0acc:", "%0abcc:"]):
            # Successful email send with injected headers
            if response_status == 200:
                success_indicators = [
                    "email sent", "message sent", "mail sent",
                    "successfully sent", "email delivered", "sent successfully",
                ]
                for indicator in success_indicators:
                    if indicator in body_lower:
                        return True, 0.75, f"Email injection: '{indicator}' after CC/BCC injection attempt"

            # Check for multiple recipient confirmation
            if re.search(r"(?:sent to|delivered to|recipients?)\s*:?\s*\d+", response_body, re.IGNORECASE):
                return True, 0.7, "Email sent to multiple recipients after injection"

        # SMTP error leak
        smtp_errors = [r"SMTP error", r"550 \d+", r"relay access denied", r"mail\(\).*failed"]
        for pattern in smtp_errors:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.6, "SMTP error revealed - email injection attempted"

        return False, 0.0, None


class ELInjectionTester(BaseTester):
    """Tester for Expression Language (EL) Injection vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "el_injection"
        self.math_results = {
            "${7*7}": "49",
            "#{7*7}": "49",
            "${3*11}": "33",
            "#{3*11}": "33",
        }

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for EL injection - expression evaluation in response"""
        # Check mathematical expression results
        for expr, result in self.math_results.items():
            if expr in payload and result in response_body:
                # Make sure the result isn't just the expression echoed
                if expr not in response_body:
                    return True, 0.95, f"EL injection confirmed: {expr} evaluated to {result}"

        # Java class names exposed via EL
        java_indicators = [
            r"java\.lang\.\w+",
            r"java\.io\.File",
            r"Runtime\.getRuntime",
            r"ProcessBuilder",
            r"javax\.\w+\.\w+",
            r"org\.apache\.\w+",
            r"getClass\(\)\.forName",
        ]
        for pattern in java_indicators:
            if re.search(pattern, response_body):
                return True, 0.8, f"Java class exposure via EL injection: {pattern}"

        # Spring EL specific
        if "T(java.lang" in payload:
            if re.search(r"class\s+\w+|java\.\w+", response_body):
                return True, 0.7, "Spring EL injection indicator - Java class reference in response"

        return False, 0.0, None


class LogInjectionTester(BaseTester):
    """Tester for Log Injection / Log4Shell / JNDI Injection vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "log_injection"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for log injection and JNDI callback indicators"""
        # JNDI/Log4Shell detection via context callback
        if "${jndi:" in payload.lower():
            # Check context for callback confirmation
            if context.get("callback_received"):
                return True, 0.95, "JNDI injection confirmed via callback"
            # Check for Log4j error in response
            log4j_indicators = [
                r"log4j", r"Log4jException", r"JNDI lookup",
                r"javax\.naming", r"InitialContext",
            ]
            for pattern in log4j_indicators:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.7, f"Log4j/JNDI indicator in response: {pattern}"

        # Newline injection in log-like responses
        if "\n" in payload or "%0a" in payload.lower() or "\\n" in payload:
            # Check if response includes log-format lines with our injected content
            log_patterns = [
                r"\[\d{4}-\d{2}-\d{2}.*\].*neurosploit",
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}.*neurosploit",
                r"(?:INFO|WARN|ERROR|DEBUG)\s+.*neurosploit",
            ]
            for pattern in log_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.7, "Log injection: injected content appears in log-format output"

        # Generic log forging check
        if "neurosploit" in payload and response_status == 200:
            if re.search(r"(?:log|audit|event).*neurosploit", response_body, re.IGNORECASE):
                return True, 0.5, "Injected marker appears in log/audit output"

        return False, 0.0, None


class HtmlInjectionTester(BaseTester):
    """Tester for HTML Injection vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "html_injection"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for rendered HTML tags in response"""
        if response_status >= 400:
            return False, 0.0, None

        # Check for injected HTML tags rendered in response
        html_tests = [
            (r"<b>neurosploit</b>", "Bold tag rendered"),
            (r"<i>neurosploit</i>", "Italic tag rendered"),
            (r"<u>neurosploit</u>", "Underline tag rendered"),
            (r'<a\s+href=["\']?[^"\']*["\']?>neurosploit</a>', "Anchor tag rendered"),
            (r'<img\s+src=["\']?[^"\']*["\']?', "Image tag rendered"),
            (r'<form\s+[^>]*action=', "Form tag rendered"),
            (r'<iframe\s+', "IFrame tag rendered"),
            (r'<marquee>', "Marquee tag rendered"),
            (r'<h1>neurosploit</h1>', "H1 tag rendered"),
            (r'<div\s+style=', "Styled div rendered"),
        ]

        for pattern, description in html_tests:
            if re.search(pattern, response_body, re.IGNORECASE):
                # Verify it wasn't already there (check if payload was actually injected)
                if any(tag in payload.lower() for tag in ["<b>", "<i>", "<u>", "<a ", "<img", "<form", "<iframe", "<marquee", "<h1>", "<div"]):
                    return True, 0.8, f"HTML injection: {description}"

        # Check for payload reflection without encoding
        if "<" in payload and ">" in payload:
            # Find the injected tag in response
            tag_match = re.search(r"<(\w+)[^>]*>", payload)
            if tag_match:
                tag_name = tag_match.group(1)
                if f"<{tag_name}" in response_body and f"&lt;{tag_name}" not in response_body:
                    return True, 0.75, f"HTML tag <{tag_name}> reflected without encoding"

        return False, 0.0, None


class CsvInjectionTester(BaseTester):
    """Tester for CSV Injection (Formula Injection) vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "csv_injection"
        self.formula_chars = ["=", "+", "-", "@", "\t", "\r"]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for formula characters preserved in CSV export responses"""
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        content_type = headers_lower.get("content-type", "")

        # Check if response is CSV or spreadsheet
        is_csv = "text/csv" in content_type or "spreadsheet" in content_type
        is_export = "content-disposition" in headers_lower and any(
            ext in headers_lower.get("content-disposition", "")
            for ext in [".csv", ".xls", ".xlsx"]
        )

        if is_csv or is_export:
            # Check if formula characters are preserved without escaping
            for char in self.formula_chars:
                if char in payload and payload in response_body:
                    return True, 0.8, f"CSV injection: formula character '{char}' preserved in export"

            # Check for specific formula patterns
            formula_patterns = [
                r'[=+\-@].*(?:HYPERLINK|IMPORTXML|IMPORTDATA|cmd|powershell)',
                r'=\w+\(.*\)',
            ]
            for pattern in formula_patterns:
                if re.search(pattern, response_body):
                    return True, 0.7, "CSV injection: formula pattern found in export data"

        # Non-CSV response but payload was stored
        if response_status in [200, 201] and any(c in payload for c in self.formula_chars[:4]):
            if payload in response_body:
                return True, 0.4, "Formula characters accepted and stored - verify CSV export"

        return False, 0.0, None


class OrmInjectionTester(BaseTester):
    """Tester for ORM Injection vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "orm_injection"
        self.error_patterns = [
            r"Hibernate.*Exception",
            r"javax\.persistence",
            r"org\.hibernate",
            r"ActiveRecord::.*Error",
            r"Sequelize.*Error",
            r"SQLAlchemy.*Error",
            r"Doctrine.*Exception",
            r"TypeORM.*Error",
            r"Prisma.*Error",
            r"EntityFramework.*Exception",
            r"LINQ.*Exception",
            r"django\.db.*Error",
            r"peewee\.\w+Error",
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for ORM injection indicators"""
        # ORM error messages
        for pattern in self.error_patterns:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                return True, 0.8, f"ORM error detected: {match.group(0)[:100]}"

        # Filter manipulation - unexpected data returned
        if any(op in payload for op in ["__gt", "__lt", "__ne", "$ne", "$gt", ">=", "!="]):
            if response_status == 200:
                # Check context for baseline comparison
                if "baseline_length" in context:
                    diff = abs(len(response_body) - context["baseline_length"])
                    if diff > 500:
                        return True, 0.6, f"ORM filter manipulation: response size differs by {diff} bytes"

        # Check for data volume suggesting bypassed filters
        if "__all" in payload or "objects.all" in payload:
            if response_status == 200 and len(response_body) > 10000:
                return True, 0.5, "ORM injection may have bypassed query filters - large data returned"

        return False, 0.0, None
