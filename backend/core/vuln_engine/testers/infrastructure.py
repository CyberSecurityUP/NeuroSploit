"""
NeuroSploit v3 - Infrastructure Vulnerability Testers

Testers for Security Headers, SSL/TLS, HTTP Methods
"""
import re
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class SecurityHeadersTester(BaseTester):
    """Tester for Missing Security Headers"""

    def __init__(self):
        super().__init__()
        self.name = "security_headers"
        self.required_headers = {
            "Strict-Transport-Security": "HSTS not configured",
            "X-Content-Type-Options": "X-Content-Type-Options not set",
            "X-Frame-Options": "X-Frame-Options not set",
            "Content-Security-Policy": "CSP not configured",
            "X-XSS-Protection": "X-XSS-Protection not set (legacy but still useful)",
            "Referrer-Policy": "Referrer-Policy not configured"
        }

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for missing security headers"""
        missing = []
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        for header, message in self.required_headers.items():
            if header.lower() not in headers_lower:
                missing.append(message)

        # Check for weak CSP
        csp = headers_lower.get("content-security-policy", "")
        if csp:
            weak_csp = []
            if "unsafe-inline" in csp:
                weak_csp.append("unsafe-inline")
            if "unsafe-eval" in csp:
                weak_csp.append("unsafe-eval")
            if "*" in csp:
                weak_csp.append("wildcard sources")
            if weak_csp:
                missing.append(f"Weak CSP: {', '.join(weak_csp)}")

        if missing:
            confidence = min(0.3 + len(missing) * 0.1, 0.8)
            return True, confidence, f"Missing/weak headers: {'; '.join(missing[:3])}"

        return False, 0.0, None


class SSLTester(BaseTester):
    """Tester for SSL/TLS Issues"""

    def __init__(self):
        super().__init__()
        self.name = "ssl_issues"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for SSL/TLS issues"""
        issues = []

        # Check HSTS
        hsts = response_headers.get("Strict-Transport-Security", "")
        if not hsts:
            issues.append("HSTS not enabled")
        else:
            # Check HSTS max-age
            max_age_match = re.search(r'max-age=(\d+)', hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # Less than 1 year
                    issues.append(f"HSTS max-age too short: {max_age}s")

            if "includeSubDomains" not in hsts:
                issues.append("HSTS missing includeSubDomains")

        # Check for HTTP resources on HTTPS page
        if "https://" in (context.get("url", "") or ""):
            http_resources = re.findall(r'(?:src|href)=["\']http://[^"\']+', response_body)
            if http_resources:
                issues.append(f"Mixed content: {len(http_resources)} HTTP resources")

        if issues:
            return True, 0.6, f"SSL/TLS issues: {'; '.join(issues)}"

        return False, 0.0, None


class HTTPMethodsTester(BaseTester):
    """Tester for Dangerous HTTP Methods"""

    def __init__(self):
        super().__init__()
        self.name = "http_methods"
        self.dangerous_methods = ["TRACE", "TRACK", "PUT", "DELETE", "CONNECT"]

    def build_request(self, endpoint, payload: str) -> Tuple[str, Dict, Dict, Optional[str]]:
        """Build OPTIONS request to check allowed methods"""
        headers = {
            "User-Agent": "NeuroSploit/3.0"
        }
        # payload is the HTTP method to test
        return endpoint.url, {}, headers, None

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for dangerous HTTP methods"""
        # Check Allow header from OPTIONS response
        allow = response_headers.get("Allow", "")
        dangerous_found = []

        for method in self.dangerous_methods:
            if method in allow.upper():
                dangerous_found.append(method)

        # TRACE method enables XST attacks
        if "TRACE" in dangerous_found or "TRACK" in dangerous_found:
            return True, 0.7, f"Dangerous methods enabled: {', '.join(dangerous_found)} (XST risk)"

        if dangerous_found:
            return True, 0.5, f"Potentially dangerous methods: {', '.join(dangerous_found)}"

        # Check if specific method test succeeded
        if payload.upper() in self.dangerous_methods:
            if response_status == 200:
                return True, 0.6, f"{payload} method accepted"

        return False, 0.0, None


class DirectoryListingTester(BaseTester):
    """Tester for Directory Listing exposure"""

    def __init__(self):
        super().__init__()
        self.name = "directory_listing"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for directory listing patterns"""
        if response_status == 200:
            listing_patterns = [
                r"<title>Index of\s*/",
                r"Index of\s*/",
                r"<h1>Index of",
                r"Directory listing for\s*/",
                r"<title>Directory listing",
                r'<a\s+href="\.\./">\.\./</a>',
                r"Parent Directory</a>",
                r'\[DIR\]',
                r'\[TXT\]',
                r"<pre>.*<a href=",
            ]

            for pattern in listing_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.9, "Directory listing: Server directory contents exposed"

            # Check for Apache/Nginx-specific listing
            if re.search(r'<address>Apache/[\d.]+ .* Server at', response_body, re.IGNORECASE):
                if "Index of" in response_body:
                    return True, 0.95, "Directory listing: Apache directory listing enabled"

        return False, 0.0, None


class DebugModeTester(BaseTester):
    """Tester for Debug Mode/Page exposure"""

    def __init__(self):
        super().__init__()
        self.name = "debug_mode"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for debug pages, stack traces with source paths"""
        # Werkzeug/Flask debugger
        werkzeug_patterns = [
            r"Werkzeug\s+Debugger",
            r"werkzeug\.debug",
            r"<div class=\"debugger\">",
            r"The debugger caught an exception",
            r"__debugger__",
        ]
        for pattern in werkzeug_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.95, "Debug mode: Werkzeug interactive debugger exposed (RCE risk)"

        # Laravel debug
        laravel_patterns = [
            r"Whoops!.*Laravel",
            r"Ignition\s",
            r"vendor/laravel",
            r"Laravel.*Exception",
            r"app/Http/Controllers",
        ]
        for pattern in laravel_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.9, "Debug mode: Laravel debug page exposed"

        # Django debug
        django_patterns = [
            r"You\'re seeing this error because you have <code>DEBUG = True</code>",
            r"Django Version:",
            r"Traceback.*django",
            r"INSTALLED_APPS",
            r"settings\.py",
        ]
        for pattern in django_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.9, "Debug mode: Django debug page exposed"

        # Generic stack traces with source paths
        stack_trace_patterns = [
            r"(?:File|at)\s+[\"']?(?:/[a-z]+/|C:\\)[^\s\"']+\.(?:py|php|rb|js|java|go)\b",
            r"Traceback \(most recent call last\)",
            r"Stack trace:.*(?:\.php|\.py|\.rb|\.java)",
            r"(?:Error|Exception)\s+in\s+(?:/[a-z]+/|C:\\)[^\s]+:\d+",
        ]
        for pattern in stack_trace_patterns:
            if re.search(pattern, response_body, re.IGNORECASE | re.DOTALL):
                return True, 0.8, "Debug mode: Stack trace with source file paths exposed"

        # ASP.NET detailed errors
        if re.search(r"Server Error in '/' Application", response_body):
            return True, 0.85, "Debug mode: ASP.NET detailed error page exposed"

        return False, 0.0, None


class ExposedAdminPanelTester(BaseTester):
    """Tester for Publicly Accessible Admin Panel"""

    def __init__(self):
        super().__init__()
        self.name = "exposed_admin_panel"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for admin login pages accessible publicly"""
        if response_status == 200:
            admin_panel_patterns = [
                (r"(?:admin|administrator)\s+(?:login|panel|dashboard|console)", "admin login page"),
                (r"<title>[^<]*(?:admin|dashboard|control\s*panel|cms)[^<]*</title>", "admin title"),
                (r"wp-login\.php", "WordPress login"),
                (r"wp-admin", "WordPress admin"),
                (r"/admin/login", "admin login endpoint"),
                (r"phpmyadmin", "phpMyAdmin"),
                (r"adminer\.php", "Adminer"),
                (r"cPanel", "cPanel"),
                (r"Webmin", "Webmin"),
                (r"Plesk", "Plesk"),
                (r"joomla.*administrator", "Joomla admin"),
                (r"drupal.*user/login", "Drupal admin login"),
            ]

            for pattern, panel_name in admin_panel_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.75, f"Exposed admin panel: {panel_name} accessible publicly"

        return False, 0.0, None


class ExposedApiDocsTester(BaseTester):
    """Tester for Publicly Accessible API Documentation"""

    def __init__(self):
        super().__init__()
        self.name = "exposed_api_docs"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for Swagger/OpenAPI documentation pages"""
        if response_status == 200:
            api_docs_patterns = [
                (r"swagger-ui", "Swagger UI"),
                (r'"swagger"\s*:\s*"[0-9.]+"', "Swagger spec"),
                (r'"openapi"\s*:\s*"[0-9.]+"', "OpenAPI spec"),
                (r"swagger-ui-bundle\.js", "Swagger UI bundle"),
                (r"<title>Swagger UI</title>", "Swagger UI page"),
                (r"redoc", "ReDoc API docs"),
                (r"api-docs", "API documentation"),
                (r"graphiql", "GraphiQL interface"),
                (r"GraphQL Playground", "GraphQL Playground"),
                (r'"paths"\s*:\s*\{', "OpenAPI paths object"),
                (r'"info"\s*:\s*\{.*"title"\s*:', "OpenAPI info object"),
            ]

            for pattern, doc_type in api_docs_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.8, f"Exposed API docs: {doc_type} publicly accessible"

            # Check content type for JSON API specs
            content_type = response_headers.get("Content-Type", "")
            if "json" in content_type.lower():
                if re.search(r'"paths"\s*:\s*\{.*"(?:get|post|put|delete)"', response_body, re.DOTALL):
                    return True, 0.85, "Exposed API docs: OpenAPI/Swagger JSON specification exposed"

        return False, 0.0, None


class InsecureCookieFlagsTester(BaseTester):
    """Tester for Missing Secure/HttpOnly/SameSite Cookie Flags"""

    def __init__(self):
        super().__init__()
        self.name = "insecure_cookie_flags"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check Set-Cookie headers for missing security flags"""
        # Collect all Set-Cookie headers
        set_cookie_values = []
        for key, value in response_headers.items():
            if key.lower() == "set-cookie":
                if isinstance(value, list):
                    set_cookie_values.extend(value)
                else:
                    set_cookie_values.append(value)

        if not set_cookie_values:
            return False, 0.0, None

        issues = []
        for cookie in set_cookie_values:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip()

            # Session cookies are more critical
            is_session = any(
                s in cookie_name.lower()
                for s in ["session", "sess", "sid", "token", "auth", "jwt", "csrf"]
            )

            missing_flags = []
            if "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if "samesite" not in cookie_lower:
                missing_flags.append("SameSite")

            if missing_flags:
                severity = "session cookie" if is_session else "cookie"
                issues.append(f"{cookie_name} ({severity}): missing {', '.join(missing_flags)}")

        if issues:
            confidence = 0.8 if any("session cookie" in i for i in issues) else 0.6
            return True, confidence, f"Insecure cookie flags: {'; '.join(issues[:3])}"

        return False, 0.0, None


class HttpSmugglingTester(BaseTester):
    """Tester for HTTP Request Smuggling (CL/TE discrepancy)"""

    def __init__(self):
        super().__init__()
        self.name = "http_smuggling"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for CL/TE discrepancy indicators"""
        # Check for request smuggling indicators
        smuggling_indicators = [
            # Different response than expected
            (r"400 Bad Request.*(?:Content-Length|Transfer-Encoding)", "CL/TE parsing error"),
            (r"(?:invalid|malformed)\s+(?:chunk|transfer.encoding)", "chunked encoding error"),
        ]
        for pattern, desc in smuggling_indicators:
            if re.search(pattern, response_body, re.IGNORECASE | re.DOTALL):
                return True, 0.7, f"HTTP smuggling indicator: {desc}"

        # Check for dual Transfer-Encoding handling
        te_header = response_headers.get("Transfer-Encoding", "")
        cl_header = response_headers.get("Content-Length", "")

        if te_header and cl_header:
            return True, 0.75, "HTTP smuggling: Both Transfer-Encoding and Content-Length in response"

        # Check for timeout-based detection (context)
        if context.get("response_time_ms", 0) > 10000:
            if "transfer-encoding" in payload.lower() or "content-length" in payload.lower():
                return True, 0.6, "HTTP smuggling: Abnormal response delay with CL/TE payload"

        # Check for response desync indicators
        if response_status == 0 or context.get("connection_reset"):
            return True, 0.65, "HTTP smuggling: Connection reset/timeout with smuggling payload"

        return False, 0.0, None


class CachePoisoningTester(BaseTester):
    """Tester for Web Cache Poisoning"""

    def __init__(self):
        super().__init__()
        self.name = "cache_poisoning"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for cached response with injected unkeyed input"""
        if response_status == 200:
            # Check for cache headers indicating response was cached
            cache_indicators = {
                "X-Cache": response_headers.get("X-Cache", ""),
                "CF-Cache-Status": response_headers.get("CF-Cache-Status", ""),
                "Age": response_headers.get("Age", ""),
                "X-Varnish": response_headers.get("X-Varnish", ""),
            }

            is_cached = False
            for header, value in cache_indicators.items():
                if value:
                    if any(hit in value.upper() for hit in ["HIT", "STALE"]):
                        is_cached = True
                        break
                    if header == "Age" and int(value or 0) > 0:
                        is_cached = True
                        break

            # Check if our unkeyed input is reflected in the cached response
            if is_cached or response_headers.get("Cache-Control", ""):
                # Common unkeyed headers that might be reflected
                unkeyed_indicators = [
                    r"X-Forwarded-Host", r"X-Forwarded-Scheme",
                    r"X-Original-URL", r"X-Rewrite-URL",
                ]

                if payload in response_body:
                    if is_cached:
                        return True, 0.9, "Cache poisoning: Injected unkeyed input reflected in cached response"
                    else:
                        return True, 0.7, "Cache poisoning: Unkeyed input reflected - verify caching"

            # Check for Vary header missing expected values
            vary = response_headers.get("Vary", "")
            cache_control = response_headers.get("Cache-Control", "")
            if "no-store" not in cache_control and "private" not in cache_control:
                if payload in response_body:
                    return True, 0.6, "Cache poisoning potential: Input reflected in cacheable response"

        return False, 0.0, None
