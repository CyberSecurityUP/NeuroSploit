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


class DomClobberingTester(BaseTester):
    """Tester for DOM Clobbering vulnerability"""

    def __init__(self):
        super().__init__()
        self.name = "dom_clobbering"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for HTML injection that could override JS variables via DOM clobbering"""
        if response_status == 200:
            # Check if injected HTML with id/name attributes is reflected
            clobber_patterns = [
                r'<(?:a|form|img|input|iframe|embed|object)\s+[^>]*(?:id|name)\s*=\s*["\']?(?:' + re.escape(payload.split("=")[0] if "=" in payload else payload) + r')',
                r'<a\s+[^>]*id=["\'][^"\']+["\'][^>]*href=["\']',
                r'<form\s+[^>]*name=["\'][^"\']+["\']',
            ]
            for pattern in clobber_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.8, "DOM Clobbering: Injected HTML with id/name attribute reflected"

            # Check for common clobberable global variables
            clobber_targets = [
                r'<[^>]+id=["\'](?:location|document|window|self|top|frames|opener|parent)["\']',
                r'<[^>]+name=["\'](?:location|document|window|self|top|frames|opener|parent)["\']',
            ]
            for pattern in clobber_targets:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.85, "DOM Clobbering: HTML element with JS global variable name injected"

        return False, 0.0, None


class PostMessageVulnTester(BaseTester):
    """Tester for postMessage vulnerability (missing origin check)"""

    def __init__(self):
        super().__init__()
        self.name = "postmessage_vuln"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for addEventListener('message') without origin validation"""
        if response_status == 200:
            # Find message event listeners
            message_listener = re.search(
                r'addEventListener\s*\(\s*["\']message["\']',
                response_body
            )
            if message_listener:
                # Check if origin is NOT validated nearby
                # Get surrounding context (500 chars after listener)
                listener_pos = message_listener.start()
                handler_block = response_body[listener_pos:listener_pos + 500]

                origin_checks = [
                    r'\.origin\s*[!=]==?\s*["\']',
                    r'event\.origin',
                    r'e\.origin',
                    r'msg\.origin',
                    r'origin\s*===',
                ]
                has_origin_check = any(re.search(p, handler_block) for p in origin_checks)

                if not has_origin_check:
                    return True, 0.85, "postMessage vulnerability: Message listener without origin validation"
                else:
                    # Origin check exists but might be weak
                    if re.search(r'\.origin\s*[!=]==?\s*["\']["\']', handler_block):
                        return True, 0.7, "postMessage vulnerability: Origin check appears to be empty string"

            # Check for postMessage with wildcard origin
            wildcard_post = re.search(
                r'\.postMessage\s*\([^)]+,\s*["\']\*["\']',
                response_body
            )
            if wildcard_post:
                return True, 0.75, "postMessage vulnerability: postMessage with wildcard '*' target origin"

        return False, 0.0, None


class WebsocketHijackTester(BaseTester):
    """Tester for WebSocket Cross-Origin Hijacking"""

    def __init__(self):
        super().__init__()
        self.name = "websocket_hijack"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for WebSocket connections accepting cross-origin requests"""
        # WebSocket upgrade accepted (101 Switching Protocols)
        if response_status == 101:
            # Check if Origin header was sent and accepted
            upgrade = response_headers.get("Upgrade", "").lower()
            if upgrade == "websocket":
                return True, 0.8, "WebSocket hijack: Cross-origin WebSocket upgrade accepted"

        # Check for WebSocket endpoint in response without origin validation
        if response_status == 200:
            ws_patterns = [
                r'new\s+WebSocket\s*\(\s*["\']wss?://',
                r'ws://[^"\'>\s]+',
                r'wss://[^"\'>\s]+',
            ]
            for pattern in ws_patterns:
                if re.search(pattern, response_body):
                    # Check for lack of CORS-like origin checking
                    if "origin" not in response_body.lower() or context.get("cross_origin_accepted"):
                        return True, 0.7, "WebSocket hijack: WebSocket endpoint found without apparent origin validation"

        # 403 on WebSocket with wrong origin is good (not vulnerable)
        if response_status == 403:
            return False, 0.0, None

        return False, 0.0, None


class PrototypePollutionTester(BaseTester):
    """Tester for JavaScript Prototype Pollution"""

    def __init__(self):
        super().__init__()
        self.name = "prototype_pollution"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for __proto__ pollution indicators"""
        if response_status == 200:
            # Check if __proto__ payload was processed
            proto_indicators = [
                r'__proto__',
                r'constructor\.prototype',
                r'Object\.prototype',
            ]

            # Payload should contain proto pollution attempt
            is_proto_payload = any(
                ind in payload for ind in ["__proto__", "constructor", "prototype"]
            )

            if is_proto_payload:
                # Check for pollution effect in response
                pollution_effects = [
                    r'"__proto__"\s*:\s*\{',
                    r'"polluted"\s*:\s*true',
                    r'"isAdmin"\s*:\s*true',
                    r'"__proto__":\s*\{[^}]*\}',
                ]
                for pattern in pollution_effects:
                    if re.search(pattern, response_body, re.IGNORECASE):
                        return True, 0.85, "Prototype pollution: __proto__ property accepted and reflected"

                # Check if server processed the prototype chain modification
                if response_status == 200 and "__proto__" in response_body:
                    return True, 0.7, "Prototype pollution: __proto__ present in server response"

                # Check for error indicating proto processing
                if re.search(r"(?:cannot|unable to).*(?:merge|assign|extend).*proto", response_body, re.IGNORECASE):
                    return True, 0.6, "Prototype pollution: Server attempted to process __proto__"

        return False, 0.0, None


class CssInjectionTester(BaseTester):
    """Tester for CSS Injection vulnerability"""

    def __init__(self):
        super().__init__()
        self.name = "css_injection"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for CSS code rendered in style context"""
        if response_status == 200:
            # Check if CSS payload is reflected in style context
            css_contexts = [
                # Inside <style> tags
                r'<style[^>]*>(?:[^<]*?)' + re.escape(payload)[:30].replace("\\", "\\\\"),
                # Inside style attribute
                r'style\s*=\s*["\'][^"\']*' + re.escape(payload)[:30].replace("\\", "\\\\"),
            ]

            for pattern in css_contexts:
                try:
                    if re.search(pattern, response_body, re.IGNORECASE | re.DOTALL):
                        return True, 0.85, "CSS injection: Payload reflected in style context"
                except re.error:
                    continue

            # Check for common CSS injection payloads reflected
            css_attack_patterns = [
                r'expression\s*\(',
                r'url\s*\(\s*["\']?javascript:',
                r'@import\s+["\']?https?://',
                r'background:\s*url\s*\(\s*["\']?https?://[^"\')\s]*attacker',
                r'behavior:\s*url\s*\(',
                r'-moz-binding:\s*url\s*\(',
            ]
            for pattern in css_attack_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.8, "CSS injection: Dangerous CSS property reflected"

        return False, 0.0, None


class TabnabbingTester(BaseTester):
    """Tester for Reverse Tabnabbing vulnerability"""

    def __init__(self):
        super().__init__()
        self.name = "tabnabbing"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for target=_blank links without rel=noopener"""
        if response_status == 200:
            # Find all target=_blank links
            blank_links = re.finditer(
                r'<a\s+[^>]*target\s*=\s*["\']_blank["\'][^>]*>',
                response_body,
                re.IGNORECASE
            )

            vulnerable_count = 0
            for match in blank_links:
                link_tag = match.group(0)
                # Check for rel=noopener or rel=noreferrer
                has_protection = re.search(
                    r'rel\s*=\s*["\'][^"\']*(?:noopener|noreferrer)[^"\']*["\']',
                    link_tag,
                    re.IGNORECASE
                )
                if not has_protection:
                    vulnerable_count += 1

            if vulnerable_count > 0:
                confidence = min(0.5 + vulnerable_count * 0.1, 0.8)
                return True, confidence, f"Tabnabbing: {vulnerable_count} target=_blank link(s) without rel=noopener/noreferrer"

        return False, 0.0, None
