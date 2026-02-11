"""
NeuroSploit v3 - Authentication Manager

Autonomous login, session management, multi-user context for
BOLA/BFLA/IDOR testing. Handles login form detection, CSRF extraction,
credential management, and session refresh.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


@dataclass
class Credentials:
    """A set of credentials for testing."""
    username: str
    password: str
    role: str = "user"          # user, admin
    source: str = "provided"    # provided, discovered, default


@dataclass
class SessionContext:
    """Authentication session state."""
    name: str                   # "user_a", "user_b", "admin"
    role: str                   # user, admin
    cookies: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)    # bearer, jwt, api_key
    headers: Dict[str, str] = field(default_factory=dict)   # Authorization: Bearer xxx
    state: str = "unauthenticated"  # unauthenticated, authenticating, authenticated, expired
    login_time: Optional[float] = None
    credential: Optional[Credentials] = None
    login_url: Optional[str] = None
    session_duration: float = 3600.0  # Estimated session lifetime (1 hour default)


@dataclass
class LoginForm:
    """Detected login form."""
    url: str                    # Form action URL
    method: str                 # POST usually
    username_field: str         # name attribute of username input
    password_field: str         # name attribute of password input
    csrf_field: Optional[str] = None
    csrf_value: Optional[str] = None
    extra_fields: Dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0


class AuthManager:
    """Autonomous authentication manager.

    Manages login automation, session tracking, and multi-user
    contexts for access control vulnerability testing.

    Features:
    - Login form detection from HTML
    - CSRF token extraction
    - Credential management (provided + discovered)
    - Session state machine (unauthenticated -> authenticated -> expired)
    - Multi-user contexts for BOLA/BFLA/IDOR testing
    - Auto session refresh on expiry detection
    - Token extraction from responses (JWT, Bearer, API keys)
    """

    # Default credentials to try on admin panels
    DEFAULT_CREDENTIALS = [
        Credentials("admin", "admin", "admin", "default"),
        Credentials("admin", "password", "admin", "default"),
        Credentials("admin", "admin123", "admin", "default"),
        Credentials("root", "root", "admin", "default"),
        Credentials("test", "test", "user", "default"),
        Credentials("user", "user", "user", "default"),
        Credentials("admin", "Password1", "admin", "default"),
        Credentials("administrator", "administrator", "admin", "default"),
    ]

    # Session expiry indicators
    EXPIRY_INDICATORS = [
        "session expired", "session timeout", "please log in",
        "please login", "sign in again", "token expired",
        "unauthorized", "authentication required", "not authenticated",
        "jwt expired", "invalid token", "access token expired",
    ]

    # Login success indicators
    SUCCESS_INDICATORS = [
        "welcome", "dashboard", "my account", "profile",
        "logged in", "sign out", "logout", "log out",
        "home", "settings", "preferences",
    ]

    # Login failure indicators
    FAILURE_INDICATORS = [
        "invalid", "incorrect", "wrong", "failed", "error",
        "denied", "bad credentials", "authentication failed",
        "login failed", "invalid username", "invalid password",
    ]

    def __init__(self, request_engine=None, recon=None):
        self.request_engine = request_engine
        self.recon = recon

        # Credential store
        self._credentials: Dict[str, List[Credentials]] = {
            "user": [],
            "admin": [],
        }

        # Session contexts
        self.contexts: Dict[str, SessionContext] = {
            "user_a": SessionContext(name="user_a", role="user"),
            "user_b": SessionContext(name="user_b", role="user"),
            "admin": SessionContext(name="admin", role="admin"),
        }

        # Discovered login forms
        self._login_forms: List[LoginForm] = []
        self._login_attempts = 0
        self._successful_logins = 0

    # --- Credential Management -------------------------------------------

    def add_credentials(self, username: str, password: str, role: str = "user", source: str = "provided"):
        """Add credentials for testing."""
        cred = Credentials(username, password, role, source)
        self._credentials.setdefault(role, []).append(cred)
        logger.debug(f"Added {role} credentials: {username} (source: {source})")

    def add_discovered_credentials(self, creds_list: List[Dict]):
        """Add credentials discovered during testing (from info disclosure, etc.)."""
        for cred_info in creds_list:
            username = cred_info.get("username", "")
            password = cred_info.get("password", "")
            if username and password:
                self.add_credentials(username, password, role="user", source="discovered")

    def get_credentials_for_role(self, role: str) -> List[Credentials]:
        """Get all credentials for a role."""
        creds = self._credentials.get(role, [])
        if not creds and role == "admin":
            return self.DEFAULT_CREDENTIALS[:4]  # Only admin defaults
        if not creds and role == "user":
            return self.DEFAULT_CREDENTIALS[4:6]  # Only user defaults
        return creds

    # --- Login Form Detection --------------------------------------------

    def detect_login_forms(self, html: str, page_url: str) -> List[LoginForm]:
        """Detect login forms in HTML content."""
        forms = []

        # Find all <form> tags
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>',
            re.DOTALL | re.IGNORECASE
        )

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            form_inner = form_match.group(1)

            # Check if this looks like a login form
            has_password = bool(re.search(r'type=["\']password["\']', form_inner, re.I))
            if not has_password:
                continue

            # Extract form action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            action = action_match.group(1) if action_match else page_url
            if not action.startswith("http"):
                action = urljoin(page_url, action)

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            method = (method_match.group(1) if method_match else "POST").upper()

            # Find username field
            username_field = self._find_username_field(form_inner)

            # Find password field
            password_field = self._find_field_name(form_inner, r'type=["\']password["\']')

            # Find CSRF token
            csrf_field, csrf_value = self._find_csrf_token(form_inner)

            # Find hidden fields
            extra_fields = self._find_hidden_fields(form_inner)
            if csrf_field and csrf_field in extra_fields:
                del extra_fields[csrf_field]

            # Calculate confidence
            confidence = 0.5  # Has password field
            login_keywords = ["login", "signin", "sign-in", "auth", "log-in", "session"]
            if any(kw in action.lower() for kw in login_keywords):
                confidence += 0.3
            if any(kw in form_html.lower() for kw in login_keywords):
                confidence += 0.2

            if username_field and password_field:
                forms.append(LoginForm(
                    url=action,
                    method=method,
                    username_field=username_field,
                    password_field=password_field,
                    csrf_field=csrf_field,
                    csrf_value=csrf_value,
                    extra_fields=extra_fields,
                    confidence=min(1.0, confidence),
                ))

        # Sort by confidence
        forms.sort(key=lambda f: f.confidence, reverse=True)
        self._login_forms.extend(forms)
        return forms

    def _find_username_field(self, html: str) -> Optional[str]:
        """Find the username/email input field name."""
        # Priority: explicit username/email fields
        patterns = [
            r'name=["\']([^"\']*(?:user|login|email|account)[^"\']*)["\']',
            r'name=["\']([^"\']*)["\'].*?type=["\'](?:text|email)["\']',
            r'type=["\'](?:text|email)["\'].*?name=["\']([^"\']*)["\']',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1)
        return None

    def _find_field_name(self, html: str, type_pattern: str) -> Optional[str]:
        """Find field name for a given input type pattern."""
        # Try: name="x" ... type="password"
        match = re.search(
            r'name=["\']([^"\']+)["\'][^>]*' + type_pattern,
            html, re.I
        )
        if match:
            return match.group(1)
        # Try: type="password" ... name="x"
        match = re.search(
            type_pattern + r'[^>]*name=["\']([^"\']+)["\']',
            html, re.I
        )
        if match:
            return match.group(1)
        return None

    def _find_csrf_token(self, html: str):
        """Find CSRF token in form."""
        csrf_patterns = [
            r'name=["\']([^"\']*(?:csrf|_token|csrfmiddlewaretoken|__RequestVerificationToken|authenticity_token|_csrf_token)[^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
            r'value=["\']([^"\']*)["\'][^>]*name=["\']([^"\']*(?:csrf|_token|csrfmiddlewaretoken)[^"\']*)["\']',
        ]
        for pattern in csrf_patterns:
            match = re.search(pattern, html, re.I)
            if match:
                groups = match.groups()
                if "csrf" in groups[0].lower() or "_token" in groups[0].lower():
                    return groups[0], groups[1]
                return groups[1], groups[0]
        return None, None

    def _find_hidden_fields(self, html: str) -> Dict[str, str]:
        """Extract all hidden field name-value pairs."""
        fields = {}
        pattern = re.compile(
            r'type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            re.I
        )
        for match in pattern.finditer(html):
            fields[match.group(1)] = match.group(2)

        # Also try reverse order (name before type)
        pattern2 = re.compile(
            r'name=["\']([^"\']+)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\']',
            re.I
        )
        for match in pattern2.finditer(html):
            fields[match.group(1)] = match.group(2)

        return fields

    # --- Authentication --------------------------------------------------

    async def authenticate(self, context_name: str = "user_a") -> bool:
        """Attempt to authenticate a session context.

        Tries login forms with available credentials.
        Returns True if authentication succeeded.
        """
        if not self.request_engine:
            return False

        ctx = self.contexts.get(context_name)
        if not ctx:
            return False

        ctx.state = "authenticating"
        creds = self.get_credentials_for_role(ctx.role)

        if not creds:
            logger.debug(f"No credentials available for {context_name} ({ctx.role})")
            ctx.state = "unauthenticated"
            return False

        # Find login forms if not already discovered
        if not self._login_forms:
            await self._discover_login_forms()

        if not self._login_forms:
            logger.debug("No login forms found")
            ctx.state = "unauthenticated"
            return False

        # Try each form with each credential
        for form in self._login_forms:
            for cred in creds:
                self._login_attempts += 1
                success = await self._attempt_login(form, cred, ctx)
                if success:
                    ctx.state = "authenticated"
                    ctx.credential = cred
                    ctx.login_time = time.time()
                    ctx.login_url = form.url
                    self._successful_logins += 1
                    logger.info(f"Login success: {context_name} as {cred.username} ({cred.role})")
                    return True

        ctx.state = "unauthenticated"
        return False

    async def _discover_login_forms(self):
        """Discover login forms by crawling common login paths."""
        if not self.request_engine:
            return

        # Use recon data if available
        target = ""
        if self.recon and hasattr(self.recon, "target"):
            target = self.recon.target

        if not target:
            return

        login_paths = [
            "/login", "/signin", "/sign-in", "/auth/login",
            "/user/login", "/admin/login", "/api/auth/login",
            "/account/login", "/wp-login.php", "/admin",
        ]

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in login_paths:
            try:
                url = f"{base}{path}"
                result = await self.request_engine.request(url, method="GET")
                if result and result.status == 200 and result.body:
                    forms = self.detect_login_forms(result.body, url)
                    if forms:
                        logger.debug(f"Found {len(forms)} login form(s) at {url}")
                        return  # Found forms, stop searching
            except Exception:
                continue

    async def _attempt_login(self, form: LoginForm, cred: Credentials, ctx: SessionContext) -> bool:
        """Attempt login with a specific form and credential."""
        try:
            # Build form data
            data = {}

            # Add hidden fields first
            data.update(form.extra_fields)

            # Refresh CSRF token if needed
            if form.csrf_field:
                fresh_csrf = await self._refresh_csrf(form)
                if fresh_csrf:
                    data[form.csrf_field] = fresh_csrf
                elif form.csrf_value:
                    data[form.csrf_field] = form.csrf_value

            # Add credentials
            data[form.username_field] = cred.username
            data[form.password_field] = cred.password

            # Submit form
            result = await self.request_engine.request(
                form.url,
                method=form.method,
                data=data,
                allow_redirects=True,
            )

            if not result:
                return False

            # Check for login success
            success = self._detect_login_success(
                result.body, result.status, result.headers
            )

            if success:
                # Extract tokens and cookies
                self._extract_session_data(result, ctx)
                return True

            return False

        except Exception as e:
            logger.debug(f"Login attempt failed: {e}")
            return False

    async def _refresh_csrf(self, form: LoginForm) -> Optional[str]:
        """Fetch fresh CSRF token from the login page."""
        try:
            # GET the form page to get a fresh token
            page_url = form.url.replace(urlparse(form.url).path, "") + urlparse(form.url).path
            result = await self.request_engine.request(page_url, method="GET")
            if result and result.body:
                _, csrf_value = self._find_csrf_token(result.body)
                return csrf_value
        except Exception:
            pass
        return None

    def _detect_login_success(self, body: str, status: int, headers: Dict) -> bool:
        """Detect if login was successful."""
        body_lower = (body or "").lower()

        # Check for redirect to authenticated area
        if status in (301, 302, 303, 307):
            location = headers.get("Location", headers.get("location", ""))
            if any(kw in location.lower() for kw in ["dashboard", "home", "profile", "admin"]):
                return True

        # Check for Set-Cookie (session creation)
        has_session_cookie = any(
            "set-cookie" in k.lower() for k in headers
        )

        # Check for success indicators in body
        success_count = sum(1 for kw in self.SUCCESS_INDICATORS if kw in body_lower)
        failure_count = sum(1 for kw in self.FAILURE_INDICATORS if kw in body_lower)

        # Success if: session cookie + success indicators and no failure indicators
        if has_session_cookie and success_count > 0 and failure_count == 0:
            return True

        # Success if: 200 OK + strong success indicators + no failure
        if status == 200 and success_count >= 2 and failure_count == 0:
            return True

        return False

    def _extract_session_data(self, result, ctx: SessionContext):
        """Extract tokens and cookies from a successful login response."""
        # Extract cookies from Set-Cookie headers
        for key, value in result.headers.items():
            if key.lower() == "set-cookie":
                cookie_parts = value.split(";")[0].split("=", 1)
                if len(cookie_parts) == 2:
                    ctx.cookies[cookie_parts[0].strip()] = cookie_parts[1].strip()

        # Extract tokens from response body (JSON)
        body = result.body or ""
        token_patterns = [
            (r'"(?:access_token|token|jwt|bearer|id_token)"\s*:\s*"([^"]+)"', "bearer"),
            (r'"(?:api_key|apikey|api-key)"\s*:\s*"([^"]+)"', "api_key"),
            (r'"(?:refresh_token)"\s*:\s*"([^"]+)"', "refresh"),
        ]

        for pattern, token_type in token_patterns:
            match = re.search(pattern, body, re.I)
            if match:
                ctx.tokens[token_type] = match.group(1)

        # Build auth headers
        if "bearer" in ctx.tokens:
            ctx.headers["Authorization"] = f"Bearer {ctx.tokens['bearer']}"
        elif "api_key" in ctx.tokens:
            ctx.headers["X-API-Key"] = ctx.tokens["api_key"]

    # --- Session Management ----------------------------------------------

    def detect_session_expiry(self, body: str, status: int) -> bool:
        """Check if a response indicates session expiry."""
        if status in (401, 403):
            return True

        body_lower = (body or "").lower()
        return any(kw in body_lower for kw in self.EXPIRY_INDICATORS)

    async def refresh(self, context_name: Optional[str] = None) -> bool:
        """Refresh an expired session by re-authenticating.

        If context_name is None, refresh all expired sessions.
        """
        contexts_to_refresh = []
        if context_name:
            ctx = self.contexts.get(context_name)
            if ctx and ctx.state == "expired":
                contexts_to_refresh.append(context_name)
        else:
            for name, ctx in self.contexts.items():
                if ctx.state == "expired":
                    contexts_to_refresh.append(name)

        results = []
        for name in contexts_to_refresh:
            ctx = self.contexts[name]
            ctx.state = "unauthenticated"
            ctx.cookies.clear()
            ctx.tokens.clear()
            ctx.headers.clear()
            success = await self.authenticate(name)
            results.append(success)

        return all(results) if results else False

    def check_and_mark_expiry(self, context_name: str, body: str, status: int) -> bool:
        """Check response for expiry and mark context if expired.

        Returns True if session was detected as expired.
        """
        ctx = self.contexts.get(context_name)
        if not ctx or ctx.state != "authenticated":
            return False

        if self.detect_session_expiry(body, status):
            ctx.state = "expired"
            logger.info(f"Session expired for {context_name}")
            return True

        # Check time-based expiry
        if ctx.login_time and (time.time() - ctx.login_time) > ctx.session_duration:
            ctx.state = "expired"
            logger.info(f"Session timeout for {context_name}")
            return True

        return False

    # --- Request Integration ---------------------------------------------

    def get_context(self, context_name: str) -> Optional[SessionContext]:
        """Get a session context by name."""
        return self.contexts.get(context_name)

    def get_request_kwargs(self, context_name: str) -> Dict:
        """Get headers and cookies for requests as a context.

        Returns dict with 'headers' and 'cookies' ready for request_engine.
        """
        ctx = self.contexts.get(context_name)
        if not ctx or ctx.state != "authenticated":
            return {"headers": {}, "cookies": {}}

        return {
            "headers": dict(ctx.headers),
            "cookies": dict(ctx.cookies),
        }

    def is_authenticated(self, context_name: str) -> bool:
        """Check if a context is currently authenticated."""
        ctx = self.contexts.get(context_name)
        return ctx is not None and ctx.state == "authenticated"

    def get_auth_summary(self) -> Dict:
        """Get summary of authentication state for reporting."""
        return {
            "contexts": {
                name: {
                    "state": ctx.state,
                    "role": ctx.role,
                    "credential": ctx.credential.username if ctx.credential else None,
                    "has_tokens": bool(ctx.tokens),
                    "has_cookies": bool(ctx.cookies),
                }
                for name, ctx in self.contexts.items()
            },
            "login_forms_found": len(self._login_forms),
            "login_attempts": self._login_attempts,
            "successful_logins": self._successful_logins,
            "credentials_available": {
                role: len(creds)
                for role, creds in self._credentials.items()
            },
        }
