"""
NeuroSploit v3 - Resilient Request Engine

Wraps aiohttp session with retry, rate limiting, circuit breaker, 
and error classification for autonomous pentesting.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Optional, Any

logger = logging.getLogger(__name__)


class ErrorType(Enum):
    SUCCESS = "success"
    CLIENT_ERROR = "client_error"       # 4xx (not 429)
    RATE_LIMITED = "rate_limited"        # 429
    WAF_BLOCKED = "waf_blocked"         # 403 + WAF indicators
    SERVER_ERROR = "server_error"       # 5xx
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"


@dataclass
class RequestResult:
    status: int
    body: str
    headers: Dict[str, str]
    url: str
    error_type: ErrorType = ErrorType.SUCCESS
    retry_count: int = 0
    response_time: float = 0.0


@dataclass
class HostState:
    """Per-host tracking for rate limiting and circuit breaker."""
    host: str
    request_count: int = 0
    error_count: int = 0
    consecutive_failures: int = 0
    last_request_time: float = 0.0
    delay: float = 0.1
    circuit_open: bool = False
    circuit_open_time: float = 0.0
    avg_response_time: float = 0.0
    # Adaptive timeout
    _response_times: list = field(default_factory=list)


class RequestEngine:
    """Resilient HTTP request engine with retry, rate limiting, and circuit breaker.
    
    Features:
    - Error classification (7 types)
    - Smart retry with exponential backoff (1s, 2s, 4s) on 5xx/timeout/connection
    - No retry on 4xx client errors
    - Per-host rate limiting with auto-increase on 429
    - Circuit breaker: N consecutive failures → open circuit for cooldown period
    - Adaptive timeouts based on target response times
    - Request counting and statistics
    - Cancel-aware (checks is_cancelled before each request)
    """

    WAF_INDICATORS = [
        "cloudflare", "incapsula", "sucuri", "akamai", "imperva",
        "mod_security", "modsecurity", "request blocked", "access denied",
        "waf", "web application firewall", "barracuda", "fortinet",
        "f5 big-ip", "citrix", "azure firewall",
    ]

    def __init__(
        self,
        session,  # aiohttp.ClientSession
        default_delay: float = 0.1,
        max_retries: int = 3,
        circuit_threshold: int = 5,
        circuit_timeout: float = 30.0,
        default_timeout: float = 10.0,
        is_cancelled_fn: Optional[Callable] = None,
    ):
        self.session = session
        self.default_delay = default_delay
        self.max_retries = max_retries
        self.circuit_threshold = circuit_threshold
        self.circuit_timeout = circuit_timeout
        self.default_timeout = default_timeout
        self.is_cancelled = is_cancelled_fn or (lambda: False)
        
        # Per-host state
        self._hosts: Dict[str, HostState] = {}
        
        # Global stats
        self.total_requests = 0
        self.total_errors = 0
        self.errors_by_type: Dict[str, int] = {e.value: 0 for e in ErrorType}
    
    def _get_host(self, url: str) -> HostState:
        """Get or create host state."""
        from urllib.parse import urlparse
        host = urlparse(url).netloc
        if host not in self._hosts:
            self._hosts[host] = HostState(host=host, delay=self.default_delay)
        return self._hosts[host]
    
    def _classify_error(self, status: int, body: str, exception: Optional[Exception] = None) -> ErrorType:
        """Classify response/error into ErrorType."""
        if exception:
            exc_name = type(exception).__name__.lower()
            if "timeout" in exc_name or "timedout" in exc_name:
                return ErrorType.TIMEOUT
            return ErrorType.CONNECTION_ERROR
        
        if 200 <= status < 400:
            return ErrorType.SUCCESS
        if status == 429:
            return ErrorType.RATE_LIMITED
        if status == 403:
            body_lower = body.lower() if body else ""
            if any(w in body_lower for w in self.WAF_INDICATORS):
                return ErrorType.WAF_BLOCKED
            return ErrorType.CLIENT_ERROR
        if 400 <= status < 500:
            return ErrorType.CLIENT_ERROR
        if status >= 500:
            return ErrorType.SERVER_ERROR
        
        return ErrorType.SUCCESS
    
    def _should_retry(self, error_type: ErrorType) -> bool:
        """Determine if this error type warrants retry."""
        return error_type in (
            ErrorType.SERVER_ERROR,
            ErrorType.TIMEOUT,
            ErrorType.CONNECTION_ERROR,
            ErrorType.RATE_LIMITED,
        )
    
    def _get_backoff_delay(self, attempt: int, error_type: ErrorType) -> float:
        """Calculate exponential backoff delay."""
        if error_type == ErrorType.RATE_LIMITED:
            return min(30.0, 2.0 * (2 ** attempt))  # Longer for rate limiting
        return min(10.0, 1.0 * (2 ** attempt))  # 1s, 2s, 4s, ...
    
    def _get_adaptive_timeout(self, host_state: HostState) -> float:
        """Calculate adaptive timeout based on target response history."""
        if not host_state._response_times:
            return self.default_timeout
        avg = sum(host_state._response_times[-20:]) / len(host_state._response_times[-20:])
        # 3x average with min 5s, max 30s
        return max(5.0, min(30.0, avg * 3.0))
    
    def _check_circuit(self, host_state: HostState) -> bool:
        """Check if circuit breaker allows request. Returns True if allowed."""
        if not host_state.circuit_open:
            return True
        # Check if cooldown has passed
        elapsed = time.time() - host_state.circuit_open_time
        if elapsed >= self.circuit_timeout:
            # Half-open: allow one test request
            host_state.circuit_open = False
            host_state.consecutive_failures = 0
            logger.debug(f"Circuit half-open for {host_state.host}")
            return True
        return False
    
    def _update_circuit(self, host_state: HostState, error_type: ErrorType):
        """Update circuit breaker state after a request."""
        if error_type == ErrorType.SUCCESS:
            host_state.consecutive_failures = 0
            host_state.circuit_open = False
        elif error_type in (ErrorType.SERVER_ERROR, ErrorType.TIMEOUT, ErrorType.CONNECTION_ERROR):
            host_state.consecutive_failures += 1
            if host_state.consecutive_failures >= self.circuit_threshold:
                host_state.circuit_open = True
                host_state.circuit_open_time = time.time()
                logger.warning(f"Circuit OPEN for {host_state.host} after {host_state.consecutive_failures} failures")
    
    async def request(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Any] = None,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        allow_redirects: bool = False,
        timeout: Optional[float] = None,
        json_data: Optional[Dict] = None,
    ) -> Optional[RequestResult]:
        """Make an HTTP request with retry, rate limiting, and circuit breaker.
        
        Returns RequestResult on success (even 4xx), None on total failure.
        """
        if self.is_cancelled():
            return None
        
        host_state = self._get_host(url)
        
        # Circuit breaker check
        if not self._check_circuit(host_state):
            logger.debug(f"Circuit open for {host_state.host}, skipping")
            return RequestResult(
                status=0, body="", headers={}, url=url,
                error_type=ErrorType.CONNECTION_ERROR
            )
        
        # Rate limiting: wait per-host delay
        now = time.time()
        elapsed = now - host_state.last_request_time
        if elapsed < host_state.delay:
            await asyncio.sleep(host_state.delay - elapsed)
        
        # Determine timeout
        req_timeout = timeout or self._get_adaptive_timeout(host_state)
        
        # Retry loop
        last_error_type = ErrorType.CONNECTION_ERROR
        for attempt in range(self.max_retries + 1):
            if self.is_cancelled():
                return None
            
            start_time = time.time()
            try:
                import aiohttp
                kwargs = {
                    "method": method,
                    "url": url,
                    "allow_redirects": allow_redirects,
                    "timeout": aiohttp.ClientTimeout(total=req_timeout),
                    "ssl": False,
                }
                if params:
                    kwargs["params"] = params
                if data:
                    kwargs["data"] = data
                if json_data:
                    kwargs["json"] = json_data
                if headers:
                    kwargs["headers"] = headers
                if cookies:
                    kwargs["cookies"] = cookies
                
                async with self.session.request(**kwargs) as resp:
                    body = await resp.text()
                    resp_time = time.time() - start_time
                    resp_headers = dict(resp.headers)
                    status = resp.status
                
                # Track response time
                host_state._response_times.append(resp_time)
                if len(host_state._response_times) > 50:
                    host_state._response_times = host_state._response_times[-30:]
                host_state.avg_response_time = sum(host_state._response_times) / len(host_state._response_times)
                
                # Classify
                error_type = self._classify_error(status, body)
                last_error_type = error_type
                
                # Update stats
                self.total_requests += 1
                host_state.request_count += 1
                host_state.last_request_time = time.time()
                self.errors_by_type[error_type.value] = self.errors_by_type.get(error_type.value, 0) + 1
                
                # Update circuit breaker
                self._update_circuit(host_state, error_type)
                
                # Handle rate limiting
                if error_type == ErrorType.RATE_LIMITED:
                    # Check Retry-After header
                    retry_after = resp_headers.get("Retry-After", "")
                    if retry_after.isdigit():
                        wait = min(60.0, float(retry_after))
                    else:
                        wait = self._get_backoff_delay(attempt, error_type)
                    # Increase per-host delay
                    host_state.delay = min(5.0, host_state.delay * 2)
                    logger.debug(f"Rate limited on {host_state.host}, delay now {host_state.delay:.1f}s")
                    if attempt < self.max_retries:
                        await asyncio.sleep(wait)
                        continue
                
                # Retry on server errors
                if self._should_retry(error_type) and attempt < self.max_retries:
                    wait = self._get_backoff_delay(attempt, error_type)
                    logger.debug(f"Retry {attempt+1}/{self.max_retries} for {url} ({error_type.value}), wait {wait:.1f}s")
                    await asyncio.sleep(wait)
                    continue
                
                # Return result (success or non-retryable error)
                if error_type != ErrorType.SUCCESS:
                    self.total_errors += 1
                    host_state.error_count += 1
                
                return RequestResult(
                    status=status,
                    body=body,
                    headers=resp_headers,
                    url=str(resp.url),
                    error_type=error_type,
                    retry_count=attempt,
                    response_time=resp_time,
                )
                
            except asyncio.TimeoutError:
                resp_time = time.time() - start_time
                last_error_type = ErrorType.TIMEOUT
                self.total_requests += 1
                self.total_errors += 1
                host_state.request_count += 1
                host_state.error_count += 1
                host_state.last_request_time = time.time()
                self.errors_by_type["timeout"] = self.errors_by_type.get("timeout", 0) + 1
                self._update_circuit(host_state, ErrorType.TIMEOUT)
                
                if attempt < self.max_retries:
                    wait = self._get_backoff_delay(attempt, ErrorType.TIMEOUT)
                    logger.debug(f"Timeout on {url}, retry {attempt+1}/{self.max_retries}")
                    await asyncio.sleep(wait)
                    continue
                    
            except Exception as e:
                resp_time = time.time() - start_time
                error_type = self._classify_error(0, "", e)
                last_error_type = error_type
                self.total_requests += 1
                self.total_errors += 1
                host_state.request_count += 1
                host_state.error_count += 1
                host_state.last_request_time = time.time()
                self.errors_by_type[error_type.value] = self.errors_by_type.get(error_type.value, 0) + 1
                self._update_circuit(host_state, error_type)
                
                if self._should_retry(error_type) and attempt < self.max_retries:
                    wait = self._get_backoff_delay(attempt, error_type)
                    logger.debug(f"Error on {url}: {e}, retry {attempt+1}")
                    await asyncio.sleep(wait)
                    continue
                
                logger.debug(f"Request failed after {attempt+1} attempts: {url} - {e}")
        
        # All retries exhausted
        return RequestResult(
            status=0, body="", headers={}, url=url,
            error_type=last_error_type, retry_count=self.max_retries,
        )
    
    def get_stats(self) -> Dict:
        """Get request statistics."""
        host_stats = {}
        for host, state in self._hosts.items():
            host_stats[host] = {
                "requests": state.request_count,
                "errors": state.error_count,
                "avg_response_time": round(state.avg_response_time, 3),
                "delay": round(state.delay, 3),
                "circuit_open": state.circuit_open,
                "consecutive_failures": state.consecutive_failures,
            }
        return {
            "total_requests": self.total_requests,
            "total_errors": self.total_errors,
            "errors_by_type": dict(self.errors_by_type),
            "hosts": host_stats,
        }
    
    def reset_stats(self):
        """Reset all statistics."""
        self.total_requests = 0
        self.total_errors = 0
        self.errors_by_type = {e.value: 0 for e in ErrorType}
        self._hosts.clear()
