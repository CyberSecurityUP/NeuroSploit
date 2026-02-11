"""
NeuroSploit v3 - Access Control Learning Engine

Adaptive learning system for BOLA/BFLA/IDOR and other access control testing.
Records test outcomes and response patterns to improve future evaluations.

Key insight: HTTP status codes are unreliable for access control testing.
This module learns from actual response DATA patterns to distinguish:
- True positives (cross-user data access)
- False positives (error messages, login pages, empty responses with 200 status)

Usage:
    learner = AccessControlLearner()
    # Record a test outcome
    learner.record_test(vuln_type, url, response_body, is_true_positive, pattern_notes)
    # Get learned patterns for a target
    patterns = learner.get_patterns_for_target(domain)
    # Get learning context for AI prompts
    context = learner.get_learning_context(vuln_type)
"""

import json
import logging
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent.parent / "data"
LEARNING_FILE = DATA_DIR / "access_control_learning.json"


@dataclass
class ResponsePattern:
    """A learned response pattern from access control testing."""
    pattern_type: str          # "denial", "empty", "login_page", "data_leak", "public_data"
    indicators: List[str]      # Strings/patterns that identify this response type
    is_false_positive: bool    # True if this pattern indicates a false positive
    confidence: float          # 0.0-1.0 how reliable this pattern is
    example_body: str          # Truncated example response body
    vuln_type: str             # bola, bfla, idor, etc.
    target_domain: str         # Domain this was learned from
    timestamp: str             # When this was learned


@dataclass
class TestRecord:
    """Record of an access control test outcome."""
    vuln_type: str
    target_url: str
    status_code: int
    response_length: int
    is_true_positive: bool
    pattern_type: str          # What pattern was identified
    key_indicators: List[str]  # What strings/patterns were decisive
    notes: str                 # Human or AI notes about why this was TP/FP
    timestamp: str


class AccessControlLearner:
    """Adaptive learning engine for access control vulnerability testing.

    Learns from test outcomes to identify response patterns that indicate
    true vs false positives for BOLA, BFLA, IDOR, and related vuln types.
    """

    MAX_RECORDS = 500
    MAX_PATTERNS = 200

    # Pre-seeded patterns from known false positive scenarios
    DEFAULT_PATTERNS: List[Dict] = [
        {
            "pattern_type": "denial_200",
            "indicators": ["unauthorized", "forbidden", "access denied", "not authorized",
                          "permission denied", "insufficient privileges"],
            "is_false_positive": True,
            "confidence": 0.9,
            "description": "Server returns 200 OK but body contains access denial message",
        },
        {
            "pattern_type": "empty_200",
            "indicators": ["[]", "{}", '""', "null", ""],
            "is_false_positive": True,
            "confidence": 0.85,
            "description": "Server returns 200 OK with empty/null response body",
        },
        {
            "pattern_type": "login_redirect",
            "indicators": ["type=\"password\"", "sign in", "log in", "login",
                          "authentication required"],
            "is_false_positive": True,
            "confidence": 0.95,
            "description": "Server returns 200 OK but body is a login page",
        },
        {
            "pattern_type": "error_json",
            "indicators": ['"error":', '"status":"error"', '"success":false',
                          '"message":"not found"', '"code":401', '"code":403'],
            "is_false_positive": True,
            "confidence": 0.9,
            "description": "Server returns 200 OK but JSON body indicates error",
        },
        {
            "pattern_type": "own_data",
            "indicators": [],
            "is_false_positive": True,
            "confidence": 0.8,
            "description": "Server returns authenticated user's own data regardless of requested ID",
        },
        {
            "pattern_type": "public_data",
            "indicators": [],
            "is_false_positive": True,
            "confidence": 0.7,
            "description": "Response contains only public profile fields (username, bio) not private data",
        },
        {
            "pattern_type": "cross_user_data",
            "indicators": ['"email":', '"phone":', '"address":', '"ssn":',
                          '"credit_card":', '"password":', '"secret":'],
            "is_false_positive": False,
            "confidence": 0.9,
            "description": "Response contains another user's private data fields",
        },
        {
            "pattern_type": "admin_data_leak",
            "indicators": ['"role":"admin"', '"is_admin":true', '"users":[',
                          '"audit_log":', '"system_config":'],
            "is_false_positive": False,
            "confidence": 0.9,
            "description": "Response contains admin-level data accessible to non-admin user",
        },
        {
            "pattern_type": "state_change",
            "indicators": ['"updated":', '"deleted":', '"created":', '"modified":',
                          '"success":true'],
            "is_false_positive": False,
            "confidence": 0.85,
            "description": "Write operation succeeded on another user's resource",
        },
    ]

    # Known application patterns that cause false positives
    KNOWN_FP_PATTERNS: Dict[str, List[str]] = {
        "wso2": ["wso2", "carbon", "identity server", "api manager"],
        "keycloak": ["keycloak", "red hat sso"],
        "spring_security": ["spring security", "whitelabel error"],
        "oauth2_proxy": ["oauth2-proxy", "sign in with"],
        "cloudflare": ["cloudflare", "cf-ray", "attention required"],
        "aws_waf": ["aws-waf", "request blocked"],
    }

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or DATA_DIR
        self.learning_file = self.data_dir / "access_control_learning.json"
        self.records: List[TestRecord] = []
        self.custom_patterns: List[ResponsePattern] = []
        self._load()

    def _load(self):
        """Load learning data from disk."""
        try:
            if self.learning_file.exists():
                with open(self.learning_file, "r") as f:
                    data = json.load(f)
                    self.records = [
                        TestRecord(**r) for r in data.get("records", [])
                    ]
                    self.custom_patterns = [
                        ResponsePattern(**p) for p in data.get("patterns", [])
                    ]
                logger.debug(f"Loaded {len(self.records)} records, {len(self.custom_patterns)} patterns")
        except Exception as e:
            logger.debug(f"Failed to load learning data: {e}")

    def _save(self):
        """Save learning data to disk."""
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            data = {
                "records": [asdict(r) for r in self.records[-self.MAX_RECORDS:]],
                "patterns": [asdict(p) for p in self.custom_patterns[-self.MAX_PATTERNS:]],
                "metadata": {
                    "total_records": len(self.records),
                    "total_patterns": len(self.custom_patterns),
                    "last_updated": datetime.now().isoformat(),
                },
            }
            with open(self.learning_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to save learning data: {e}")

    def record_test(
        self,
        vuln_type: str,
        target_url: str,
        status_code: int,
        response_body: str,
        is_true_positive: bool,
        pattern_notes: str = "",
    ):
        """Record an access control test outcome for learning.

        Called after the validation judge makes a decision, with the
        verified outcome (true positive or false positive).
        """
        # Identify response pattern
        pattern_type = self._classify_response(response_body, status_code)
        key_indicators = self._extract_key_indicators(response_body)

        record = TestRecord(
            vuln_type=vuln_type,
            target_url=target_url,
            status_code=status_code,
            response_length=len(response_body),
            is_true_positive=is_true_positive,
            pattern_type=pattern_type,
            key_indicators=key_indicators[:10],
            notes=pattern_notes[:500],
            timestamp=datetime.now().isoformat(),
        )
        self.records.append(record)

        # Learn new pattern if we have enough data
        self._maybe_learn_pattern(record, response_body)

        # Auto-save periodically
        if len(self.records) % 10 == 0:
            self._save()

    def _classify_response(self, body: str, status: int) -> str:
        """Classify the response into a pattern type."""
        body_lower = body.lower().strip()

        if len(body_lower) < 10:
            return "empty_200"

        # Check for denial indicators
        denial = ["unauthorized", "forbidden", "access denied", "not authorized",
                  "permission denied", '"error":', '"success":false']
        if sum(1 for d in denial if d in body_lower) >= 2:
            return "denial_200"

        # Check for login page
        login = ["type=\"password\"", "sign in", "log in", "<form"]
        if sum(1 for l in login if l in body_lower) >= 2:
            return "login_redirect"

        # Check for data fields
        data = ['"email":', '"name":', '"phone":', '"address":',
                '"role":', '"password":', '"token":']
        if sum(1 for d in data if d in body_lower) >= 2:
            return "cross_user_data" if status == 200 else "blocked_data"

        return "unknown"

    def _extract_key_indicators(self, body: str) -> List[str]:
        """Extract key string indicators from the response."""
        indicators = []
        body_lower = body.lower()

        # Check for JSON keys
        json_keys = re.findall(r'"(\w+)":', body[:2000])
        indicators.extend(json_keys[:10])

        # Check for specific patterns
        patterns = {
            "has_email": '"email":' in body_lower,
            "has_name": '"name":' in body_lower,
            "has_error": '"error":' in body_lower,
            "has_success_false": '"success":false' in body_lower or '"success": false' in body_lower,
            "has_login_form": 'type="password"' in body_lower,
            "is_empty_array": body.strip() in ("[]", "{}"),
            "has_html_form": "<form" in body_lower,
        }
        for key, present in patterns.items():
            if present:
                indicators.append(key)

        return indicators

    def _maybe_learn_pattern(self, record: TestRecord, body: str):
        """Learn a new pattern from a test record if it provides new insight."""
        from urllib.parse import urlparse

        domain = urlparse(record.target_url).netloc
        body_excerpt = body[:500]

        # Check if we already know this pattern for this domain
        known = any(
            p.target_domain == domain
            and p.pattern_type == record.pattern_type
            and p.vuln_type == record.vuln_type
            for p in self.custom_patterns
        )
        if known:
            return

        # Learn new domain-specific pattern
        pattern = ResponsePattern(
            pattern_type=record.pattern_type,
            indicators=record.key_indicators,
            is_false_positive=not record.is_true_positive,
            confidence=0.7,  # Start with moderate confidence
            example_body=body_excerpt,
            vuln_type=record.vuln_type,
            target_domain=domain,
            timestamp=record.timestamp,
        )
        self.custom_patterns.append(pattern)

    def get_patterns_for_target(self, domain: str) -> List[ResponsePattern]:
        """Get learned patterns for a specific target domain."""
        return [
            p for p in self.custom_patterns
            if p.target_domain == domain
        ]

    def get_false_positive_rate(self, vuln_type: str) -> float:
        """Get the false positive rate for a specific vuln type from historical data."""
        type_records = [r for r in self.records if r.vuln_type == vuln_type]
        if not type_records:
            return 0.5  # No data → assume 50%
        fp_count = sum(1 for r in type_records if not r.is_true_positive)
        return fp_count / len(type_records)

    def get_learning_context(self, vuln_type: str, domain: str = "") -> str:
        """Generate learning context for AI prompts.

        Returns a formatted string with learned patterns and statistics
        that can be injected into LLM prompts to improve access control testing.
        """
        parts = []

        # Historical stats
        type_records = [r for r in self.records if r.vuln_type == vuln_type]
        if type_records:
            total = len(type_records)
            tp = sum(1 for r in type_records if r.is_true_positive)
            fp = total - tp
            parts.append(
                f"Historical {vuln_type} testing: {total} tests, "
                f"{tp} true positives ({100*tp/total:.0f}%), "
                f"{fp} false positives ({100*fp/total:.0f}%)"
            )

            # Most common FP patterns
            fp_patterns = [r.pattern_type for r in type_records if not r.is_true_positive]
            if fp_patterns:
                from collections import Counter
                common = Counter(fp_patterns).most_common(3)
                pattern_str = ", ".join(f"{p} ({c}x)" for p, c in common)
                parts.append(f"Common false positive patterns: {pattern_str}")

        # Domain-specific patterns
        if domain:
            domain_patterns = self.get_patterns_for_target(domain)
            if domain_patterns:
                for p in domain_patterns[:5]:
                    status = "FALSE POSITIVE" if p.is_false_positive else "TRUE POSITIVE"
                    parts.append(
                        f"Known pattern for {domain}: {p.pattern_type} = {status} "
                        f"(confidence: {p.confidence:.0%})"
                    )

        # Known application FP patterns
        if domain:
            for app_name, indicators in self.KNOWN_FP_PATTERNS.items():
                if any(i in domain.lower() for i in indicators):
                    parts.append(
                        f"WARNING: Target appears to use {app_name} — "
                        f"known for producing false positive access control findings"
                    )

        if not parts:
            return ""

        return "## Learned Access Control Patterns\n" + "\n".join(f"- {p}" for p in parts)

    def get_evaluation_hints(self, vuln_type: str, response_body: str, status: int) -> Dict:
        """Get evaluation hints for a specific response.

        Returns hints that can help the validation judge or AI make better decisions.
        """
        pattern_type = self._classify_response(response_body, status)
        indicators = self._extract_key_indicators(response_body)

        # Check against default patterns
        matching_default = [
            p for p in self.DEFAULT_PATTERNS
            if any(i.lower() in response_body.lower() for i in p["indicators"] if i)
        ]

        # Check against learned patterns
        matching_learned = [
            p for p in self.custom_patterns
            if p.vuln_type == vuln_type and p.pattern_type == pattern_type
        ]

        fp_signals = sum(
            1 for p in matching_default if p["is_false_positive"]
        ) + sum(
            1 for p in matching_learned if p.is_false_positive
        )

        tp_signals = sum(
            1 for p in matching_default if not p["is_false_positive"]
        ) + sum(
            1 for p in matching_learned if not p.is_false_positive
        )

        return {
            "pattern_type": pattern_type,
            "indicators": indicators,
            "fp_signals": fp_signals,
            "tp_signals": tp_signals,
            "likely_false_positive": fp_signals > tp_signals,
            "matching_patterns": len(matching_default) + len(matching_learned),
        }
