"""
NeuroSploit v3 - Prompt Parser

Parses user prompts to extract:
1. Vulnerability types to test
2. Testing scope and depth
3. Special instructions
4. Output format preferences

This enables dynamic, prompt-driven testing instead of hardcoded vulnerability types.
"""
import re
from typing import List, Dict, Optional, Tuple
from backend.schemas.prompt import (
    PromptParseResult,
    VulnerabilityTypeExtracted,
    TestingScope
)


class PromptParser:
    """
    Parses penetration testing prompts to extract structured testing instructions.

    Instead of requiring specific LLM calls for every parse, this uses pattern matching
    and keyword analysis for fast, deterministic extraction.
    """

    # Vulnerability keyword mappings
    VULNERABILITY_KEYWORDS = {
        # XSS variants
        "xss_reflected": [
            "xss", "cross-site scripting", "reflected xss", "reflected cross-site",
            "script injection", "html injection"
        ],
        "xss_stored": [
            "stored xss", "persistent xss", "stored cross-site", "persistent cross-site"
        ],
        "xss_dom": [
            "dom xss", "dom-based xss", "dom based", "client-side xss"
        ],

        # SQL Injection variants
        "sqli_error": [
            "sql injection", "sqli", "sql error", "error-based sql"
        ],
        "sqli_union": [
            "union sql", "union injection", "union-based", "union based"
        ],
        "sqli_blind": [
            "blind sql", "blind injection", "boolean sql", "boolean-based"
        ],
        "sqli_time": [
            "time-based sql", "time based sql", "time-based injection"
        ],

        # Other injections
        "nosql_injection": [
            "nosql", "mongodb injection", "nosql injection"
        ],
        "command_injection": [
            "command injection", "os command", "shell injection", "rce",
            "remote code execution", "code execution"
        ],
        "ssti": [
            "ssti", "template injection", "server-side template", "jinja injection",
            "twig injection"
        ],
        "ldap_injection": [
            "ldap injection", "ldap"
        ],
        "xpath_injection": [
            "xpath injection", "xpath"
        ],
        "header_injection": [
            "header injection", "http header"
        ],
        "crlf_injection": [
            "crlf", "carriage return", "header splitting"
        ],

        # File access
        "lfi": [
            "lfi", "local file inclusion", "file inclusion", "path traversal",
            "directory traversal", "../"
        ],
        "rfi": [
            "rfi", "remote file inclusion"
        ],
        "path_traversal": [
            "path traversal", "directory traversal", "dot dot slash"
        ],
        "file_upload": [
            "file upload", "upload vulnerability", "unrestricted upload",
            "malicious upload"
        ],
        "xxe": [
            "xxe", "xml external entity", "xml injection"
        ],

        # Request forgery
        "ssrf": [
            "ssrf", "server-side request forgery", "server side request",
            "internal request"
        ],
        "ssrf_cloud": [
            "cloud metadata", "169.254.169.254", "metadata service", "aws metadata",
            "gcp metadata"
        ],
        "csrf": [
            "csrf", "cross-site request forgery", "xsrf"
        ],

        # Authentication
        "auth_bypass": [
            "authentication bypass", "auth bypass", "login bypass", "broken auth"
        ],
        "session_fixation": [
            "session fixation", "session hijacking"
        ],
        "jwt_manipulation": [
            "jwt", "json web token", "token manipulation", "jwt bypass"
        ],
        "weak_password": [
            "weak password", "password policy", "credential"
        ],
        "brute_force": [
            "brute force", "credential stuffing", "password spray"
        ],

        # Authorization
        "idor": [
            "idor", "insecure direct object", "direct object reference"
        ],
        "bola": [
            "bola", "broken object level", "api authorization"
        ],
        "privilege_escalation": [
            "privilege escalation", "privesc", "priv esc", "elevation"
        ],

        # API Security
        "rate_limiting": [
            "rate limit", "rate limiting", "throttling"
        ],
        "mass_assignment": [
            "mass assignment", "parameter pollution"
        ],
        "excessive_data": [
            "excessive data", "data exposure", "over-fetching"
        ],
        "graphql_introspection": [
            "graphql introspection", "graphql schema"
        ],
        "graphql_injection": [
            "graphql injection", "graphql attack"
        ],

        # Client-side
        "cors_misconfig": [
            "cors", "cross-origin", "cors misconfiguration"
        ],
        "clickjacking": [
            "clickjacking", "click jacking", "ui redressing", "x-frame-options"
        ],
        "open_redirect": [
            "open redirect", "url redirect", "redirect vulnerability"
        ],

        # Information disclosure
        "error_disclosure": [
            "error message", "stack trace", "debug information"
        ],
        "sensitive_data": [
            "sensitive data", "pii exposure", "data leak"
        ],
        "debug_endpoints": [
            "debug endpoint", "admin panel", "hidden endpoint"
        ],

        # Infrastructure
        "security_headers": [
            "security headers", "http headers", "csp", "content-security-policy",
            "hsts", "x-content-type"
        ],
        "ssl_issues": [
            "ssl", "tls", "certificate", "https"
        ],
        "http_methods": [
            "http methods", "options method", "trace method", "put method"
        ],

        # Logic flaws
        "race_condition": [
            "race condition", "toctou", "time of check"
        ],
        "business_logic": [
            "business logic", "logic flaw", "workflow"
        ]
    }

    # Category mappings
    VULNERABILITY_CATEGORIES = {
        "injection": [
            "xss_reflected", "xss_stored", "xss_dom", "sqli_error", "sqli_union",
            "sqli_blind", "sqli_time", "nosql_injection", "command_injection",
            "ssti", "ldap_injection", "xpath_injection", "header_injection", "crlf_injection"
        ],
        "file_access": ["lfi", "rfi", "path_traversal", "file_upload", "xxe"],
        "request_forgery": ["ssrf", "ssrf_cloud", "csrf"],
        "authentication": [
            "auth_bypass", "session_fixation", "jwt_manipulation",
            "weak_password", "brute_force"
        ],
        "authorization": ["idor", "bola", "privilege_escalation"],
        "api_security": [
            "rate_limiting", "mass_assignment", "excessive_data",
            "graphql_introspection", "graphql_injection"
        ],
        "client_side": ["cors_misconfig", "clickjacking", "open_redirect"],
        "information_disclosure": ["error_disclosure", "sensitive_data", "debug_endpoints"],
        "infrastructure": ["security_headers", "ssl_issues", "http_methods"],
        "logic_flaws": ["race_condition", "business_logic"]
    }

    # Depth keywords
    DEPTH_KEYWORDS = {
        "quick": ["quick", "fast", "basic", "simple", "light"],
        "standard": ["standard", "normal", "default"],
        "thorough": ["thorough", "comprehensive", "complete", "full", "deep"],
        "exhaustive": ["exhaustive", "extensive", "all", "everything", "maximum"]
    }

    def __init__(self):
        # Compile regex patterns for efficiency
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for keyword matching"""
        self.vuln_patterns = {}
        for vuln_type, keywords in self.VULNERABILITY_KEYWORDS.items():
            pattern = r'\b(' + '|'.join(re.escape(kw) for kw in keywords) + r')\b'
            self.vuln_patterns[vuln_type] = re.compile(pattern, re.IGNORECASE)

    async def parse(self, prompt: str) -> PromptParseResult:
        """
        Parse a prompt to extract testing instructions.

        Args:
            prompt: User's penetration testing prompt

        Returns:
            PromptParseResult with extracted vulnerabilities and scope
        """
        prompt_lower = prompt.lower()

        # Extract vulnerability types
        vulnerabilities = self._extract_vulnerabilities(prompt, prompt_lower)

        # If no specific vulnerabilities mentioned but comprehensive keywords found,
        # add all vulnerabilities
        if not vulnerabilities:
            if any(kw in prompt_lower for kw in ["all vulnerabilities", "comprehensive", "full pentest", "everything"]):
                vulnerabilities = self._get_all_vulnerabilities(prompt)

        # Extract testing scope
        scope = self._extract_scope(prompt_lower)

        # Extract special instructions
        special_instructions = self._extract_special_instructions(prompt)

        # Extract target filters
        target_filters = self._extract_target_filters(prompt)

        # Extract output preferences
        output_preferences = self._extract_output_preferences(prompt_lower)

        return PromptParseResult(
            vulnerabilities_to_test=vulnerabilities,
            testing_scope=scope,
            special_instructions=special_instructions,
            target_filters=target_filters,
            output_preferences=output_preferences
        )

    def _extract_vulnerabilities(self, prompt: str, prompt_lower: str) -> List[VulnerabilityTypeExtracted]:
        """Extract vulnerability types from prompt"""
        vulnerabilities = []
        found_types = set()

        for vuln_type, pattern in self.vuln_patterns.items():
            matches = pattern.findall(prompt_lower)
            if matches:
                # Calculate confidence based on number of matches and context
                confidence = min(0.9, 0.5 + len(matches) * 0.1)

                # Get category
                category = self._get_category(vuln_type)

                # Extract context (surrounding text)
                context = self._extract_context(prompt, matches[0])

                if vuln_type not in found_types:
                    found_types.add(vuln_type)
                    vulnerabilities.append(VulnerabilityTypeExtracted(
                        type=vuln_type,
                        category=category,
                        confidence=confidence,
                        context=context
                    ))

        return vulnerabilities

    def _get_all_vulnerabilities(self, prompt: str) -> List[VulnerabilityTypeExtracted]:
        """Get all vulnerability types for comprehensive testing"""
        vulnerabilities = []
        for vuln_type in self.VULNERABILITY_KEYWORDS.keys():
            category = self._get_category(vuln_type)
            vulnerabilities.append(VulnerabilityTypeExtracted(
                type=vuln_type,
                category=category,
                confidence=0.7,
                context="Comprehensive testing requested"
            ))
        return vulnerabilities

    def _get_category(self, vuln_type: str) -> str:
        """Get category for a vulnerability type"""
        for category, types in self.VULNERABILITY_CATEGORIES.items():
            if vuln_type in types:
                return category
        return "other"

    def _extract_context(self, prompt: str, keyword: str, window: int = 50) -> str:
        """Extract context around a keyword"""
        idx = prompt.lower().find(keyword.lower())
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end = min(len(prompt), idx + len(keyword) + window)
        return prompt[start:end].strip()

    def _extract_scope(self, prompt_lower: str) -> TestingScope:
        """Extract testing scope from prompt"""
        # Determine depth
        depth = "standard"
        for level, keywords in self.DEPTH_KEYWORDS.items():
            if any(kw in prompt_lower for kw in keywords):
                depth = level
                break

        # Check for recon
        include_recon = not any(
            kw in prompt_lower for kw in ["no recon", "skip recon", "without recon"]
        )

        # Extract time limits
        time_limit = None
        time_match = re.search(r'(\d+)\s*(minute|min|hour|hr)', prompt_lower)
        if time_match:
            value = int(time_match.group(1))
            unit = time_match.group(2)
            if 'hour' in unit or 'hr' in unit:
                time_limit = value * 60
            else:
                time_limit = value

        # Extract request limits
        max_requests = None
        req_match = re.search(r'(\d+)\s*(request|req)', prompt_lower)
        if req_match:
            max_requests = int(req_match.group(1))

        return TestingScope(
            include_recon=include_recon,
            depth=depth,
            max_requests_per_endpoint=max_requests,
            time_limit_minutes=time_limit
        )

    def _extract_special_instructions(self, prompt: str) -> List[str]:
        """Extract special instructions from prompt"""
        instructions = []

        # Look for explicit instructions
        instruction_patterns = [
            r'focus on[:\s]+([^.]+)',
            r'prioritize[:\s]+([^.]+)',
            r'especially[:\s]+([^.]+)',
            r'important[:\s]+([^.]+)',
            r'make sure to[:\s]+([^.]+)',
            r'don\'t forget to[:\s]+([^.]+)'
        ]

        for pattern in instruction_patterns:
            matches = re.findall(pattern, prompt, re.IGNORECASE)
            instructions.extend(matches)

        return instructions

    def _extract_target_filters(self, prompt: str) -> Dict:
        """Extract target filtering preferences"""
        filters = {
            "include_patterns": [],
            "exclude_patterns": [],
            "focus_on_parameters": []
        }

        # Look for include patterns
        include_match = re.findall(r'only\s+test\s+([^.]+)', prompt, re.IGNORECASE)
        if include_match:
            filters["include_patterns"].extend(include_match)

        # Look for exclude patterns
        exclude_match = re.findall(r'(?:skip|exclude|ignore)\s+([^.]+)', prompt, re.IGNORECASE)
        if exclude_match:
            filters["exclude_patterns"].extend(exclude_match)

        # Look for parameter focus
        param_match = re.findall(r'parameter[s]?\s+(?:like|named|called)\s+(\w+)', prompt, re.IGNORECASE)
        if param_match:
            filters["focus_on_parameters"].extend(param_match)

        return filters

    def _extract_output_preferences(self, prompt_lower: str) -> Dict:
        """Extract output and reporting preferences"""
        preferences = {
            "severity_threshold": "all",
            "include_poc": True,
            "include_remediation": True
        }

        # Severity threshold
        if "critical only" in prompt_lower or "only critical" in prompt_lower:
            preferences["severity_threshold"] = "critical"
        elif "high and above" in prompt_lower or "high severity" in prompt_lower:
            preferences["severity_threshold"] = "high"
        elif "medium and above" in prompt_lower:
            preferences["severity_threshold"] = "medium"

        # PoC preference
        if "no poc" in prompt_lower or "without poc" in prompt_lower:
            preferences["include_poc"] = False

        # Remediation preference
        if "no remediation" in prompt_lower or "without remediation" in prompt_lower:
            preferences["include_remediation"] = False

        return preferences
