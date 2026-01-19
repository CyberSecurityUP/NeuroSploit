"""
NeuroSploit v3 - AI-Powered Prompt Processor

Uses Claude/OpenAI to intelligently analyze prompts and determine:
1. What vulnerabilities to test
2. Testing strategy and depth
3. Custom payloads based on context
4. Dynamic analysis based on recon results
"""
import os
import json
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class TestingPlan:
    """AI-generated testing plan"""
    vulnerability_types: List[str]
    testing_focus: List[str]
    custom_payloads: List[str]
    testing_depth: str
    specific_endpoints: List[str]
    bypass_techniques: List[str]
    priority_order: List[str]
    ai_reasoning: str


class AIPromptProcessor:
    """
    Uses LLM (Claude/OpenAI) to process prompts and generate intelligent testing plans.
    NOT limited to predefined vulnerability types - the AI decides what to test.
    """

    def __init__(self):
        self.anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self.openai_key = os.environ.get("OPENAI_API_KEY", "")

    async def process_prompt(
        self,
        prompt: str,
        recon_data: Optional[Dict] = None,
        target_info: Optional[Dict] = None
    ) -> TestingPlan:
        """
        Process a user prompt with AI to generate a testing plan.

        Args:
            prompt: User's testing prompt/instructions
            recon_data: Results from reconnaissance phase
            target_info: Information about the target

        Returns:
            TestingPlan with AI-determined testing strategy
        """
        # Build context for the AI
        context = self._build_context(prompt, recon_data, target_info)

        # Try Claude first, then OpenAI
        if self.anthropic_key:
            return await self._process_with_claude(context)
        elif self.openai_key:
            return await self._process_with_openai(context)
        else:
            # Fallback to intelligent defaults based on prompt analysis
            return await self._intelligent_fallback(prompt, recon_data)

    def _build_context(
        self,
        prompt: str,
        recon_data: Optional[Dict],
        target_info: Optional[Dict]
    ) -> str:
        """Build comprehensive context for the AI"""
        context_parts = [
            "You are an expert penetration tester analyzing a target.",
            f"\n## User's Testing Request:\n{prompt}",
        ]

        if target_info:
            context_parts.append(f"\n## Target Information:\n{json.dumps(target_info, indent=2)}")

        if recon_data:
            # Summarize recon data
            summary = {
                "subdomains_count": len(recon_data.get("subdomains", [])),
                "live_hosts": recon_data.get("live_hosts", [])[:10],
                "endpoints_count": len(recon_data.get("endpoints", [])),
                "sample_endpoints": [e.get("url", e) if isinstance(e, dict) else e for e in recon_data.get("endpoints", [])[:20]],
                "urls_with_params": [u for u in recon_data.get("urls", []) if "?" in str(u)][:10],
                "open_ports": recon_data.get("ports", [])[:20],
                "technologies": recon_data.get("technologies", []),
                "interesting_paths": recon_data.get("interesting_paths", []),
                "js_files": recon_data.get("js_files", [])[:10],
                "nuclei_findings": recon_data.get("vulnerabilities", [])
            }
            context_parts.append(f"\n## Reconnaissance Results:\n{json.dumps(summary, indent=2)}")

        context_parts.append("""
## Your Task:
Based on the user's request and the reconnaissance data, create a comprehensive testing plan.
You are NOT limited to specific vulnerability types - analyze the context and determine what to test.

Consider:
1. What the user specifically asked for
2. What the recon data reveals (technologies, endpoints, parameters)
3. Common vulnerabilities for the detected tech stack
4. Any interesting findings that warrant deeper testing
5. OWASP Top 10 and beyond based on context

Respond with a JSON object containing:
{
    "vulnerability_types": ["list of specific vulnerability types to test"],
    "testing_focus": ["specific areas to focus on based on findings"],
    "custom_payloads": ["any custom payloads based on detected technologies"],
    "testing_depth": "quick|medium|thorough",
    "specific_endpoints": ["high-priority endpoints to test first"],
    "bypass_techniques": ["WAF/filter bypass techniques if applicable"],
    "priority_order": ["ordered list of what to test first"],
    "ai_reasoning": "brief explanation of why you chose this testing strategy"
}
""")

        return "\n".join(context_parts)

    async def _process_with_claude(self, context: str) -> TestingPlan:
        """Process with Claude API"""
        try:
            import httpx

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.anthropic_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json"
                    },
                    json={
                        "model": "claude-sonnet-4-20250514",
                        "max_tokens": 4096,
                        "messages": [
                            {"role": "user", "content": context}
                        ]
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    content = data.get("content", [{}])[0].get("text", "{}")

                    # Extract JSON from response
                    return self._parse_ai_response(content)
                else:
                    print(f"Claude API error: {response.status_code}")
                    return await self._intelligent_fallback(context, None)

        except Exception as e:
            print(f"Claude processing error: {e}")
            return await self._intelligent_fallback(context, None)

    async def _process_with_openai(self, context: str) -> TestingPlan:
        """Process with OpenAI API"""
        try:
            import httpx

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.openai_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "gpt-4o",
                        "messages": [
                            {"role": "system", "content": "You are an expert penetration tester. Respond only with valid JSON."},
                            {"role": "user", "content": context}
                        ],
                        "max_tokens": 4096,
                        "temperature": 0.3
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    content = data.get("choices", [{}])[0].get("message", {}).get("content", "{}")
                    return self._parse_ai_response(content)
                else:
                    print(f"OpenAI API error: {response.status_code}")
                    return await self._intelligent_fallback(context, None)

        except Exception as e:
            print(f"OpenAI processing error: {e}")
            return await self._intelligent_fallback(context, None)

    def _parse_ai_response(self, content: str) -> TestingPlan:
        """Parse AI response into TestingPlan"""
        try:
            # Try to extract JSON from the response
            import re
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                data = json.loads(json_match.group())
                return TestingPlan(
                    vulnerability_types=data.get("vulnerability_types", []),
                    testing_focus=data.get("testing_focus", []),
                    custom_payloads=data.get("custom_payloads", []),
                    testing_depth=data.get("testing_depth", "medium"),
                    specific_endpoints=data.get("specific_endpoints", []),
                    bypass_techniques=data.get("bypass_techniques", []),
                    priority_order=data.get("priority_order", []),
                    ai_reasoning=data.get("ai_reasoning", "AI-generated testing plan")
                )
        except Exception as e:
            print(f"Failed to parse AI response: {e}")

        return self._default_plan()

    async def _intelligent_fallback(self, prompt: str, recon_data: Optional[Dict]) -> TestingPlan:
        """
        Intelligent fallback when no API key is available.
        Still provides smart testing plan based on prompt and recon analysis.
        """
        prompt_lower = prompt.lower()
        vuln_types = []
        focus = []
        priority = []

        # Analyze prompt for specific requests
        if any(word in prompt_lower for word in ["xss", "cross-site", "script"]):
            vuln_types.extend(["xss_reflected", "xss_stored", "xss_dom"])
            priority.append("XSS Testing")

        if any(word in prompt_lower for word in ["sql", "injection", "database", "sqli"]):
            vuln_types.extend(["sqli_error", "sqli_blind", "sqli_time", "sqli_union"])
            priority.append("SQL Injection")

        if any(word in prompt_lower for word in ["command", "rce", "exec", "shell"]):
            vuln_types.extend(["command_injection", "rce", "os_injection"])
            priority.append("Command Injection")

        if any(word in prompt_lower for word in ["file", "lfi", "rfi", "path", "traversal", "include"]):
            vuln_types.extend(["lfi", "rfi", "path_traversal"])
            priority.append("File Inclusion")

        if any(word in prompt_lower for word in ["ssrf", "request forgery", "server-side"]):
            vuln_types.extend(["ssrf", "ssrf_cloud"])
            priority.append("SSRF")

        if any(word in prompt_lower for word in ["auth", "login", "password", "session", "jwt", "token"]):
            vuln_types.extend(["auth_bypass", "session_fixation", "jwt_manipulation", "brute_force"])
            priority.append("Authentication Testing")

        if any(word in prompt_lower for word in ["idor", "authorization", "access control", "privilege"]):
            vuln_types.extend(["idor", "bola", "privilege_escalation"])
            priority.append("Authorization Testing")

        if any(word in prompt_lower for word in ["api", "rest", "graphql", "endpoint"]):
            vuln_types.extend(["api_abuse", "mass_assignment", "rate_limiting", "graphql_introspection"])
            priority.append("API Security")

        if any(word in prompt_lower for word in ["cors", "header", "security header"]):
            vuln_types.extend(["cors_misconfiguration", "missing_security_headers"])
            priority.append("Headers & CORS")

        if any(word in prompt_lower for word in ["upload", "file upload"]):
            vuln_types.extend(["file_upload", "unrestricted_upload"])
            priority.append("File Upload Testing")

        if any(word in prompt_lower for word in ["redirect", "open redirect"]):
            vuln_types.extend(["open_redirect"])
            priority.append("Open Redirect")

        if any(word in prompt_lower for word in ["ssti", "template"]):
            vuln_types.extend(["ssti"])
            priority.append("SSTI")

        if any(word in prompt_lower for word in ["xxe", "xml"]):
            vuln_types.extend(["xxe"])
            priority.append("XXE")

        if any(word in prompt_lower for word in ["deserialization", "serialize"]):
            vuln_types.extend(["insecure_deserialization"])
            priority.append("Deserialization")

        # If prompt mentions comprehensive/full/all/everything
        if any(word in prompt_lower for word in ["comprehensive", "full", "all", "everything", "complete", "pentest", "assessment"]):
            vuln_types = list(set(vuln_types + [
                "xss_reflected", "xss_stored", "sqli_error", "sqli_blind",
                "command_injection", "lfi", "path_traversal", "ssrf",
                "auth_bypass", "idor", "cors_misconfiguration", "open_redirect",
                "ssti", "file_upload", "xxe", "missing_security_headers"
            ]))
            focus.append("Comprehensive security assessment")

        # OWASP Top 10 focus
        if "owasp" in prompt_lower:
            vuln_types = list(set(vuln_types + [
                "sqli_error", "xss_reflected", "auth_bypass", "idor",
                "security_misconfiguration", "sensitive_data_exposure",
                "xxe", "insecure_deserialization", "missing_security_headers",
                "ssrf"
            ]))
            focus.append("OWASP Top 10 Coverage")

        # Bug bounty focus
        if any(word in prompt_lower for word in ["bounty", "bug bounty", "high impact"]):
            vuln_types = list(set(vuln_types + [
                "sqli_error", "xss_stored", "rce", "ssrf", "idor",
                "auth_bypass", "privilege_escalation"
            ]))
            focus.append("High-impact vulnerabilities for bug bounty")

        # Analyze recon data if available
        if recon_data:
            endpoints = recon_data.get("endpoints", [])
            urls = recon_data.get("urls", [])
            techs = recon_data.get("technologies", [])

            # Check for parameters (injection points)
            param_urls = [u for u in urls if "?" in str(u)]
            if param_urls:
                focus.append(f"Found {len(param_urls)} URLs with parameters - test for injection")
                if "sqli_error" not in vuln_types:
                    vuln_types.append("sqli_error")
                if "xss_reflected" not in vuln_types:
                    vuln_types.append("xss_reflected")

            # Check for interesting paths
            interesting = recon_data.get("interesting_paths", [])
            if interesting:
                focus.append(f"Found {len(interesting)} interesting paths to investigate")

            # Check for JS files (DOM XSS potential)
            js_files = recon_data.get("js_files", [])
            if js_files:
                focus.append(f"Found {len(js_files)} JS files - check for DOM XSS and secrets")
                if "xss_dom" not in vuln_types:
                    vuln_types.append("xss_dom")

            # Technology-specific testing
            tech_str = str(techs).lower()
            if "php" in tech_str:
                vuln_types = list(set(vuln_types + ["lfi", "rfi", "file_upload"]))
            if "wordpress" in tech_str:
                focus.append("WordPress detected - test for WP-specific vulns")
            if "java" in tech_str or "spring" in tech_str:
                vuln_types = list(set(vuln_types + ["ssti", "insecure_deserialization"]))
            if "node" in tech_str or "express" in tech_str:
                vuln_types = list(set(vuln_types + ["prototype_pollution", "ssti"]))
            if "api" in tech_str or "json" in tech_str:
                vuln_types = list(set(vuln_types + ["api_abuse", "mass_assignment"]))

        # Default if nothing specific found
        if not vuln_types:
            vuln_types = [
                "xss_reflected", "sqli_error", "lfi", "open_redirect",
                "cors_misconfiguration", "missing_security_headers"
            ]
            focus.append("General security assessment")

        return TestingPlan(
            vulnerability_types=vuln_types,
            testing_focus=focus if focus else ["General vulnerability testing"],
            custom_payloads=[],
            testing_depth="medium",
            specific_endpoints=[],
            bypass_techniques=[],
            priority_order=priority if priority else vuln_types[:5],
            ai_reasoning="Intelligent fallback analysis based on prompt keywords and recon data"
        )

    def _default_plan(self) -> TestingPlan:
        """Default testing plan"""
        return TestingPlan(
            vulnerability_types=[
                "xss_reflected", "sqli_error", "sqli_blind", "command_injection",
                "lfi", "path_traversal", "ssrf", "auth_bypass", "idor",
                "cors_misconfiguration", "open_redirect", "missing_security_headers"
            ],
            testing_focus=["Comprehensive vulnerability assessment"],
            custom_payloads=[],
            testing_depth="medium",
            specific_endpoints=[],
            bypass_techniques=[],
            priority_order=["SQL Injection", "XSS", "Command Injection", "Authentication"],
            ai_reasoning="Default comprehensive testing plan"
        )


class AIVulnerabilityAnalyzer:
    """
    Uses AI to analyze potential vulnerabilities found during testing.
    Provides intelligent confirmation and exploitation guidance.
    """

    def __init__(self):
        self.anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self.openai_key = os.environ.get("OPENAI_API_KEY", "")

    async def analyze_finding(
        self,
        vuln_type: str,
        request: Dict,
        response: Dict,
        payload: str,
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Use AI to analyze a potential vulnerability finding.

        Returns confidence level, exploitation advice, and remediation.
        """
        if not self.anthropic_key and not self.openai_key:
            return self._basic_analysis(vuln_type, request, response, payload)

        prompt = f"""
Analyze this potential security vulnerability:

**Vulnerability Type**: {vuln_type}
**Payload Used**: {payload}
**Request**: {json.dumps(request, indent=2)[:1000]}
**Response Status**: {response.get('status')}
**Response Body Preview**: {response.get('body_preview', '')[:500]}

Analyze and respond with JSON:
{{
    "is_vulnerable": true/false,
    "confidence": 0.0-1.0,
    "evidence": "specific evidence from response",
    "severity": "critical/high/medium/low/info",
    "exploitation_path": "how to exploit if vulnerable",
    "remediation": "how to fix",
    "false_positive_indicators": ["reasons this might be false positive"]
}}
"""

        try:
            if self.anthropic_key:
                return await self._analyze_with_claude(prompt)
            elif self.openai_key:
                return await self._analyze_with_openai(prompt)
        except Exception as e:
            print(f"AI analysis error: {e}")

        return self._basic_analysis(vuln_type, request, response, payload)

    async def _analyze_with_claude(self, prompt: str) -> Dict:
        """Analyze with Claude"""
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": prompt}]
                }
            )

            if response.status_code == 200:
                data = response.json()
                content = data.get("content", [{}])[0].get("text", "{}")
                import re
                json_match = re.search(r'\{[\s\S]*\}', content)
                if json_match:
                    return json.loads(json_match.group())

        return {}

    async def _analyze_with_openai(self, prompt: str) -> Dict:
        """Analyze with OpenAI"""
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.openai_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-4o",
                    "messages": [
                        {"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 1024
                }
            )

            if response.status_code == 200:
                data = response.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "{}")
                import re
                json_match = re.search(r'\{[\s\S]*\}', content)
                if json_match:
                    return json.loads(json_match.group())

        return {}

    def _basic_analysis(self, vuln_type: str, request: Dict, response: Dict, payload: str) -> Dict:
        """Basic analysis without AI"""
        body = response.get("body_preview", "").lower()
        status = response.get("status", 0)

        is_vulnerable = False
        confidence = 0.0
        evidence = ""

        # Basic detection patterns
        if vuln_type in ["xss_reflected", "xss_stored"]:
            if payload.lower() in body:
                is_vulnerable = True
                confidence = 0.7
                evidence = f"Payload reflected in response"

        elif vuln_type in ["sqli_error", "sqli_blind"]:
            error_patterns = ["sql", "mysql", "syntax", "query", "oracle", "postgresql", "sqlite"]
            if any(p in body for p in error_patterns):
                is_vulnerable = True
                confidence = 0.8
                evidence = "SQL error message detected"

        elif vuln_type == "lfi":
            if "root:" in body or "[extensions]" in body:
                is_vulnerable = True
                confidence = 0.9
                evidence = "File content detected in response"

        elif vuln_type == "open_redirect":
            if status in [301, 302, 303, 307, 308]:
                is_vulnerable = True
                confidence = 0.6
                evidence = "Redirect detected"

        return {
            "is_vulnerable": is_vulnerable,
            "confidence": confidence,
            "evidence": evidence,
            "severity": "medium",
            "exploitation_path": "",
            "remediation": "",
            "false_positive_indicators": []
        }
