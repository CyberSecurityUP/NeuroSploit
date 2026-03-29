"""
NeuroSploit v3 - Markdown-Based Agent System (Real Execution)

Each .md file in prompts/agents/ acts as a self-contained agent definition.
Agents EXECUTE REAL HTTP TESTS against the target — not theoretical analysis.

Cycle per agent:
  1. PLAN  — LLM reads methodology + recon context → generates test plan (HTTP requests)
  2. EXECUTE — sends actual HTTP requests against the target
  3. ANALYZE — LLM reviews real responses → confirms/rejects with evidence

Components:
  - MdAgentDefinition: parsed .md agent metadata
  - MdAgent(SpecialistAgent): plans, executes, and analyzes real tests
  - MdAgentLibrary: loads & indexes all .md agent definitions
  - MdAgentOrchestrator: runs agents in phases (recon → offensive → generalist)
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    from backend.core.agent_base import SpecialistAgent, AgentResult
except ImportError:
    from core.agent_base import SpecialistAgent, AgentResult

logger = logging.getLogger(__name__)

# ─── Agent categories ───────────────────────────────────────────────
AGENT_CATEGORIES: Dict[str, str] = {
    "pentest_generalist": "generalist",
    "red_team_agent": "generalist",
    "bug_bounty_hunter": "generalist",
    "owasp_expert": "generalist",
    "exploit_expert": "generalist",
    "cwe_expert": "generalist",
    "replay_attack_specialist": "generalist",
    "recon_deep": "recon",
    "Pentestfull": "methodology",
}

SKIP_AGENTS = {"Pentestfull"}
RUN_ALL_BY_DEFAULT = True

# Max tests per agent to execute
MAX_TESTS_PER_AGENT = 5
# Max iterations of the plan→execute→analyze loop
MAX_ITERATIONS = 2
# HTTP request timeout per test
REQUEST_TIMEOUT = 10


# ─── Data classes ────────────────────────────────────────────────────

@dataclass
class MdAgentDefinition:
    """Parsed .md agent definition."""
    name: str
    display_name: str
    category: str  # offensive / generalist / recon / methodology
    user_prompt_template: str
    system_prompt: str
    file_path: str
    placeholders: List[str] = field(default_factory=list)


# ─── MdAgent: plans, executes, and analyzes real tests ───────────────

class MdAgent(SpecialistAgent):
    """Executes a single .md-based agent with REAL HTTP testing.

    Cycle:
      1. PLAN  — sends methodology + recon to LLM → gets structured test plan
      2. EXECUTE — runs actual HTTP requests against the target
      3. ANALYZE — LLM reviews real responses, confirms findings with evidence
    """

    def __init__(
        self,
        definition: MdAgentDefinition,
        llm=None,
        memory=None,
        budget_allocation: float = 0.0,
        budget=None,
        validation_judge=None,
        http_session=None,
        auth_headers: Optional[Dict] = None,
        cancel_fn: Optional[Callable] = None,
    ):
        super().__init__(
            name=f"md_{definition.name}",
            llm=llm,
            memory=memory,
            budget_allocation=budget_allocation,
            budget=budget,
        )
        self.definition = definition
        self.validation_judge = validation_judge
        self.http_session = http_session
        self.auth_headers = auth_headers or {}
        self.cancel_fn = cancel_fn or (lambda: False)

    async def run(self, context: Dict) -> AgentResult:
        """Execute the full PLAN → EXECUTE → ANALYZE cycle."""
        result = AgentResult(agent_name=self.name)
        target = context.get("target", "")

        if not target:
            result.error = "No target provided"
            return result

        # Check LLM availability upfront
        if not self.llm:
            result.error = "No LLM provided"
            logger.warning(f"[{self.definition.name}] No LLM available — skipping")
            return result

        if not hasattr(self.llm, 'generate'):
            result.error = f"LLM has no generate method (type: {type(self.llm).__name__})"
            logger.warning(f"[{self.definition.name}] {result.error}")
            return result

        all_findings = []

        for iteration in range(1, MAX_ITERATIONS + 1):
            if self.cancel_fn():
                break

            # ── PHASE 1: PLAN ──
            plan_prompt = self._build_plan_prompt(context, iteration, all_findings)
            plan_response = await self._llm_with_retry(plan_prompt)

            if not plan_response:
                result.error = "LLM plan call failed after retries"
                break

            tests = self._parse_test_plan(plan_response, target)
            if not tests:
                # No actionable tests — fall back to theoretical analysis
                theoretical = self._parse_findings(plan_response, target)
                all_findings.extend(theoretical)
                break

            # ── PHASE 2: EXECUTE ──
            test_results = await self._execute_tests(tests, target)
            if not test_results:
                break

            # ── PHASE 3: ANALYZE ──
            analysis_prompt = self._build_analysis_prompt(
                context, test_results, target
            )
            analysis_response = await self._llm_with_retry(analysis_prompt)
            if not analysis_response:
                break

            if analysis_response:
                confirmed = self._parse_analysis_findings(
                    analysis_response, test_results, target
                )
                all_findings.extend(confirmed)

                # If we found confirmed vulns, no need for another iteration
                if confirmed:
                    break

        result.findings = all_findings
        result.data = {
            "agent_name": self.definition.display_name,
            "agent_category": self.definition.category,
            "findings_count": len(all_findings),
            "execution_mode": "real_http",
        }
        self.tasks_completed += 1
        return result

    # ── LLM call with retry ─────────────────────────────────────────

    async def _llm_with_retry(self, prompt: str, max_retries: int = 3) -> Optional[str]:
        """Call LLM with exponential backoff retry."""
        last_error = ""
        for attempt in range(max_retries):
            try:
                result = await self.llm.generate(prompt)
                if result and len(result.strip()) > 10:
                    return result
                last_error = f"Empty/short response (len={len(result) if result else 0})"
                logger.debug(f"[{self.definition.name}] {last_error}, attempt {attempt + 1}")
            except Exception as e:
                last_error = str(e)[:200]
                logger.warning(f"[{self.definition.name}] LLM error (attempt {attempt + 1}/{max_retries}): {last_error}")

            if attempt < max_retries - 1:
                delay = 5 * (attempt + 1)  # 5s, 10s
                await asyncio.sleep(delay)

        logger.warning(f"[{self.definition.name}] All {max_retries} attempts failed: {last_error}")
        return None

    # ── PLAN prompt ──────────────────────────────────────────────────

    def _build_plan_prompt(
        self, context: Dict, iteration: int, previous_findings: List[Dict]
    ) -> str:
        """Build the planning prompt: methodology + recon → structured test plan."""
        target = context.get("target", "")
        endpoints = context.get("endpoints", [])
        technologies = context.get("technologies", [])
        parameters = context.get("parameters", {})
        waf_info = context.get("waf_info", "")
        forms = context.get("forms", [])

        # Fill the .md template with recon context for methodology
        methodology = self._fill_template(context)

        # Recon summary for the LLM
        endpoint_list = []
        for ep in endpoints[:12]:
            if isinstance(ep, dict):
                url = ep.get("url", "")
                method = ep.get("method", "GET")
                params = ep.get("params", [])
                endpoint_list.append(f"  {method} {url} params={params}")
            else:
                endpoint_list.append(f"  GET {ep}")

        # JS sinks for DOM-related agents
        js_sinks = context.get("js_sinks", [])
        js_sinks_str = ""
        if js_sinks:
            sink_list = []
            for s in js_sinks[:5]:
                if hasattr(s, 'sink_type'):
                    sink_list.append(f"  {s.sink_type}: {getattr(s, 'code_snippet', '')[:60]}")
                elif isinstance(s, dict):
                    sink_list.append(f"  {s.get('sink_type','?')}: {s.get('code_snippet','')[:60]}")
            if sink_list:
                js_sinks_str = f"\nJS Sinks (DOM XSS vectors):\n" + chr(10).join(sink_list)

        # API endpoints
        api_eps = context.get("api_endpoints", [])
        api_str = ""
        if api_eps:
            api_str = f"\nAPI endpoints: {', '.join(str(a) for a in api_eps[:5])}"

        # Forms
        forms_str = ""
        if forms:
            form_list = []
            for f in (forms if isinstance(forms, list) else [])[:3]:
                if isinstance(f, dict):
                    form_list.append(f"  {f.get('method','POST')} {f.get('action','?')} inputs={f.get('inputs',[])}")
            if form_list:
                forms_str = f"\nForms:\n" + chr(10).join(form_list)

        recon_summary = f"""Target: {target}
Tech: {', '.join(technologies[:5]) or 'Unknown'} | WAF: {waf_info or 'None'}
Endpoints ({len(endpoints)} total, showing {len(endpoint_list)}):
{chr(10).join(endpoint_list)}
Params: {json.dumps(dict(list(parameters.items())[:8]) if isinstance(parameters, dict) else {}, default=str)}{forms_str}{js_sinks_str}{api_str}"""

        previous_str = ""
        if previous_findings:
            previous_str = f"\n\nPrevious iteration found {len(previous_findings)} potential issues. Adapt your tests to probe deeper or try different vectors."

        system = self.definition.system_prompt or (
            f"You are a {self.definition.display_name} security testing agent. "
            f"You perform REAL penetration tests by generating HTTP requests that will be executed against the target."
        )

        prompt = f"""{system}

## Your Methodology
{methodology}

## Reconnaissance Data
{recon_summary}
{previous_str}

## Your Task (Iteration {iteration}/{MAX_ITERATIONS})

Based on your methodology and the recon data above, generate a CONCRETE test plan.
Each test must be an HTTP request that will be ACTUALLY EXECUTED against the target.

You MUST output a JSON block with this exact structure:

```json
{{
  "reasoning": "Brief explanation of your attack strategy",
  "tests": [
    {{
      "name": "Test name describing what you're checking",
      "url": "Full URL to test (use target endpoints from recon)",
      "method": "GET or POST",
      "params": {{"param_name": "payload_value"}},
      "headers": {{"Header-Name": "value"}},
      "body": "POST body if needed (empty string for GET)",
      "injection_point": "parameter|header|body",
      "expected_if_vulnerable": "What to look for in the response if vulnerable"
    }}
  ]
}}
```

Rules:
- Generate {MAX_TESTS_PER_AGENT} specific tests maximum
- Use REAL endpoints from the recon data
- Use REAL parameters discovered
- Payloads must be safe for testing (no destructive operations)
- Each test targets a specific vulnerability pattern from your methodology
- Include the expected_if_vulnerable field so we can verify results
"""
        return prompt

    # ── EXECUTE tests ────────────────────────────────────────────────

    async def _execute_tests(
        self, tests: List[Dict], default_target: str
    ) -> List[Dict]:
        """Execute HTTP requests from the test plan. Returns results with real responses."""
        results = []

        # Create session if needed
        own_session = False
        session = self.http_session
        if not session and HAS_AIOHTTP:
            connector = aiohttp.TCPConnector(ssl=False)
            session = aiohttp.ClientSession(connector=connector)
            own_session = True
        elif not session:
            logger.warning(f"[{self.definition.name}] No HTTP session and aiohttp not available")
            return []

        try:
            for test in tests[:MAX_TESTS_PER_AGENT]:
                if self.cancel_fn():
                    break

                test_url = test.get("url", default_target)
                method = test.get("method", "GET").upper()
                params = test.get("params", {})
                test_headers = test.get("headers", {})
                body = test.get("body", "")
                test_name = test.get("name", "unnamed")
                expected = test.get("expected_if_vulnerable", "")

                # Merge auth headers
                req_headers = {**self.auth_headers, **test_headers}

                start = time.time()
                try:
                    kwargs: Dict[str, Any] = {
                        "timeout": aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                        "headers": req_headers,
                        "allow_redirects": False,
                        "ssl": False,
                    }

                    if method == "GET":
                        kwargs["params"] = params
                    elif method == "POST":
                        if body:
                            kwargs["data"] = body
                        elif params:
                            kwargs["data"] = params

                    async with session.request(method, test_url, **kwargs) as resp:
                        status = resp.status
                        resp_headers = dict(resp.headers)
                        resp_body = await resp.text(errors="replace")
                        elapsed = time.time() - start

                    results.append({
                        "test_name": test_name,
                        "url": test_url,
                        "method": method,
                        "params": params,
                        "payload": json.dumps(params) if params else body,
                        "status": status,
                        "response_headers": {k: v for k, v in list(resp_headers.items())[:15]},
                        "body_preview": resp_body[:2000],
                        "body_length": len(resp_body),
                        "response_time": round(elapsed, 3),
                        "expected_if_vulnerable": expected,
                    })

                except asyncio.TimeoutError:
                    results.append({
                        "test_name": test_name,
                        "url": test_url,
                        "method": method,
                        "status": 0,
                        "body_preview": "TIMEOUT",
                        "body_length": 0,
                        "response_time": REQUEST_TIMEOUT,
                        "expected_if_vulnerable": expected,
                    })
                except Exception as e:
                    results.append({
                        "test_name": test_name,
                        "url": test_url,
                        "method": method,
                        "status": 0,
                        "body_preview": f"ERROR: {str(e)[:200]}",
                        "body_length": 0,
                        "response_time": 0,
                        "expected_if_vulnerable": expected,
                    })

                # Small delay between requests to avoid hammering
                await asyncio.sleep(0.15)

        finally:
            if own_session:
                await session.close()

        return results

    # ── ANALYZE prompt ───────────────────────────────────────────────

    def _build_analysis_prompt(
        self, context: Dict, test_results: List[Dict], target: str
    ) -> str:
        """Build the analysis prompt: real HTTP responses → confirmed findings."""
        vuln_type = self.definition.name

        results_summary = []
        for tr in test_results[:MAX_TESTS_PER_AGENT]:
            results_summary.append({
                "test_name": tr["test_name"],
                "url": tr.get("url", ""),
                "method": tr.get("method", ""),
                "status": tr.get("status", 0),
                "response_time": tr.get("response_time", 0),
                "body_preview": tr.get("body_preview", "")[:1200],
                "body_length": tr.get("body_length", 0),
                "response_headers": tr.get("response_headers", {}),
                "expected_if_vulnerable": tr.get("expected_if_vulnerable", ""),
            })

        results_json = json.dumps(results_summary, indent=2, default=str)[:8000]

        return f"""You are a {self.definition.display_name} analyzing REAL HTTP responses from penetration tests against {target}.

## Test Results (ACTUAL HTTP responses — not simulated)
{results_json}

## Your Task

Analyze each test result and determine if a REAL vulnerability was found.
You are looking at ACTUAL server responses. Be rigorous:

- A vulnerability is CONFIRMED only if the response PROVES exploitation worked
- Look for: payload reflection, error messages, data leaks, behavior changes, timing anomalies
- Compare the "expected_if_vulnerable" hint with what actually appeared in the response
- Do NOT hallucinate — if the evidence is not in the response body/headers/status, it's NOT confirmed
- Status code alone is NOT proof (many 200s are normal, many 403s are WAF blocks)

Output a JSON block:
```json
{{
  "analysis": [
    {{
      "test_name": "Name of the test",
      "is_vulnerable": true/false,
      "confidence": "high|medium|low",
      "evidence": "Exact text/pattern from the response that proves the vulnerability",
      "title": "Short vulnerability title",
      "severity": "critical|high|medium|low|info",
      "explanation": "Why this is a real vulnerability (reference specific response content)"
    }}
  ]
}}
```

Only include entries where is_vulnerable is true. If no vulnerabilities found, return empty analysis array.
Be STRICT — false positives are worse than false negatives."""

    # ── Parse test plan from LLM ─────────────────────────────────────

    def _parse_test_plan(self, response: str, target: str) -> List[Dict]:
        """Extract structured test plan from LLM plan response."""
        # Find JSON block
        json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', response)
        if not json_match:
            json_match = re.search(r'(\{[\s\S]*"tests"[\s\S]*\})', response)

        if not json_match:
            return []

        try:
            plan = json.loads(json_match.group(1))
        except json.JSONDecodeError:
            # Try to fix common JSON issues
            try:
                cleaned = re.sub(r',\s*}', '}', json_match.group(1))
                cleaned = re.sub(r',\s*]', ']', cleaned)
                plan = json.loads(cleaned)
            except json.JSONDecodeError:
                return []

        tests = plan.get("tests", [])
        if not isinstance(tests, list):
            return []

        # Validate and normalize tests
        valid_tests = []
        for t in tests[:MAX_TESTS_PER_AGENT]:
            if not isinstance(t, dict):
                continue
            url = t.get("url", "")
            if not url:
                continue
            # Resolve relative URLs
            if url.startswith("/"):
                url = urljoin(target, url)
            # Ensure URL is within scope (same host)
            if urlparse(url).netloc and urlparse(url).netloc != urlparse(target).netloc:
                continue
            t["url"] = url
            t["method"] = t.get("method", "GET").upper()
            if t["method"] not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
                t["method"] = "GET"
            valid_tests.append(t)

        return valid_tests

    # ── Parse analysis findings from LLM ─────────────────────────────

    def _parse_analysis_findings(
        self, response: str, test_results: List[Dict], target: str
    ) -> List[Dict]:
        """Extract confirmed findings from LLM analysis of real responses."""
        json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', response)
        if not json_match:
            json_match = re.search(r'(\{[\s\S]*"analysis"[\s\S]*\})', response)

        if not json_match:
            # Fall back to parsing FINDING: blocks
            return self._parse_findings(response, target)

        try:
            data = json.loads(json_match.group(1))
        except json.JSONDecodeError:
            return self._parse_findings(response, target)

        findings = []
        for entry in data.get("analysis", []):
            if not isinstance(entry, dict):
                continue
            if not entry.get("is_vulnerable"):
                continue
            if entry.get("confidence") not in ("high", "medium"):
                continue

            evidence = entry.get("evidence", "")
            test_name = entry.get("test_name", "")

            # Anti-hallucination: verify evidence exists in actual response
            matched_result = None
            for tr in test_results:
                if tr.get("test_name") == test_name:
                    matched_result = tr
                    break

            if evidence and matched_result:
                body = matched_result.get("body_preview", "")
                headers_str = json.dumps(matched_result.get("response_headers", {}))
                combined = body + headers_str
                # Check evidence is grounded in actual response
                evidence_words = [w for w in evidence.lower().split() if len(w) > 3]
                if evidence_words:
                    grounded = sum(1 for w in evidence_words if w in combined.lower())
                    if grounded < len(evidence_words) * 0.3:
                        logger.debug(
                            f"[{self.definition.name}] REJECTED: evidence not grounded "
                            f"for {test_name}"
                        )
                        continue

            vuln_type = self.definition.name

            findings.append({
                "title": entry.get("title", f"{self.definition.display_name} Finding"),
                "severity": entry.get("severity", "medium"),
                "vulnerability_type": vuln_type,
                "cvss_score": 0.0,
                "cwe_id": "",
                "description": entry.get("explanation", ""),
                "affected_endpoint": matched_result.get("url", target) if matched_result else target,
                "evidence": evidence,
                "poc_code": (
                    f"# Request:\n{matched_result.get('method', 'GET')} "
                    f"{matched_result.get('url', target)}\n"
                    f"# Params: {json.dumps(matched_result.get('params', {}), default=str)}\n"
                    f"# Response Status: {matched_result.get('status', '?')}\n"
                    f"# Response Body (excerpt):\n{matched_result.get('body_preview', '')[:500]}"
                ) if matched_result else "",
                "impact": entry.get("explanation", ""),
                "remediation": "",
                "source_agent": self.definition.display_name,
                "parameter": "",
                "confidence": entry.get("confidence", "medium"),
                "http_evidence": {
                    "request_url": matched_result.get("url", "") if matched_result else "",
                    "request_method": matched_result.get("method", "") if matched_result else "",
                    "response_status": matched_result.get("status", 0) if matched_result else 0,
                    "response_time": matched_result.get("response_time", 0) if matched_result else 0,
                } if matched_result else {},
            })

        return findings

    # ── Template filling (for methodology context) ───────────────────

    def _fill_template(self, context: Dict) -> str:
        """Fill the .md template placeholders with recon context."""
        target = context.get("target", "")
        endpoints = context.get("endpoints", [])
        technologies = context.get("technologies", [])
        parameters = context.get("parameters", {})
        headers = context.get("headers", {})
        forms = context.get("forms", [])
        waf_info = context.get("waf_info", "")
        existing_findings = context.get("existing_findings", [])

        recon_data_json = json.dumps({
            "target": target,
            "endpoints": [
                ep.get("url", ep) if isinstance(ep, dict) else str(ep)
                for ep in endpoints[:30]
            ],
            "technologies": technologies[:15],
            "parameters": (
                {k: v for k, v in list(parameters.items())[:20]}
                if isinstance(parameters, dict) else {}
            ),
        }, indent=2)

        scope_json = json.dumps({
            "target": target,
            "endpoints_discovered": len(endpoints),
            "technologies": technologies[:15],
            "waf": waf_info or "Not detected",
        }, indent=2)

        existing_summary = ""
        if existing_findings:
            existing_summary = "\n".join(
                f"- [{getattr(f, 'severity', 'unknown').upper()}] "
                f"{getattr(f, 'title', '?')} at {getattr(f, 'affected_endpoint', '?')}"
                for f in existing_findings[:20]
            )

        replacements = {
            "{target}": target,
            "{recon_json}": recon_data_json,
            "{scope_json}": scope_json,
            "{initial_info_json}": recon_data_json,
            "{target_environment_json}": scope_json,
            "{user_input}": target,
            "{target_info_json}": recon_data_json,
            "{recon_data_json}": recon_data_json,
            "{mission_objectives_json}": json.dumps({
                "primary": f"Test {target} for vulnerabilities",
                "existing_findings": len(existing_findings),
            }),
            "{vulnerability_details_json}": recon_data_json,
            "{traffic_logs_json}": json.dumps({"target": target}),
            "{code_vulnerability_json}": json.dumps({
                "target": target, "technologies": technologies[:10],
            }),
        }

        prompt = self.definition.user_prompt_template
        for placeholder, value in replacements.items():
            prompt = prompt.replace(placeholder, value)

        return prompt[:2000]  # Cap methodology length to save tokens

    # ── Legacy finding parsing (fallback for theoretical responses) ───

    def _parse_findings(self, response: str, target: str) -> List[Dict]:
        """Parse FINDING: blocks or ## sections from LLM response (fallback)."""
        findings = []

        # Pattern 1: FINDING: blocks
        finding_blocks = re.split(r"(?:^|\n)FINDING:", response)
        if len(finding_blocks) > 1:
            for block in finding_blocks[1:]:
                parsed = self._parse_finding_block(block, target)
                if parsed:
                    findings.append(parsed)
            if findings:
                return findings

        # Pattern 2: Section-based
        vuln_sections = re.findall(
            r"##\s*\[?(Critical|High|Medium|Low|Info)\]?\s*(?:Vulnerability|Attack|OWASP\s+A\d+)[\s:]*([^\n]+)",
            response, re.IGNORECASE,
        )
        if vuln_sections:
            parts = re.split(
                r"(?=##\s*\[?(?:Critical|High|Medium|Low|Info)\]?\s*(?:Vulnerability|Attack|OWASP))",
                response, flags=re.IGNORECASE,
            )
            for part in parts:
                f = self._parse_finding_section(part, target)
                if f:
                    findings.append(f)

        return findings

    def _parse_finding_block(self, block: str, target: str) -> Optional[Dict]:
        """Parse a FINDING: key-value block."""
        if not block.strip():
            return None

        kvs: Dict[str, str] = {}
        for match in re.finditer(r"-\s*([A-Za-z][\w\s/]*?):\s*(.+)", block):
            key = match.group(1).strip().lower().replace(" ", "_")
            kvs[key] = match.group(2).strip()

        title = kvs.get("title", "").strip()
        if not title:
            return None

        sev_raw = kvs.get("severity", "medium").lower().strip()
        severity = "medium"
        for s in ("critical", "high", "medium", "low", "info"):
            if s in sev_raw:
                severity = s
                break

        cwe = ""
        cwe_match = re.search(r"CWE-(\d+)", kvs.get("cwe", ""))
        if cwe_match:
            cwe = f"CWE-{cwe_match.group(1)}"

        vuln_type = self.definition.name
        endpoint = kvs.get("endpoint", kvs.get("url", target)).strip()

        poc = ""
        code_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", block, re.DOTALL)
        if code_blocks:
            poc = "\n---\n".join(b.strip() for b in code_blocks[:3])

        return {
            "title": title,
            "severity": severity,
            "vulnerability_type": vuln_type,
            "cvss_score": 0.0,
            "cwe_id": cwe,
            "description": kvs.get("impact", ""),
            "affected_endpoint": endpoint,
            "evidence": kvs.get("evidence", kvs.get("proof", "")),
            "poc_code": poc or kvs.get("poc", kvs.get("payload", "")),
            "impact": kvs.get("impact", ""),
            "remediation": kvs.get("remediation", kvs.get("fix", "")),
            "source_agent": self.definition.display_name,
            "parameter": kvs.get("parameter", kvs.get("param", "")),
        }

    def _parse_finding_section(self, section: str, target: str) -> Optional[Dict]:
        """Parse a ## [SEVERITY] Vulnerability: ... section."""
        if not section.strip():
            return None

        title_match = re.search(
            r"##\s*\[?(?:Critical|High|Medium|Low|Info)\]?\s*(?:Vulnerability|Attack|OWASP[^:]*)[:\s]*(.+)",
            section, re.IGNORECASE,
        )
        title = title_match.group(1).strip() if title_match else ""
        if not title:
            return None

        severity = "medium"
        sev_match = re.search(
            r"\*\*Severity\*\*\s*\|?\s*(Critical|High|Medium|Low|Info)",
            section, re.IGNORECASE,
        )
        if sev_match:
            severity = sev_match.group(1).lower()
        else:
            header_sev = re.search(
                r"##\s*\[?(Critical|High|Medium|Low|Info)\]?",
                section, re.IGNORECASE,
            )
            if header_sev:
                severity = header_sev.group(1).lower()

        cwe_match = re.search(r"CWE-(\d+)", section)
        cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else ""

        poc = ""
        code_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", section, re.DOTALL)
        if code_blocks:
            poc = "\n---\n".join(b.strip() for b in code_blocks[:3])

        evidence = ""
        ev_match = re.search(
            r"###?\s*(?:Proof|Evidence)\s*\n(.*?)(?=\n###?\s|\Z)",
            section, re.DOTALL | re.IGNORECASE,
        )
        if ev_match:
            evidence = ev_match.group(1).strip()[:1000]

        return {
            "title": title,
            "severity": severity,
            "vulnerability_type": self._infer_vuln_type(title),
            "cvss_score": 0.0,
            "cwe_id": cwe,
            "description": "",
            "affected_endpoint": target,
            "evidence": evidence,
            "poc_code": poc,
            "impact": "",
            "remediation": "",
            "source_agent": self.definition.display_name,
        }

    @staticmethod
    def _infer_vuln_type(title: str) -> str:
        """Infer vulnerability type from finding title."""
        title_lower = title.lower()
        type_map = {
            "sql injection": "sqli_error", "sqli": "sqli_error",
            "xss": "xss_reflected", "cross-site scripting": "xss_reflected",
            "stored xss": "xss_stored", "dom xss": "xss_dom",
            "command injection": "command_injection", "rce": "command_injection",
            "ssrf": "ssrf", "csrf": "csrf", "lfi": "lfi",
            "path traversal": "path_traversal", "file upload": "file_upload",
            "xxe": "xxe", "ssti": "ssti", "open redirect": "open_redirect",
            "idor": "idor", "bola": "bola", "auth bypass": "auth_bypass",
            "jwt": "jwt_manipulation", "cors": "cors_misconfig",
            "crlf": "crlf_injection", "header injection": "header_injection",
            "nosql": "nosql_injection", "graphql": "graphql_injection",
            "race condition": "race_condition", "business logic": "business_logic",
            "subdomain takeover": "subdomain_takeover",
            "prototype pollution": "prototype_pollution",
            "websocket": "websocket_hijacking",
            "information disclosure": "information_disclosure",
            "directory listing": "directory_listing",
            "clickjacking": "clickjacking", "ssl": "ssl_issues",
        }
        for keyword, vtype in type_map.items():
            if keyword in title_lower:
                return vtype
        return "unknown"


# ─── MdAgentLibrary: loads all .md agents ────────────────────────────

class MdAgentLibrary:
    """Loads all .md files from prompts/agents/ and indexes them."""

    def __init__(self, md_dir: str = ""):
        if not md_dir:
            # Resolve relative to project root (parent of backend/)
            project_root = Path(__file__).resolve().parent.parent.parent
            md_dir = str(project_root / "prompts" / "agents")
        self.md_dir = Path(md_dir)
        self.agents: Dict[str, MdAgentDefinition] = {}
        self._load_all()

    def _load_all(self):
        if not self.md_dir.is_dir():
            logger.warning(f"MD agent directory not found: {self.md_dir}")
            return

        for md_file in sorted(self.md_dir.glob("*.md")):
            name = md_file.stem
            if name in SKIP_AGENTS:
                continue

            try:
                content = md_file.read_text(encoding="utf-8")

                user_match = re.search(
                    r"## User Prompt\n(.*?)(?=\n## System Prompt|\Z)",
                    content, re.DOTALL,
                )
                system_match = re.search(
                    r"## System Prompt\n(.*?)(?=\n## User Prompt|\Z)",
                    content, re.DOTALL,
                )

                user_prompt = user_match.group(1).strip() if user_match else ""
                system_prompt = system_match.group(1).strip() if system_match else ""

                if not user_prompt and not system_prompt:
                    system_prompt = content.strip()

                placeholders = re.findall(r"\{(\w+)\}", user_prompt)

                display_name = name.replace("_", " ").title()
                title_match = re.search(r"^#\s+(.+)", content)
                if title_match:
                    raw_title = title_match.group(1).strip()
                    display_name = re.sub(
                        r"\s*(?:Specialist Agent|Agent|Prompt)\s*$",
                        "", raw_title,
                    ).strip()

                category = AGENT_CATEGORIES.get(name, "offensive")

                self.agents[name] = MdAgentDefinition(
                    name=name,
                    display_name=display_name,
                    category=category,
                    user_prompt_template=user_prompt,
                    system_prompt=system_prompt,
                    file_path=str(md_file.resolve()),
                    placeholders=placeholders,
                )
                logger.debug(f"Loaded MD agent: {name} ({category})")

            except Exception as e:
                logger.warning(f"Failed to load MD agent {md_file.name}: {e}")

        logger.info(
            f"MdAgentLibrary: loaded {len(self.agents)} agents from {self.md_dir}"
        )

    def get_agent(self, name: str) -> Optional[MdAgentDefinition]:
        return self.agents.get(name)

    def get_all_runnable(self) -> List[MdAgentDefinition]:
        """Return ALL agents that can be dispatched."""
        return [
            a for a in self.agents.values()
            if a.category in ("offensive", "generalist", "recon")
        ]

    def get_offensive_agents(self) -> List[MdAgentDefinition]:
        return [a for a in self.agents.values() if a.category == "offensive"]

    def get_by_category(self, category: str) -> List[MdAgentDefinition]:
        return [a for a in self.agents.values() if a.category == category]

    def list_agents(self) -> List[Dict]:
        return [
            {
                "name": a.name,
                "display_name": a.display_name,
                "category": a.category,
                "placeholders": a.placeholders,
            }
            for a in self.agents.values()
        ]


# ─── MdAgentOrchestrator: phased execution ──────────────────────────

class MdAgentOrchestrator:
    """Coordinates execution of .md-based agents in phases.

    Flow:
      Phase 1: Recon agents (discover more attack surface)
      Phase 2: Offensive agents (test specific vuln types, 5 concurrent)
      Phase 3: Generalist agents (cross-cutting analysis)
    All agents execute REAL HTTP requests.
    """

    MAX_CONCURRENT = 2  # Keep low to avoid API rate limits

    def __init__(
        self,
        llm=None,
        memory=None,
        budget=None,
        validation_judge=None,
        log_callback: Optional[Callable] = None,
        progress_callback: Optional[Callable] = None,
        http_session=None,
        auth_headers: Optional[Dict] = None,
        cancel_fn: Optional[Callable] = None,
    ):
        self.llm = llm
        self.memory = memory
        self.budget = budget
        self.validation_judge = validation_judge
        self.log = log_callback
        self.progress_callback = progress_callback
        self.http_session = http_session
        self.auth_headers = auth_headers or {}
        self.cancel_fn = cancel_fn or (lambda: False)
        self.library = MdAgentLibrary()
        self._cancel_event = asyncio.Event()

    async def _log(self, level: str, message: str):
        if self.log:
            await self.log(level, message)

    async def run(
        self,
        target: str,
        recon_data: Any = None,
        existing_findings: List[Any] = None,
        selected_agents: Optional[List[str]] = None,
        headers: Optional[Dict] = None,
        waf_info: str = "",
    ) -> Dict:
        """Execute agents in phases: recon → offensive → generalist."""
        start_time = time.time()
        self._cancel_event.clear()

        # Merge auth headers
        all_headers = {**self.auth_headers}
        if headers:
            all_headers.update(headers)

        # Resolve agents
        agents_to_run = self._resolve_agents(selected_agents)
        if not agents_to_run:
            await self._log("warning", "[AGENT GRID] No agents available")
            return {"findings": [], "agent_results": {}, "duration": 0}

        # Split into phases
        recon_agents = [a for a in agents_to_run if a.category == "recon"]
        offensive_agents = [a for a in agents_to_run if a.category == "offensive"]
        generalist_agents = [a for a in agents_to_run if a.category == "generalist"]

        await self._log("info",
            f"[AGENT GRID] {len(agents_to_run)} agents: "
            f"{len(recon_agents)} recon, {len(offensive_agents)} offensive, "
            f"{len(generalist_agents)} generalist")

        # Build shared context
        context = self._build_context(
            target, recon_data, existing_findings, all_headers, waf_info,
        )

        all_results: Dict[str, AgentResult] = {}
        all_findings: List[Dict] = []

        # ── Phase 1: Recon agents (sequential, enriches context) ──
        if recon_agents and not self._cancel_event.is_set():
            await self._log("info", "[PHASE 1] Recon agents — deep discovery")
            for defn in recon_agents:
                if self._cancel_event.is_set():
                    break
                r = await self._run_agent(defn, context, all_headers)
                all_results[r.agent_name] = r
                all_findings.extend(r.findings)
                # Recon findings enrich context for subsequent phases
                if r.findings:
                    context["existing_findings"] = (
                        context.get("existing_findings", []) + r.findings
                    )

        # ── Phase 2: Offensive agents (parallel, bounded) ──
        if offensive_agents and not self._cancel_event.is_set():
            await self._log("info",
                f"[PHASE 2] {len(offensive_agents)} offensive agents — real exploitation")
            phase_results = await self._run_parallel(
                offensive_agents, context, all_headers
            )
            for r in phase_results:
                all_results[r.agent_name] = r
                all_findings.extend(r.findings)

        # ── Phase 3: Generalist agents (parallel, cross-analysis) ──
        if generalist_agents and not self._cancel_event.is_set():
            # Update context with all findings so far
            context["existing_findings"] = (
                context.get("existing_findings", []) + all_findings
            )
            await self._log("info",
                f"[PHASE 3] {len(generalist_agents)} generalist agents — cross-analysis")
            phase_results = await self._run_parallel(
                generalist_agents, context, all_headers
            )
            for r in phase_results:
                all_results[r.agent_name] = r
                all_findings.extend(r.findings)

        elapsed = time.time() - start_time
        total_tokens = sum(
            r.tokens_used for r in all_results.values()
            if isinstance(r, AgentResult)
        )

        await self._log("info",
            f"[AGENT GRID] Complete: {len(all_findings)} findings from "
            f"{len(agents_to_run)} agents in {elapsed:.1f}s")

        return {
            "findings": all_findings,
            "agent_results": {
                name: {
                    "status": r.status,
                    "findings_count": len(r.findings),
                    "tokens_used": r.tokens_used,
                    "duration": round(r.duration, 1),
                    "error": r.error,
                }
                for name, r in all_results.items()
                if isinstance(r, AgentResult)
            },
            "total_findings": len(all_findings),
            "total_tokens": total_tokens,
            "agents_run": len(agents_to_run),
            "duration": round(elapsed, 1),
        }

    async def _run_agent(
        self, defn: MdAgentDefinition, context: Dict, headers: Dict
    ) -> AgentResult:
        """Run a single agent."""
        agent = MdAgent(
            definition=defn,
            llm=self.llm,
            memory=self.memory,
            budget_allocation=1.0 / max(len(self.library.agents), 1),
            budget=self.budget,
            validation_judge=self.validation_judge,
            http_session=self.http_session,
            auth_headers=headers,
            cancel_fn=self.cancel_fn,
        )
        await self._log("info", f"  [{defn.display_name}] Starting...")
        result = await agent.execute(context)
        if result.error:
            await self._log("warning",
                f"  [{defn.display_name}] Error: {result.error[:100]}, {result.duration:.1f}s")
        elif result.findings:
            await self._log("success",
                f"  [{defn.display_name}] {len(result.findings)} findings! {result.duration:.1f}s")
        else:
            await self._log("info",
                f"  [{defn.display_name}] Clean, {result.duration:.1f}s")
        return result

    async def _run_parallel(
        self, agents: List[MdAgentDefinition], context: Dict, headers: Dict
    ) -> List[AgentResult]:
        """Run agents in parallel with bounded concurrency."""
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)

        agent_index = [0]  # mutable counter for staggering

        async def _bounded(defn: MdAgentDefinition) -> AgentResult:
            async with semaphore:
                if self._cancel_event.is_set():
                    return AgentResult(agent_name=f"md_{defn.name}", status="cancelled")
                # Stagger API calls: small delay based on position
                idx = agent_index[0]
                agent_index[0] += 1
                if idx > 0:
                    await asyncio.sleep(2.0)  # 2s between each agent start to respect rate limits
                return await self._run_agent(defn, context, headers)

        tasks = [_bounded(d) for d in agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final = []
        for defn, res in zip(agents, results):
            if isinstance(res, Exception):
                logger.error(f"Agent {defn.name} error: {res}")
                final.append(AgentResult(
                    agent_name=f"md_{defn.name}", status="failed", error=str(res)
                ))
            else:
                final.append(res)
        return final

    def _resolve_agents(
        self, selected: Optional[List[str]],
    ) -> List[MdAgentDefinition]:
        """Resolve agent selection."""
        if selected:
            resolved = []
            for name in selected:
                defn = self.library.get_agent(name)
                if defn:
                    resolved.append(defn)
                else:
                    logger.warning(f"MD agent not found: {name}")
            return resolved

        if RUN_ALL_BY_DEFAULT:
            return self.library.get_all_runnable()
        return self.library.get_offensive_agents()

    def _build_context(
        self,
        target: str,
        recon_data: Any,
        existing_findings: List[Any],
        headers: Optional[Dict],
        waf_info: str,
    ) -> Dict:
        ctx: Dict[str, Any] = {"target": target}

        if recon_data:
            ctx["endpoints"] = getattr(recon_data, "endpoints", [])
            ctx["technologies"] = getattr(recon_data, "technologies", [])
            ctx["parameters"] = getattr(recon_data, "parameters", {})
            ctx["forms"] = getattr(recon_data, "forms", [])
            ctx["headers"] = getattr(recon_data, "response_headers", {})
            ctx["js_files"] = getattr(recon_data, "js_files", [])
            ctx["js_sinks"] = getattr(recon_data, "js_sinks", [])
            ctx["api_endpoints"] = getattr(recon_data, "api_endpoints", [])
            ctx["cookies"] = getattr(recon_data, "cookies", [])
        else:
            ctx["endpoints"] = []
            ctx["technologies"] = []
            ctx["parameters"] = {}
            ctx["forms"] = []
            ctx["headers"] = {}
            ctx["js_files"] = []
            ctx["js_sinks"] = []
            ctx["api_endpoints"] = []
            ctx["cookies"] = []

        if headers:
            ctx["headers"].update(headers)

        ctx["existing_findings"] = existing_findings or []
        ctx["waf_info"] = waf_info
        return ctx

    def cancel(self):
        self._cancel_event.set()

    def list_available_agents(self) -> List[Dict]:
        return self.library.list_agents()
