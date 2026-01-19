"""
NeuroSploit v3 - Dynamic Vulnerability Engine

The core of NeuroSploit v3: prompt-driven vulnerability testing.
Instead of hardcoded tests, this engine dynamically tests based on
what vulnerabilities are extracted from the user's prompt.
"""
import asyncio
import aiohttp
from typing import List, Dict, Optional, Any
from datetime import datetime

from backend.core.vuln_engine.registry import VulnerabilityRegistry
from backend.core.vuln_engine.payload_generator import PayloadGenerator
from backend.models import Endpoint, Vulnerability, VulnerabilityTest
from backend.schemas.prompt import VulnerabilityTypeExtracted


class TestResult:
    """Result of a vulnerability test"""
    def __init__(
        self,
        vuln_type: str,
        is_vulnerable: bool,
        confidence: float,
        payload: str,
        request_data: dict,
        response_data: dict,
        evidence: Optional[str] = None
    ):
        self.vuln_type = vuln_type
        self.is_vulnerable = is_vulnerable
        self.confidence = confidence
        self.payload = payload
        self.request_data = request_data
        self.response_data = response_data
        self.evidence = evidence


class DynamicVulnerabilityEngine:
    """
    Prompt-driven vulnerability testing engine.

    Key principles:
    1. Tests ONLY what the prompt specifies
    2. Generates payloads dynamically based on context
    3. Uses multiple detection techniques per vulnerability type
    4. Adapts based on target responses
    """

    def __init__(self, llm_manager=None):
        self.llm_manager = llm_manager
        self.registry = VulnerabilityRegistry()
        self.payload_generator = PayloadGenerator()
        self.session: Optional[aiohttp.ClientSession] = None
        self.timeout = aiohttp.ClientTimeout(total=30)

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def test_endpoint(
        self,
        endpoint: Endpoint,
        vuln_types: List[VulnerabilityTypeExtracted],
        context: Dict[str, Any],
        progress_callback=None
    ) -> List[TestResult]:
        """
        Test an endpoint for specified vulnerability types.

        Args:
            endpoint: The endpoint to test
            vuln_types: List of vulnerability types to test for
            context: Additional context (technologies, WAF info, etc.)
            progress_callback: Optional callback for progress updates

        Returns:
            List of test results
        """
        results = []

        if not self.session:
            self.session = aiohttp.ClientSession(timeout=self.timeout)

        for vuln in vuln_types:
            try:
                if progress_callback:
                    await progress_callback(f"Testing {vuln.type} on {endpoint.url}")

                # Get tester for this vulnerability type
                tester = self.registry.get_tester(vuln.type)

                # Get payloads for this vulnerability and endpoint
                payloads = await self.payload_generator.get_payloads(
                    vuln_type=vuln.type,
                    endpoint=endpoint,
                    context=context
                )

                # Test each payload
                for payload in payloads:
                    result = await self._execute_test(
                        endpoint=endpoint,
                        vuln_type=vuln.type,
                        payload=payload,
                        tester=tester,
                        context=context
                    )
                    results.append(result)

                    # If vulnerable, try to get more evidence
                    if result.is_vulnerable:
                        deeper_results = await self._deep_test(
                            endpoint=endpoint,
                            vuln_type=vuln.type,
                            initial_result=result,
                            tester=tester,
                            context=context
                        )
                        results.extend(deeper_results)
                        break  # Found vulnerability, move to next type

            except Exception as e:
                print(f"Error testing {vuln.type}: {e}")
                continue

        return results

    async def _execute_test(
        self,
        endpoint: Endpoint,
        vuln_type: str,
        payload: str,
        tester,
        context: Dict
    ) -> TestResult:
        """Execute a single vulnerability test"""
        request_data = {
            "url": endpoint.url,
            "method": endpoint.method,
            "payload": payload,
            "timestamp": datetime.utcnow().isoformat()
        }

        try:
            # Build the test request
            test_url, test_params, test_headers, test_body = tester.build_request(
                endpoint=endpoint,
                payload=payload
            )

            # Send the request
            async with self.session.request(
                method=endpoint.method,
                url=test_url,
                params=test_params,
                headers=test_headers,
                data=test_body,
                ssl=False,
                allow_redirects=False
            ) as response:
                response_text = await response.text()
                response_data = {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body_preview": response_text[:2000] if response_text else "",
                    "content_length": len(response_text) if response_text else 0
                }

                # Analyze response for vulnerability
                is_vulnerable, confidence, evidence = tester.analyze_response(
                    payload=payload,
                    response_status=response.status,
                    response_headers=dict(response.headers),
                    response_body=response_text,
                    context=context
                )

                return TestResult(
                    vuln_type=vuln_type,
                    is_vulnerable=is_vulnerable,
                    confidence=confidence,
                    payload=payload,
                    request_data=request_data,
                    response_data=response_data,
                    evidence=evidence
                )

        except asyncio.TimeoutError:
            # Timeout might indicate time-based injection
            response_data = {"error": "timeout", "timeout_seconds": self.timeout.total}
            is_vulnerable = tester.check_timeout_vulnerability(vuln_type)
            return TestResult(
                vuln_type=vuln_type,
                is_vulnerable=is_vulnerable,
                confidence=0.7 if is_vulnerable else 0.0,
                payload=payload,
                request_data=request_data,
                response_data=response_data,
                evidence="Request timed out - possible time-based vulnerability" if is_vulnerable else None
            )
        except Exception as e:
            response_data = {"error": str(e)}
            return TestResult(
                vuln_type=vuln_type,
                is_vulnerable=False,
                confidence=0.0,
                payload=payload,
                request_data=request_data,
                response_data=response_data,
                evidence=None
            )

    async def _deep_test(
        self,
        endpoint: Endpoint,
        vuln_type: str,
        initial_result: TestResult,
        tester,
        context: Dict
    ) -> List[TestResult]:
        """
        Perform deeper testing after initial vulnerability confirmation.
        This helps establish higher confidence and better PoC.
        """
        results = []

        # Get exploitation payloads
        deeper_payloads = await self.payload_generator.get_exploitation_payloads(
            vuln_type=vuln_type,
            initial_payload=initial_result.payload,
            context=context
        )

        for payload in deeper_payloads[:3]:  # Limit to 3 deeper tests
            result = await self._execute_test(
                endpoint=endpoint,
                vuln_type=vuln_type,
                payload=payload,
                tester=tester,
                context=context
            )
            if result.is_vulnerable:
                result.confidence = min(result.confidence + 0.1, 1.0)
            results.append(result)

        return results

    async def create_vulnerability_record(
        self,
        scan_id: str,
        endpoint: Endpoint,
        result: TestResult
    ) -> Vulnerability:
        """Create a vulnerability record from a test result"""
        # Get severity based on vulnerability type
        severity = self.registry.get_severity(result.vuln_type)

        # Get CWE ID
        cwe_id = self.registry.get_cwe_id(result.vuln_type)

        # Get remediation advice
        remediation = self.registry.get_remediation(result.vuln_type)

        # Generate title
        title = self.registry.get_title(result.vuln_type)

        return Vulnerability(
            scan_id=scan_id,
            title=f"{title} on {endpoint.path or endpoint.url}",
            vulnerability_type=result.vuln_type,
            severity=severity,
            cwe_id=cwe_id,
            description=self.registry.get_description(result.vuln_type),
            affected_endpoint=endpoint.url,
            poc_request=str(result.request_data),
            poc_response=str(result.response_data.get("body_preview", ""))[:5000],
            poc_payload=result.payload,
            impact=self.registry.get_impact(result.vuln_type),
            remediation=remediation,
            ai_analysis=result.evidence
        )
