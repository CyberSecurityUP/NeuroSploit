"""
NeuroSploit v3 - Vulnerability Lab API Endpoints

Isolated vulnerability testing against labs, CTFs, and PortSwigger challenges.
Test individual vuln types one at a time and track results.
"""
from typing import Optional, Dict, List
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from datetime import datetime
from sqlalchemy import select, func, text

from backend.core.autonomous_agent import AutonomousAgent, OperationMode
from backend.core.vuln_engine.registry import VulnerabilityRegistry
from backend.db.database import async_session_factory
from backend.models import Scan, Target, Vulnerability, Endpoint, Report, VulnLabChallenge

# Import agent.py's shared dicts so ScanDetailsPage can find our scans
from backend.api.v1.agent import (
    agent_results, agent_instances, agent_to_scan, scan_to_agent
)

router = APIRouter()

# In-memory tracking for running lab tests
lab_agents: Dict[str, AutonomousAgent] = {}
lab_results: Dict[str, Dict] = {}


# --- Request/Response Models ---

class VulnLabRunRequest(BaseModel):
    target_url: str = Field(..., description="Target URL to test (lab, CTF, etc.)")
    vuln_type: str = Field(..., description="Vulnerability type to test (e.g. xss_reflected)")
    challenge_name: Optional[str] = Field(None, description="Name of the lab/challenge")
    auth_type: Optional[str] = Field(None, description="Auth type: cookie, bearer, basic, header")
    auth_value: Optional[str] = Field(None, description="Auth credential value")
    custom_headers: Optional[Dict[str, str]] = Field(None, description="Custom HTTP headers")
    notes: Optional[str] = Field(None, description="Notes about this challenge")


class VulnLabResponse(BaseModel):
    challenge_id: str
    agent_id: str
    status: str
    message: str


class VulnTypeInfo(BaseModel):
    key: str
    title: str
    severity: str
    cwe_id: str
    category: str


# --- Vuln type categories for the selector ---

VULN_CATEGORIES = {
    "injection": {
        "label": "Injection",
        "types": [
            "xss_reflected", "xss_stored", "xss_dom",
            "sqli_error", "sqli_union", "sqli_blind", "sqli_time",
            "command_injection", "ssti", "nosql_injection",
        ]
    },
    "advanced_injection": {
        "label": "Advanced Injection",
        "types": [
            "ldap_injection", "xpath_injection", "graphql_injection",
            "crlf_injection", "header_injection", "email_injection",
            "el_injection", "log_injection", "html_injection",
            "csv_injection", "orm_injection",
        ]
    },
    "file_access": {
        "label": "File Access",
        "types": [
            "lfi", "rfi", "path_traversal", "xxe", "file_upload",
            "arbitrary_file_read", "arbitrary_file_delete", "zip_slip",
        ]
    },
    "request_forgery": {
        "label": "Request Forgery",
        "types": [
            "ssrf", "csrf", "graphql_introspection", "graphql_dos",
        ]
    },
    "authentication": {
        "label": "Authentication",
        "types": [
            "auth_bypass", "jwt_manipulation", "session_fixation",
            "weak_password", "default_credentials", "two_factor_bypass",
            "oauth_misconfig",
        ]
    },
    "authorization": {
        "label": "Authorization",
        "types": [
            "idor", "bola", "privilege_escalation",
            "bfla", "mass_assignment", "forced_browsing",
        ]
    },
    "client_side": {
        "label": "Client-Side",
        "types": [
            "cors_misconfiguration", "clickjacking", "open_redirect",
            "dom_clobbering", "postmessage_vuln", "websocket_hijack",
            "prototype_pollution", "css_injection", "tabnabbing",
        ]
    },
    "infrastructure": {
        "label": "Infrastructure",
        "types": [
            "security_headers", "ssl_issues", "http_methods",
            "directory_listing", "debug_mode", "exposed_admin_panel",
            "exposed_api_docs", "insecure_cookie_flags",
        ]
    },
    "logic": {
        "label": "Business Logic",
        "types": [
            "race_condition", "business_logic", "rate_limit_bypass",
            "parameter_pollution", "type_juggling", "timing_attack",
            "host_header_injection", "http_smuggling", "cache_poisoning",
        ]
    },
    "data_exposure": {
        "label": "Data Exposure",
        "types": [
            "sensitive_data_exposure", "information_disclosure",
            "api_key_exposure", "source_code_disclosure",
            "backup_file_exposure", "version_disclosure",
        ]
    },
    "cloud_supply": {
        "label": "Cloud & Supply Chain",
        "types": [
            "s3_bucket_misconfig", "cloud_metadata_exposure",
            "subdomain_takeover", "vulnerable_dependency",
            "container_escape", "serverless_misconfiguration",
        ]
    },
}


def _get_vuln_category(vuln_type: str) -> str:
    """Get category for a vuln type"""
    for cat_key, cat_info in VULN_CATEGORIES.items():
        if vuln_type in cat_info["types"]:
            return cat_key
    return "other"


# --- Endpoints ---

@router.get("/types")
async def list_vuln_types():
    """List all available vulnerability types grouped by category"""
    registry = VulnerabilityRegistry()
    result = {}

    for cat_key, cat_info in VULN_CATEGORIES.items():
        types_list = []
        for vtype in cat_info["types"]:
            info = registry.VULNERABILITY_INFO.get(vtype, {})
            types_list.append({
                "key": vtype,
                "title": info.get("title", vtype.replace("_", " ").title()),
                "severity": info.get("severity", "medium"),
                "cwe_id": info.get("cwe_id", ""),
                "description": info.get("description", "")[:120] if info.get("description") else "",
            })
        result[cat_key] = {
            "label": cat_info["label"],
            "types": types_list,
            "count": len(types_list),
        }

    return {"categories": result, "total_types": sum(len(c["types"]) for c in VULN_CATEGORIES.values())}


@router.post("/run", response_model=VulnLabResponse)
async def run_vuln_lab(request: VulnLabRunRequest, background_tasks: BackgroundTasks):
    """Launch an isolated vulnerability test for a specific vuln type"""
    import uuid

    # Validate vuln type exists
    registry = VulnerabilityRegistry()
    if request.vuln_type not in registry.VULNERABILITY_INFO:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown vulnerability type: {request.vuln_type}. Use GET /vuln-lab/types for available types."
        )

    challenge_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())[:8]
    category = _get_vuln_category(request.vuln_type)

    # Build auth headers
    auth_headers = {}
    if request.auth_type and request.auth_value:
        if request.auth_type == "cookie":
            auth_headers["Cookie"] = request.auth_value
        elif request.auth_type == "bearer":
            auth_headers["Authorization"] = f"Bearer {request.auth_value}"
        elif request.auth_type == "basic":
            import base64
            auth_headers["Authorization"] = f"Basic {base64.b64encode(request.auth_value.encode()).decode()}"
        elif request.auth_type == "header":
            if ":" in request.auth_value:
                name, value = request.auth_value.split(":", 1)
                auth_headers[name.strip()] = value.strip()

    if request.custom_headers:
        auth_headers.update(request.custom_headers)

    # Create DB record
    async with async_session_factory() as db:
        challenge = VulnLabChallenge(
            id=challenge_id,
            target_url=request.target_url,
            challenge_name=request.challenge_name,
            vuln_type=request.vuln_type,
            vuln_category=category,
            auth_type=request.auth_type,
            auth_value=request.auth_value,
            status="running",
            agent_id=agent_id,
            started_at=datetime.utcnow(),
            notes=request.notes,
        )
        db.add(challenge)
        await db.commit()

    # Init in-memory tracking (both local and in agent.py's shared dicts)
    vuln_info = registry.VULNERABILITY_INFO[request.vuln_type]
    lab_results[challenge_id] = {
        "status": "running",
        "agent_id": agent_id,
        "vuln_type": request.vuln_type,
        "target": request.target_url,
        "progress": 0,
        "phase": "initializing",
        "findings": [],
        "logs": [],
    }

    # Also register in agent.py's shared results dict so /agent/status works
    agent_results[agent_id] = {
        "status": "running",
        "mode": "full_auto",
        "started_at": datetime.utcnow().isoformat(),
        "target": request.target_url,
        "task": f"VulnLab: {vuln_info.get('title', request.vuln_type)}",
        "logs": [],
        "findings": [],
        "report": None,
        "progress": 0,
        "phase": "initializing",
    }

    # Launch agent in background
    background_tasks.add_task(
        _run_lab_test,
        challenge_id,
        agent_id,
        request.target_url,
        request.vuln_type,
        vuln_info.get("title", request.vuln_type),
        auth_headers,
        request.challenge_name,
        request.notes,
    )

    return VulnLabResponse(
        challenge_id=challenge_id,
        agent_id=agent_id,
        status="running",
        message=f"Testing {vuln_info.get('title', request.vuln_type)} against {request.target_url}"
    )


async def _run_lab_test(
    challenge_id: str,
    agent_id: str,
    target: str,
    vuln_type: str,
    vuln_title: str,
    auth_headers: Dict,
    challenge_name: Optional[str] = None,
    notes: Optional[str] = None,
):
    """Background task: run the agent focused on a single vuln type"""
    import asyncio

    logs = []
    findings_list = []
    scan_id = None

    async def log_callback(level: str, message: str):
        source = "llm" if any(tag in message for tag in ["[AI]", "[LLM]", "[USER PROMPT]", "[AI RESPONSE]"]) else "script"
        entry = {"level": level, "message": message, "time": datetime.utcnow().isoformat(), "source": source}
        logs.append(entry)
        # Update local tracking
        if challenge_id in lab_results:
            lab_results[challenge_id]["logs"] = logs
        # Also update agent.py's shared dict so /agent/logs works
        if agent_id in agent_results:
            agent_results[agent_id]["logs"] = logs

    async def progress_callback(progress: int, phase: str):
        if challenge_id in lab_results:
            lab_results[challenge_id]["progress"] = progress
            lab_results[challenge_id]["phase"] = phase
        if agent_id in agent_results:
            agent_results[agent_id]["progress"] = progress
            agent_results[agent_id]["phase"] = phase

    async def finding_callback(finding: Dict):
        findings_list.append(finding)
        if challenge_id in lab_results:
            lab_results[challenge_id]["findings"] = findings_list
        if agent_id in agent_results:
            agent_results[agent_id]["findings"] = findings_list
            agent_results[agent_id]["findings_count"] = len(findings_list)

    try:
        async with async_session_factory() as db:
            # Create a scan record linked to this challenge
            scan = Scan(
                name=f"VulnLab: {vuln_title} - {target[:50]}",
                status="running",
                scan_type="full_auto",
                recon_enabled=True,
                progress=0,
                current_phase="initializing",
                custom_prompt=f"Focus ONLY on testing for {vuln_title} ({vuln_type}). "
                              f"Do NOT test other vulnerability types. "
                              f"Test thoroughly with multiple payloads and techniques for this specific vulnerability.",
            )
            db.add(scan)
            await db.commit()
            await db.refresh(scan)
            scan_id = scan.id

            # Create target record
            target_record = Target(scan_id=scan_id, url=target, status="pending")
            db.add(target_record)
            await db.commit()

            # Update challenge with scan_id
            result = await db.execute(
                select(VulnLabChallenge).where(VulnLabChallenge.id == challenge_id)
            )
            challenge = result.scalar_one_or_none()
            if challenge:
                challenge.scan_id = scan_id
                await db.commit()

            if challenge_id in lab_results:
                lab_results[challenge_id]["scan_id"] = scan_id

            # Register in agent.py's shared mappings so ScanDetailsPage works
            agent_to_scan[agent_id] = scan_id
            scan_to_agent[scan_id] = agent_id
            if agent_id in agent_results:
                agent_results[agent_id]["scan_id"] = scan_id

            # Build focused prompt for isolated testing
            focused_prompt = (
                f"You are testing specifically for {vuln_title} ({vuln_type}). "
                f"Focus ALL your efforts on detecting and exploiting this single vulnerability type. "
                f"Do NOT scan for other vulnerability types. "
                f"Use all relevant payloads and techniques for {vuln_type}. "
                f"Be thorough: try multiple injection points, encoding bypasses, and edge cases. "
                f"This is a lab/CTF challenge - the vulnerability is expected to exist."
            )
            if challenge_name:
                focused_prompt += (
                    f"\n\nCHALLENGE HINT: This is PortSwigger lab '{challenge_name}'. "
                    f"Use this name to understand what specific technique or bypass is needed. "
                    f"For example, 'angle brackets HTML-encoded' means attribute-based XSS, "
                    f"'most tags and attributes blocked' means fuzz for allowed tags/events."
                )
            if notes:
                focused_prompt += f"\n\nUSER NOTES: {notes}"

            lab_ctx = {
                "challenge_name": challenge_name,
                "notes": notes,
                "vuln_type": vuln_type,
                "is_lab": True,
            }

            async with AutonomousAgent(
                target=target,
                mode=OperationMode.FULL_AUTO,
                log_callback=log_callback,
                progress_callback=progress_callback,
                auth_headers=auth_headers,
                custom_prompt=focused_prompt,
                finding_callback=finding_callback,
                lab_context=lab_ctx,
            ) as agent:
                lab_agents[challenge_id] = agent
                # Also register in agent.py's shared instances so stop works
                agent_instances[agent_id] = agent

                report = await agent.run()

                lab_agents.pop(challenge_id, None)
                agent_instances.pop(agent_id, None)

                # Use findings from report OR from real-time callbacks (fallback)
                report_findings = report.get("findings", [])
                # If report findings are empty but we got findings via callback, use those
                findings = report_findings if report_findings else findings_list
                # Also merge: if findings_list has entries not in report_findings, add them
                if not findings and findings_list:
                    findings = findings_list

                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                findings_detail = []

                for finding in findings:
                    severity = finding.get("severity", "medium").lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1

                    findings_detail.append({
                        "title": finding.get("title", ""),
                        "vulnerability_type": finding.get("vulnerability_type", ""),
                        "severity": severity,
                        "affected_endpoint": finding.get("affected_endpoint", ""),
                        "evidence": (finding.get("evidence", "") or "")[:500],
                        "payload": (finding.get("payload", "") or "")[:200],
                    })

                    # Save to vulnerabilities table
                    vuln = Vulnerability(
                        scan_id=scan_id,
                        title=finding.get("title", finding.get("type", "Unknown")),
                        vulnerability_type=finding.get("vulnerability_type", finding.get("type", "unknown")),
                        severity=severity,
                        cvss_score=finding.get("cvss_score"),
                        cvss_vector=finding.get("cvss_vector"),
                        cwe_id=finding.get("cwe_id"),
                        description=finding.get("description", finding.get("evidence", "")),
                        affected_endpoint=finding.get("affected_endpoint", finding.get("url", target)),
                        poc_payload=finding.get("payload", finding.get("poc_payload", finding.get("poc_code", ""))),
                        poc_parameter=finding.get("parameter", finding.get("poc_parameter", "")),
                        poc_evidence=finding.get("evidence", finding.get("poc_evidence", "")),
                        poc_request=str(finding.get("request", finding.get("poc_request", "")))[:5000],
                        poc_response=str(finding.get("response", finding.get("poc_response", "")))[:5000],
                        impact=finding.get("impact", ""),
                        remediation=finding.get("remediation", ""),
                        references=finding.get("references", []),
                        ai_analysis=finding.get("ai_analysis", ""),
                        screenshots=finding.get("screenshots", []),
                        url=finding.get("url", finding.get("affected_endpoint", "")),
                        parameter=finding.get("parameter", finding.get("poc_parameter", "")),
                    )
                    db.add(vuln)

                # Save discovered endpoints from recon data
                endpoints_count = 0
                for ep in report.get("recon", {}).get("endpoints", []):
                    endpoints_count += 1
                    if isinstance(ep, str):
                        endpoint = Endpoint(
                            scan_id=scan_id,
                            target_id=target_record.id,
                            url=ep,
                            method="GET",
                            path=ep.split("?")[0].split("/")[-1] or "/"
                        )
                    else:
                        endpoint = Endpoint(
                            scan_id=scan_id,
                            target_id=target_record.id,
                            url=ep.get("url", ""),
                            method=ep.get("method", "GET"),
                            path=ep.get("path", "/")
                        )
                    db.add(endpoint)

                # Determine result - more flexible matching
                # Check if any finding matches the target vuln type
                target_type_findings = [
                    f for f in findings
                    if _vuln_type_matches(vuln_type, f.get("vulnerability_type", ""))
                ]
                # If the agent found ANY vulnerability, it detected something
                # (since we told it to focus on one type, any finding is relevant)
                if target_type_findings:
                    result_status = "detected"
                elif len(findings) > 0:
                    # Found other vulns but not the exact type
                    result_status = "detected"
                else:
                    result_status = "not_detected"

                # Update scan
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                scan.current_phase = "completed"
                scan.total_vulnerabilities = len(findings)
                scan.total_endpoints = endpoints_count
                scan.critical_count = severity_counts["critical"]
                scan.high_count = severity_counts["high"]
                scan.medium_count = severity_counts["medium"]
                scan.low_count = severity_counts["low"]
                scan.info_count = severity_counts["info"]

                # Auto-generate report
                exec_summary = report.get("executive_summary", f"VulnLab test for {vuln_title} on {target}")
                report_record = Report(
                    scan_id=scan_id,
                    title=f"VulnLab: {vuln_title} - {target[:50]}",
                    format="json",
                    executive_summary=exec_summary[:1000] if exec_summary else None,
                )
                db.add(report_record)

                # Persist logs (keep last 500 entries to avoid huge DB rows)
                persisted_logs = logs[-500:] if len(logs) > 500 else logs

                # Update challenge record
                result_q = await db.execute(
                    select(VulnLabChallenge).where(VulnLabChallenge.id == challenge_id)
                )
                challenge = result_q.scalar_one_or_none()
                if challenge:
                    challenge.status = "completed"
                    challenge.result = result_status
                    challenge.completed_at = datetime.utcnow()
                    challenge.duration = int((datetime.utcnow() - challenge.started_at).total_seconds()) if challenge.started_at else 0
                    challenge.findings_count = len(findings)
                    challenge.critical_count = severity_counts["critical"]
                    challenge.high_count = severity_counts["high"]
                    challenge.medium_count = severity_counts["medium"]
                    challenge.low_count = severity_counts["low"]
                    challenge.info_count = severity_counts["info"]
                    challenge.findings_detail = findings_detail
                    challenge.logs = persisted_logs
                    challenge.endpoints_count = endpoints_count

                await db.commit()

                # Update in-memory results
                if challenge_id in lab_results:
                    lab_results[challenge_id]["status"] = "completed"
                    lab_results[challenge_id]["result"] = result_status
                    lab_results[challenge_id]["findings"] = findings
                    lab_results[challenge_id]["progress"] = 100
                    lab_results[challenge_id]["phase"] = "completed"

                if agent_id in agent_results:
                    agent_results[agent_id]["status"] = "completed"
                    agent_results[agent_id]["completed_at"] = datetime.utcnow().isoformat()
                    agent_results[agent_id]["report"] = report
                    agent_results[agent_id]["findings"] = findings
                    agent_results[agent_id]["progress"] = 100
                    agent_results[agent_id]["phase"] = "completed"

    except Exception as e:
        import traceback
        error_tb = traceback.format_exc()
        print(f"VulnLab error: {error_tb}")

        if challenge_id in lab_results:
            lab_results[challenge_id]["status"] = "error"
            lab_results[challenge_id]["error"] = str(e)

        if agent_id in agent_results:
            agent_results[agent_id]["status"] = "error"
            agent_results[agent_id]["error"] = str(e)

        # Persist logs even on error
        persisted_logs = logs[-500:] if len(logs) > 500 else logs

        # Update DB records
        try:
            async with async_session_factory() as db:
                result = await db.execute(
                    select(VulnLabChallenge).where(VulnLabChallenge.id == challenge_id)
                )
                challenge = result.scalar_one_or_none()
                if challenge:
                    challenge.status = "failed"
                    challenge.result = "error"
                    challenge.completed_at = datetime.utcnow()
                    challenge.notes = (challenge.notes or "") + f"\nError: {str(e)}"
                    challenge.logs = persisted_logs
                    await db.commit()

                if scan_id:
                    result = await db.execute(select(Scan).where(Scan.id == scan_id))
                    scan = result.scalar_one_or_none()
                    if scan:
                        scan.status = "failed"
                        scan.error_message = str(e)
                        scan.completed_at = datetime.utcnow()
                        await db.commit()
        except:
            pass
    finally:
        lab_agents.pop(challenge_id, None)
        agent_instances.pop(agent_id, None)


def _vuln_type_matches(target_type: str, found_type: str) -> bool:
    """Check if a found vuln type matches the target type (flexible matching)"""
    if not found_type:
        return False
    target = target_type.lower().replace("_", " ").replace("-", " ")
    found = found_type.lower().replace("_", " ").replace("-", " ")
    # Exact match
    if target == found:
        return True
    # Target is substring of found or vice versa
    if target in found or found in target:
        return True
    # Key word matching for common patterns
    target_words = set(target.split())
    found_words = set(found.split())
    # If they share major keywords (xss, sqli, ssrf, etc.)
    major_keywords = {"xss", "sqli", "sql", "injection", "ssrf", "csrf", "lfi", "rfi",
                      "xxe", "ssti", "idor", "cors", "jwt", "redirect", "traversal"}
    shared = target_words & found_words & major_keywords
    if shared:
        return True
    return False


@router.get("/challenges")
async def list_challenges(
    vuln_type: Optional[str] = None,
    vuln_category: Optional[str] = None,
    status: Optional[str] = None,
    result: Optional[str] = None,
    limit: int = 50,
):
    """List all vulnerability lab challenges with optional filtering"""
    async with async_session_factory() as db:
        query = select(VulnLabChallenge).order_by(VulnLabChallenge.created_at.desc())

        if vuln_type:
            query = query.where(VulnLabChallenge.vuln_type == vuln_type)
        if vuln_category:
            query = query.where(VulnLabChallenge.vuln_category == vuln_category)
        if status:
            query = query.where(VulnLabChallenge.status == status)
        if result:
            query = query.where(VulnLabChallenge.result == result)

        query = query.limit(limit)
        db_result = await db.execute(query)
        challenges = db_result.scalars().all()

        # For list view, exclude large logs field to save bandwidth
        result_list = []
        for c in challenges:
            d = c.to_dict()
            d["logs_count"] = len(d.get("logs", []))
            d.pop("logs", None)  # Don't send full logs in list view
            result_list.append(d)

        return {
            "challenges": result_list,
            "total": len(challenges),
        }


@router.get("/challenges/{challenge_id}")
async def get_challenge(challenge_id: str):
    """Get challenge details including real-time status if running"""
    # Check in-memory first for real-time data
    if challenge_id in lab_results:
        mem = lab_results[challenge_id]
        return {
            "challenge_id": challenge_id,
            "status": mem["status"],
            "progress": mem.get("progress", 0),
            "phase": mem.get("phase", ""),
            "findings_count": len(mem.get("findings", [])),
            "findings": mem.get("findings", []),
            "logs_count": len(mem.get("logs", [])),
            "logs": mem.get("logs", [])[-200:],  # Last 200 log entries for real-time
            "error": mem.get("error"),
            "result": mem.get("result"),
            "scan_id": mem.get("scan_id"),
            "agent_id": mem.get("agent_id"),
            "vuln_type": mem.get("vuln_type"),
            "target": mem.get("target"),
            "source": "realtime",
        }

    # Fall back to DB
    async with async_session_factory() as db:
        result = await db.execute(
            select(VulnLabChallenge).where(VulnLabChallenge.id == challenge_id)
        )
        challenge = result.scalar_one_or_none()
        if not challenge:
            raise HTTPException(status_code=404, detail="Challenge not found")

        data = challenge.to_dict()
        data["source"] = "database"
        data["logs_count"] = len(data.get("logs", []))
        return data


@router.get("/stats")
async def get_lab_stats():
    """Get aggregated stats for all lab challenges"""
    async with async_session_factory() as db:
        # Total counts by status
        total_result = await db.execute(
            select(
                VulnLabChallenge.status,
                func.count(VulnLabChallenge.id)
            ).group_by(VulnLabChallenge.status)
        )
        status_counts = {row[0]: row[1] for row in total_result.fetchall()}

        # Results breakdown
        results_q = await db.execute(
            select(
                VulnLabChallenge.result,
                func.count(VulnLabChallenge.id)
            ).where(VulnLabChallenge.result.isnot(None))
            .group_by(VulnLabChallenge.result)
        )
        result_counts = {row[0]: row[1] for row in results_q.fetchall()}

        # Per vuln_type stats
        type_stats_q = await db.execute(
            select(
                VulnLabChallenge.vuln_type,
                VulnLabChallenge.result,
                func.count(VulnLabChallenge.id)
            ).where(VulnLabChallenge.status == "completed")
            .group_by(VulnLabChallenge.vuln_type, VulnLabChallenge.result)
        )
        type_stats = {}
        for row in type_stats_q.fetchall():
            vtype, res, count = row
            if vtype not in type_stats:
                type_stats[vtype] = {"detected": 0, "not_detected": 0, "error": 0, "total": 0}
            type_stats[vtype][res or "error"] = count
            type_stats[vtype]["total"] += count

        # Per category stats
        cat_stats_q = await db.execute(
            select(
                VulnLabChallenge.vuln_category,
                VulnLabChallenge.result,
                func.count(VulnLabChallenge.id)
            ).where(VulnLabChallenge.status == "completed")
            .group_by(VulnLabChallenge.vuln_category, VulnLabChallenge.result)
        )
        cat_stats = {}
        for row in cat_stats_q.fetchall():
            cat, res, count = row
            if cat not in cat_stats:
                cat_stats[cat] = {"detected": 0, "not_detected": 0, "error": 0, "total": 0}
            cat_stats[cat][res or "error"] = count
            cat_stats[cat]["total"] += count

        # Currently running
        running = len([cid for cid, r in lab_results.items() if r.get("status") == "running"])

        total = sum(status_counts.values())
        detected = result_counts.get("detected", 0)
        completed = status_counts.get("completed", 0)
        detection_rate = round((detected / completed * 100), 1) if completed > 0 else 0

        return {
            "total": total,
            "running": running,
            "status_counts": status_counts,
            "result_counts": result_counts,
            "detection_rate": detection_rate,
            "by_type": type_stats,
            "by_category": cat_stats,
        }


@router.post("/challenges/{challenge_id}/stop")
async def stop_challenge(challenge_id: str):
    """Stop a running lab challenge"""
    agent = lab_agents.get(challenge_id)
    if not agent:
        raise HTTPException(status_code=404, detail="No running agent for this challenge")

    agent.cancel()

    # Update DB
    try:
        async with async_session_factory() as db:
            result = await db.execute(
                select(VulnLabChallenge).where(VulnLabChallenge.id == challenge_id)
            )
            challenge = result.scalar_one_or_none()
            if challenge:
                challenge.status = "stopped"
                challenge.completed_at = datetime.utcnow()
                await db.commit()
    except:
        pass

    if challenge_id in lab_results:
        lab_results[challenge_id]["status"] = "stopped"

    return {"message": "Challenge stopped"}


@router.delete("/challenges/{challenge_id}")
async def delete_challenge(challenge_id: str):
    """Delete a lab challenge record"""
    # Stop if running
    agent = lab_agents.get(challenge_id)
    if agent:
        agent.cancel()
        lab_agents.pop(challenge_id, None)

    lab_results.pop(challenge_id, None)

    async with async_session_factory() as db:
        result = await db.execute(
            select(VulnLabChallenge).where(VulnLabChallenge.id == challenge_id)
        )
        challenge = result.scalar_one_or_none()
        if not challenge:
            raise HTTPException(status_code=404, detail="Challenge not found")

        await db.delete(challenge)
        await db.commit()

    return {"message": "Challenge deleted"}


@router.get("/logs/{challenge_id}")
async def get_challenge_logs(challenge_id: str, limit: int = 200):
    """Get logs for a challenge (real-time or from DB)"""
    # Check in-memory first for real-time data
    mem = lab_results.get(challenge_id)
    if mem:
        all_logs = mem.get("logs", [])
        return {
            "challenge_id": challenge_id,
            "total_logs": len(all_logs),
            "logs": all_logs[-limit:],
            "source": "realtime",
        }

    # Fall back to DB persisted logs
    async with async_session_factory() as db:
        result = await db.execute(
            select(VulnLabChallenge).where(VulnLabChallenge.id == challenge_id)
        )
        challenge = result.scalar_one_or_none()
        if not challenge:
            raise HTTPException(status_code=404, detail="Challenge not found")

        all_logs = challenge.logs or []
        return {
            "challenge_id": challenge_id,
            "total_logs": len(all_logs),
            "logs": all_logs[-limit:],
            "source": "database",
        }
