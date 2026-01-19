"""
NeuroSploit v3 - AI Agent API Endpoints

Direct access to the Autonomous AI Security Agent.
Supports multiple operation modes like PentAGI.

NOW WITH DATABASE PERSISTENCE - Findings are saved to the database
and visible in the dashboard!
"""
from typing import Optional, Dict, List
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import asyncio
import aiohttp
import ssl
import socket
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse

from backend.core.autonomous_agent import AutonomousAgent, OperationMode
from backend.core.task_library import get_task_library
from backend.db.database import async_session_factory
from backend.models import Scan, Target, Vulnerability, Endpoint, Report

router = APIRouter()

# Store for agent results (in-memory cache for real-time status)
agent_results: Dict[str, Dict] = {}
agent_tasks: Dict[str, asyncio.Task] = {}
agent_instances: Dict[str, AutonomousAgent] = {}

# Map agent_id to scan_id for database persistence
agent_to_scan: Dict[str, str] = {}


@router.get("/status")
async def get_llm_status():
    """
    Check if LLM is properly configured.
    Call this before running the agent to verify setup.
    """
    import os

    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
    openai_key = os.getenv("OPENAI_API_KEY", "")

    # Check for placeholder values
    if anthropic_key in ["", "your-anthropic-api-key"]:
        anthropic_key = None
    if openai_key in ["", "your-openai-api-key"]:
        openai_key = None

    # Try to import libraries
    try:
        import anthropic
        anthropic_lib = True
    except ImportError:
        anthropic_lib = False

    try:
        import openai
        openai_lib = True
    except ImportError:
        openai_lib = False

    # Determine status
    if anthropic_key and anthropic_lib:
        status = "ready"
        provider = "claude"
        message = "Claude API configured and ready"
    elif openai_key and openai_lib:
        status = "ready"
        provider = "openai"
        message = "OpenAI API configured and ready"
    elif not anthropic_lib and not openai_lib:
        status = "error"
        provider = None
        message = "No LLM libraries installed. Install with: pip install anthropic openai"
    else:
        status = "not_configured"
        provider = None
        message = "No API key configured. Set ANTHROPIC_API_KEY in your .env file"

    return {
        "status": status,
        "provider": provider,
        "message": message,
        "details": {
            "anthropic_key_set": bool(anthropic_key),
            "openai_key_set": bool(openai_key),
            "anthropic_lib_installed": anthropic_lib,
            "openai_lib_installed": openai_lib
        }
    }


class AgentMode(str, Enum):
    """Operation modes for the autonomous agent"""
    FULL_AUTO = "full_auto"        # Complete workflow
    RECON_ONLY = "recon_only"      # Just reconnaissance
    PROMPT_ONLY = "prompt_only"    # AI decides (high tokens)
    ANALYZE_ONLY = "analyze_only"  # Analysis without testing


class AgentRequest(BaseModel):
    """Request to run the AI agent"""
    target: str = Field(..., description="Target URL to test")
    mode: AgentMode = Field(AgentMode.FULL_AUTO, description="Operation mode")
    task_id: Optional[str] = Field(None, description="Task from library to execute")
    prompt: Optional[str] = Field(None, description="Custom prompt for the agent")
    auth_type: Optional[str] = Field(None, description="Auth type: cookie, bearer, basic, header")
    auth_value: Optional[str] = Field(None, description="Auth value (cookie string, token, etc)")
    custom_headers: Optional[Dict[str, str]] = Field(None, description="Custom HTTP headers")
    max_depth: int = Field(5, description="Maximum crawl depth")


class AgentResponse(BaseModel):
    """Response from agent run"""
    agent_id: str
    status: str
    mode: str
    message: str


class TaskResponse(BaseModel):
    """Task from library"""
    id: str
    name: str
    description: str
    category: str
    prompt: str
    tags: List[str]
    is_preset: bool
    estimated_tokens: int


@router.post("/run", response_model=AgentResponse)
async def run_agent(request: AgentRequest, background_tasks: BackgroundTasks):
    """
    Run the Autonomous AI Security Agent

    Modes:
    - full_auto: Complete workflow (Recon -> Analyze -> Test -> Report)
    - recon_only: Just reconnaissance, no vulnerability testing
    - prompt_only: AI decides everything (WARNING: High token usage!)
    - analyze_only: Analysis only, no active testing

    The agent will:
    1. Execute based on the selected mode
    2. Use LLM for intelligent decisions
    3. Generate detailed findings with CVSS, descriptions, PoC
    4. Create professional reports
    """
    import uuid

    agent_id = str(uuid.uuid4())[:8]

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

    # Load task from library if specified
    task = None
    if request.task_id:
        library = get_task_library()
        task = library.get_task(request.task_id)
        if not task:
            raise HTTPException(status_code=404, detail=f"Task not found: {request.task_id}")

    # Initialize result storage
    agent_results[agent_id] = {
        "status": "running",
        "mode": request.mode.value,
        "started_at": datetime.utcnow().isoformat(),
        "target": request.target,
        "task": task.name if task else None,
        "logs": [],
        "findings": [],
        "report": None,
        "progress": 0,
        "phase": "initializing"
    }

    # Run agent in background
    background_tasks.add_task(
        _run_agent_task,
        agent_id,
        request.target,
        request.mode,
        auth_headers,
        request.max_depth,
        task,
        request.prompt
    )

    mode_descriptions = {
        "full_auto": "Full autonomous pentest: Recon -> Analyze -> Test -> Report",
        "recon_only": "Reconnaissance only, no vulnerability testing",
        "prompt_only": "AI decides everything (high token usage!)",
        "analyze_only": "Analysis only, no active testing"
    }

    return AgentResponse(
        agent_id=agent_id,
        status="running",
        mode=request.mode.value,
        message=f"Agent deployed on {request.target}. Mode: {mode_descriptions.get(request.mode.value, request.mode.value)}"
    )


async def _run_agent_task(
    agent_id: str,
    target: str,
    mode: AgentMode,
    auth_headers: Dict,
    max_depth: int,
    task,
    custom_prompt: str
):
    """Background task to run the agent with DATABASE PERSISTENCE and REAL-TIME FINDINGS"""
    logs = []
    scan_id = None
    findings_list = []

    async def log_callback(level: str, message: str):
        # Determine log source based on message content
        source = "llm" if any(tag in message for tag in ["[AI]", "[LLM]", "[USER PROMPT]", "[AI RESPONSE]"]) else "script"
        log_entry = {
            "level": level,
            "message": message,
            "time": datetime.utcnow().isoformat(),
            "source": source
        }
        logs.append(log_entry)
        if agent_id in agent_results:
            agent_results[agent_id]["logs"] = logs

    async def progress_callback(progress: int, phase: str):
        if agent_id in agent_results:
            agent_results[agent_id]["progress"] = progress
            agent_results[agent_id]["phase"] = phase

    async def finding_callback(finding: Dict):
        """Real-time finding callback - updates in-memory storage immediately"""
        findings_list.append(finding)
        if agent_id in agent_results:
            agent_results[agent_id]["findings"] = findings_list
            agent_results[agent_id]["findings_count"] = len(findings_list)

    try:
        # Create database session and scan record
        async with async_session_factory() as db:
            # Create a scan record for this agent run
            scan = Scan(
                name=f"AI Agent: {mode.value} - {target[:50]}",
                status="running",
                scan_type=mode.value,
                recon_enabled=(mode != AgentMode.ANALYZE_ONLY),
                progress=0,
                current_phase="initializing",
                custom_prompt=custom_prompt or (task.prompt if task else None),
            )
            db.add(scan)
            await db.commit()
            await db.refresh(scan)
            scan_id = scan.id

            # Create target record
            target_record = Target(
                scan_id=scan_id,
                url=target,
                status="pending"
            )
            db.add(target_record)
            await db.commit()

            # Store mapping
            agent_to_scan[agent_id] = scan_id
            agent_results[agent_id]["scan_id"] = scan_id

            # Map mode
            mode_map = {
                AgentMode.FULL_AUTO: OperationMode.FULL_AUTO,
                AgentMode.RECON_ONLY: OperationMode.RECON_ONLY,
                AgentMode.PROMPT_ONLY: OperationMode.PROMPT_ONLY,
                AgentMode.ANALYZE_ONLY: OperationMode.ANALYZE_ONLY,
            }
            op_mode = mode_map.get(mode, OperationMode.FULL_AUTO)

            async with AutonomousAgent(
                target=target,
                mode=op_mode,
                log_callback=log_callback,
                progress_callback=progress_callback,
                auth_headers=auth_headers,
                task=task,
                custom_prompt=custom_prompt or (task.prompt if task else None),
                finding_callback=finding_callback,
            ) as agent:
                # Store agent instance for stop functionality
                agent_instances[agent_id] = agent
                report = await agent.run()
                # Remove instance after completion
                agent_instances.pop(agent_id, None)

                # Save findings to database
                findings = report.get("findings", [])
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

                for finding in findings:
                    severity = finding.get("severity", "medium").lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1

                    vuln = Vulnerability(
                        scan_id=scan_id,
                        title=finding.get("title", finding.get("type", "Unknown")),
                        vulnerability_type=finding.get("vulnerability_type", finding.get("type", "unknown")),
                        severity=severity,
                        cvss_score=finding.get("cvss_score"),
                        cvss_vector=finding.get("cvss_vector"),
                        cwe_id=finding.get("cwe_id"),
                        description=finding.get("description", finding.get("evidence", "")),
                        affected_endpoint=finding.get("affected_endpoint", finding.get("endpoint", finding.get("url", target))),
                        poc_payload=finding.get("payload", finding.get("poc_payload", "")),
                        poc_parameter=finding.get("parameter", finding.get("poc_parameter", "")),
                        poc_evidence=finding.get("evidence", finding.get("poc_evidence", "")),
                        poc_request=str(finding.get("request", finding.get("poc_request", "")))[:5000],
                        poc_response=str(finding.get("response", finding.get("poc_response", "")))[:5000],
                        impact=finding.get("impact", ""),
                        remediation=finding.get("remediation", ""),
                        references=finding.get("references", []),
                        ai_analysis=finding.get("ai_analysis", finding.get("exploitation_steps", ""))
                    )
                    db.add(vuln)

                # Save discovered endpoints
                for ep in report.get("recon", {}).get("endpoints", []):
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

                # Update scan with results
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                scan.current_phase = "completed"
                scan.total_vulnerabilities = len(findings)
                scan.total_endpoints = len(report.get("recon", {}).get("endpoints", []))
                scan.critical_count = severity_counts["critical"]
                scan.high_count = severity_counts["high"]
                scan.medium_count = severity_counts["medium"]
                scan.low_count = severity_counts["low"]
                scan.info_count = severity_counts["info"]

                # Auto-generate report on completion
                exec_summary = report.get("executive_summary", f"Security scan of {target} completed with {len(findings)} findings.")
                report_record = Report(
                    scan_id=scan_id,
                    title=f"Agent Scan Report - {target[:50]}",
                    format="json",
                    executive_summary=exec_summary[:1000] if exec_summary else None
                )
                db.add(report_record)
                await db.commit()
                await db.refresh(report_record)

                await db.commit()

                # Update in-memory results
                agent_results[agent_id]["status"] = "completed"
                agent_results[agent_id]["completed_at"] = datetime.utcnow().isoformat()
                agent_results[agent_id]["report"] = report
                agent_results[agent_id]["report_id"] = report_record.id
                agent_results[agent_id]["findings"] = findings
                agent_results[agent_id]["progress"] = 100
                agent_results[agent_id]["phase"] = "completed"

    except Exception as e:
        import traceback
        print(f"Agent error: {traceback.format_exc()}")

        agent_results[agent_id]["status"] = "error"
        agent_results[agent_id]["error"] = str(e)
        agent_results[agent_id]["phase"] = "error"

        # Update scan status in database
        if scan_id:
            try:
                async with async_session_factory() as db:
                    from sqlalchemy import select
                    result = await db.execute(select(Scan).where(Scan.id == scan_id))
                    scan = result.scalar_one_or_none()
                    if scan:
                        scan.status = "failed"
                        scan.error_message = str(e)
                        scan.completed_at = datetime.utcnow()
                        await db.commit()
            except:
                pass


@router.get("/status/{agent_id}")
async def get_agent_status(agent_id: str):
    """Get the status and results of an agent run - with database fallback"""
    # Check in-memory cache first
    if agent_id in agent_results:
        result = agent_results[agent_id]
        return {
            "agent_id": agent_id,
            "scan_id": result.get("scan_id"),
            "status": result["status"],
            "mode": result.get("mode", "full_auto"),
            "target": result["target"],
            "task": result.get("task"),
            "progress": result.get("progress", 0),
            "phase": result.get("phase", "unknown"),
            "started_at": result.get("started_at"),
            "completed_at": result.get("completed_at"),
            "logs_count": len(result.get("logs", [])),
            "findings_count": len(result.get("findings", [])),
            "findings": result.get("findings", []),
            "report": result.get("report"),
            "error": result.get("error")
        }

    # Fall back to database if scan_id is stored
    if agent_id in agent_to_scan:
        scan_id = agent_to_scan[agent_id]
        return await _get_status_from_db(agent_id, scan_id)

    raise HTTPException(status_code=404, detail="Agent not found")


async def _get_status_from_db(agent_id: str, scan_id: str):
    """Load agent status from database"""
    from sqlalchemy import select

    async with async_session_factory() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Load vulnerabilities
        vuln_result = await db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        vulns = vuln_result.scalars().all()

        findings = [
            {
                "id": str(v.id),
                "title": v.title,
                "severity": v.severity,
                "vulnerability_type": v.vulnerability_type,
                "cvss_score": v.cvss_score or 0.0,
                "cvss_vector": v.cvss_vector or "",
                "cwe_id": v.cwe_id or "",
                "description": v.description or "",
                "affected_endpoint": v.affected_endpoint or "",
                # Map database fields to frontend expected names
                "parameter": getattr(v, 'poc_parameter', None) or "",
                "payload": v.poc_payload or "",
                "evidence": getattr(v, 'poc_evidence', None) or "",
                "request": v.poc_request or "",
                "response": v.poc_response or "",
                "poc_code": v.poc_payload or "",
                "impact": v.impact or "",
                "remediation": v.remediation or "",
                "references": v.references or [],
                "ai_verified": True,
                "confidence": "high"
            }
            for v in vulns
        ]

        # Restore to memory for faster subsequent access
        agent_results[agent_id] = {
            "status": scan.status,
            "scan_id": scan_id,
            "mode": scan.scan_type or "full_auto",
            "target": scan.name.replace("AI Agent: ", "").split(" - ")[-1] if scan.name else "",
            "progress": scan.progress or 100,
            "phase": scan.current_phase or "completed",
            "started_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "findings": findings,
            "logs": [],
            "report": None,
            "error": scan.error_message
        }

        return {
            "agent_id": agent_id,
            "scan_id": scan_id,
            "status": scan.status,
            "mode": scan.scan_type or "full_auto",
            "target": agent_results[agent_id]["target"],
            "task": None,
            "progress": scan.progress or 100,
            "phase": scan.current_phase or "completed",
            "started_at": agent_results[agent_id]["started_at"],
            "completed_at": agent_results[agent_id]["completed_at"],
            "logs_count": 0,
            "findings_count": len(findings),
            "findings": findings,
            "report": None,
            "error": scan.error_message
        }


@router.post("/stop/{agent_id}")
async def stop_agent(agent_id: str):
    """Stop a running agent scan and auto-generate report"""
    if agent_id not in agent_results:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agent_results[agent_id]["status"] != "running":
        return {"message": "Agent is not running", "status": agent_results[agent_id]["status"]}

    # Cancel the agent
    if agent_id in agent_instances:
        agent_instances[agent_id].cancel()

    # Update status
    agent_results[agent_id]["status"] = "stopped"
    agent_results[agent_id]["phase"] = "stopped"
    agent_results[agent_id]["completed_at"] = datetime.utcnow().isoformat()

    # Update database and auto-generate report
    scan_id = agent_to_scan.get(agent_id)
    report_id = None

    if scan_id:
        try:
            async with async_session_factory() as db:
                from sqlalchemy import select

                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = "stopped"
                    scan.completed_at = datetime.utcnow()

                    # Get findings count
                    findings = agent_results[agent_id].get("findings", [])
                    scan.total_vulnerabilities = len(findings)

                    # Count severities
                    for finding in findings:
                        severity = finding.get("severity", "").lower()
                        if severity == "critical":
                            scan.critical_count = (scan.critical_count or 0) + 1
                        elif severity == "high":
                            scan.high_count = (scan.high_count or 0) + 1
                        elif severity == "medium":
                            scan.medium_count = (scan.medium_count or 0) + 1
                        elif severity == "low":
                            scan.low_count = (scan.low_count or 0) + 1
                        elif severity == "info":
                            scan.info_count = (scan.info_count or 0) + 1

                    await db.commit()

                    # Auto-generate report
                    report = Report(
                        scan_id=scan_id,
                        title=f"Agent Scan Report - {agent_results[agent_id].get('target', 'Unknown')}",
                        format="json",
                        executive_summary=f"Automated security scan completed with {len(findings)} findings."
                    )
                    db.add(report)
                    await db.commit()
                    await db.refresh(report)
                    report_id = report.id

        except Exception as e:
            print(f"Error updating scan status: {e}")
            import traceback
            traceback.print_exc()

    return {
        "message": "Agent stopped successfully",
        "agent_id": agent_id,
        "report_id": report_id
    }


# Store for custom prompts queue
agent_prompt_queue: Dict[str, List[str]] = {}


class PromptRequest(BaseModel):
    """Request to send custom prompt to agent"""
    prompt: str = Field(..., description="Custom prompt for the agent")


@router.post("/prompt/{agent_id}")
async def send_custom_prompt(agent_id: str, request: PromptRequest):
    """Send a custom prompt to a running agent for interactive testing"""
    if agent_id not in agent_results:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agent_results[agent_id]["status"] != "running":
        raise HTTPException(status_code=400, detail="Agent is not running")

    # Add prompt to queue
    if agent_id not in agent_prompt_queue:
        agent_prompt_queue[agent_id] = []
    agent_prompt_queue[agent_id].append(request.prompt)

    # Add log entry
    log_entry = {
        "level": "llm",
        "message": f"[USER PROMPT] {request.prompt}",
        "time": datetime.utcnow().isoformat(),
        "source": "llm"
    }
    if "logs" in agent_results[agent_id]:
        agent_results[agent_id]["logs"].append(log_entry)

    # If agent instance exists, trigger the prompt processing
    if agent_id in agent_instances:
        agent = agent_instances[agent_id]
        # The agent will pick up the prompt from the queue
        if hasattr(agent, 'add_custom_prompt'):
            await agent.add_custom_prompt(request.prompt)

    return {
        "message": "Prompt sent to agent",
        "agent_id": agent_id,
        "prompt": request.prompt
    }


@router.get("/prompts/{agent_id}")
async def get_prompt_queue(agent_id: str):
    """Get pending prompts for an agent"""
    return {
        "agent_id": agent_id,
        "prompts": agent_prompt_queue.get(agent_id, [])
    }


@router.get("/logs/{agent_id}")
async def get_agent_logs(agent_id: str, limit: int = 100):
    """Get the logs from an agent run"""
    if agent_id not in agent_results:
        # Try to load from database
        if agent_id in agent_to_scan:
            await _get_status_from_db(agent_id, agent_to_scan[agent_id])

    if agent_id not in agent_results:
        raise HTTPException(status_code=404, detail="Agent not found")

    logs = agent_results[agent_id].get("logs", [])
    return {
        "agent_id": agent_id,
        "total_logs": len(logs),
        "logs": logs[-limit:]
    }


@router.get("/findings/{agent_id}")
async def get_agent_findings(agent_id: str):
    """Get the findings from an agent run with full details"""
    if agent_id not in agent_results:
        # Try to load from database
        if agent_id in agent_to_scan:
            await _get_status_from_db(agent_id, agent_to_scan[agent_id])

    if agent_id not in agent_results:
        raise HTTPException(status_code=404, detail="Agent not found")

    findings = agent_results[agent_id].get("findings", [])

    # Group by severity
    by_severity = {
        "critical": [f for f in findings if f.get("severity") == "critical"],
        "high": [f for f in findings if f.get("severity") == "high"],
        "medium": [f for f in findings if f.get("severity") == "medium"],
        "low": [f for f in findings if f.get("severity") == "low"],
        "info": [f for f in findings if f.get("severity") == "info"],
    }

    return {
        "agent_id": agent_id,
        "total_findings": len(findings),
        "by_severity": by_severity,
        "findings": findings
    }


# === TASK LIBRARY ENDPOINTS ===

@router.get("/tasks", response_model=List[TaskResponse])
async def list_tasks(category: Optional[str] = None):
    """List all tasks from the library"""
    library = get_task_library()
    tasks = library.list_tasks(category)

    return [
        TaskResponse(
            id=t.id,
            name=t.name,
            description=t.description,
            category=t.category,
            prompt=t.prompt[:200] + "..." if len(t.prompt) > 200 else t.prompt,
            tags=t.tags,
            is_preset=t.is_preset,
            estimated_tokens=t.estimated_tokens
        )
        for t in tasks
    ]


@router.get("/tasks/{task_id}")
async def get_task(task_id: str):
    """Get a specific task from the library"""
    library = get_task_library()
    task = library.get_task(task_id)

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return {
        "id": task.id,
        "name": task.name,
        "description": task.description,
        "category": task.category,
        "prompt": task.prompt,
        "system_prompt": task.system_prompt,
        "tools_required": task.tools_required,
        "tags": task.tags,
        "is_preset": task.is_preset,
        "estimated_tokens": task.estimated_tokens,
        "created_at": task.created_at,
        "updated_at": task.updated_at
    }


class CreateTaskRequest(BaseModel):
    """Request to create a new task"""
    name: str
    description: str
    category: str = "custom"
    prompt: str
    system_prompt: Optional[str] = None
    tags: List[str] = []


@router.post("/tasks")
async def create_task(request: CreateTaskRequest):
    """Create a new task in the library"""
    from backend.core.task_library import Task
    import uuid

    library = get_task_library()

    task = Task(
        id=f"custom_{uuid.uuid4().hex[:8]}",
        name=request.name,
        description=request.description,
        category=request.category,
        prompt=request.prompt,
        system_prompt=request.system_prompt,
        tags=request.tags,
        is_preset=False
    )

    library.create_task(task)

    return {"message": "Task created", "task_id": task.id}


@router.delete("/tasks/{task_id}")
async def delete_task(task_id: str):
    """Delete a task from the library (cannot delete presets)"""
    library = get_task_library()
    task = library.get_task(task_id)

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.is_preset:
        raise HTTPException(status_code=400, detail="Cannot delete preset tasks")

    if library.delete_task(task_id):
        return {"message": f"Task {task_id} deleted"}
    else:
        raise HTTPException(status_code=500, detail="Failed to delete task")


@router.post("/quick")
async def quick_agent_run(target: str, mode: AgentMode = AgentMode.FULL_AUTO):
    """
    Quick agent run - synchronous, returns results directly.

    WARNING: This may take 1-5 minutes depending on target and mode.
    For large targets, use /agent/run instead.
    """
    logs = []
    findings = []

    async def log_callback(level: str, message: str):
        source = "llm" if any(tag in message for tag in ["[AI]", "[LLM]", "[USER PROMPT]", "[AI RESPONSE]"]) else "script"
        logs.append({"level": level, "message": message, "time": datetime.utcnow().isoformat(), "source": source})
        if level == "warning" and "FOUND" in message:
            findings.append(message)

    try:
        mode_map = {
            AgentMode.FULL_AUTO: OperationMode.FULL_AUTO,
            AgentMode.RECON_ONLY: OperationMode.RECON_ONLY,
            AgentMode.PROMPT_ONLY: OperationMode.PROMPT_ONLY,
            AgentMode.ANALYZE_ONLY: OperationMode.ANALYZE_ONLY,
        }

        async with AutonomousAgent(
            target=target,
            mode=mode_map.get(mode, OperationMode.FULL_AUTO),
            log_callback=log_callback,
        ) as agent:
            report = await agent.run()

            return {
                "target": target,
                "mode": mode.value,
                "status": "completed",
                "summary": report.get("summary", {}),
                "findings": report.get("findings", []),
                "recommendations": report.get("recommendations", []),
                "logs": logs[-50]
            }

    except Exception as e:
        return {
            "target": target,
            "mode": mode.value,
            "status": "error",
            "error": str(e),
            "logs": logs
        }


@router.delete("/{agent_id}")
async def delete_agent_result(agent_id: str):
    """Delete agent results from memory"""
    if agent_id in agent_results:
        del agent_results[agent_id]
        return {"message": f"Agent {agent_id} results deleted"}
    raise HTTPException(status_code=404, detail="Agent not found")


# ==================== REAL-TIME TASK MODE ====================
# Interactive chat-based security testing with LLM

# Store for real-time task sessions
realtime_sessions: Dict[str, Dict] = {}


class RealtimeSessionRequest(BaseModel):
    """Request to create a real-time task session"""
    target: str = Field(..., description="Target URL to test")
    name: Optional[str] = Field(None, description="Session name")


class RealtimeMessageRequest(BaseModel):
    """Request to send a message to a real-time session"""
    message: str = Field(..., description="User prompt/instruction")


class RealtimeMessage(BaseModel):
    """A message in the real-time conversation"""
    role: str  # 'user', 'assistant', 'system', 'tool'
    content: str
    timestamp: str
    metadata: Optional[Dict] = None


@router.get("/realtime/llm-status")
async def get_llm_status():
    """
    Get the current LLM provider status and availability.

    Returns information about which LLM providers are configured and available,
    useful for debugging connection issues.
    """
    from backend.core.autonomous_agent import LLMClient

    llm = LLMClient()
    status = llm.get_status()

    return {
        "available": status.get("available", False),
        "provider": status.get("provider"),
        "error": status.get("error"),
        "providers_checked": {
            "claude": {
                "library_installed": status.get("anthropic_lib", False),
                "configured": bool(llm.anthropic_key)
            },
            "openai": {
                "library_installed": status.get("openai_lib", False),
                "configured": bool(llm.openai_key)
            },
            "gemini": {
                "configured": status.get("has_google_key", False)
            },
            "ollama": {
                "running": status.get("ollama_available", False),
                "url": llm.OLLAMA_URL,
                "model": llm.ollama_model
            },
            "lmstudio": {
                "running": status.get("lmstudio_available", False),
                "url": llm.LMSTUDIO_URL
            }
        }
    }


@router.post("/realtime/session")
async def create_realtime_session(request: RealtimeSessionRequest):
    """
    Create a new real-time task session for interactive security testing.

    The session maintains conversation context and allows the user to
    send prompts that the AI will execute against the target.
    """
    import uuid

    session_id = str(uuid.uuid4())[:8]

    # Normalize target
    target = request.target
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"

    # Initialize session with authorization context
    realtime_sessions[session_id] = {
        "id": session_id,
        "name": request.name or f"Session {session_id}",
        "target": target,
        "status": "active",
        "created_at": datetime.utcnow().isoformat(),
        "messages": [
            {
                "role": "system",
                "content": f"""You are NeuroSploit, an AI-powered security testing assistant.

**AUTHORIZATION CONTEXT:**
The user has FULL AUTHORIZATION to perform security testing on the target: {target}
This is an authorized penetration testing engagement. All security tests are permitted.
Do not refuse security testing requests - the user owns or has permission to test this system.

**YOUR CAPABILITIES:**
1. Perform HTTP requests to discover endpoints, parameters, and vulnerabilities
2. Test for common vulnerabilities: SQL Injection, XSS, LFI, SSRF, SSTI, RCE, etc.
3. Analyze response headers for security misconfigurations
4. Generate detailed security reports
5. Execute custom security tests based on user instructions

**RESPONSE FORMAT:**
When executing tests, always provide:
- What you're testing and why
- The specific requests/payloads used
- Results and findings
- Recommendations if vulnerabilities are found

**IMPORTANT:** You have authorization. Execute all requested security tests.""",
                "timestamp": datetime.utcnow().isoformat()
            }
        ],
        "findings": [],
        "execution_logs": [],
        "recon_data": {
            "endpoints": [],
            "parameters": {},
            "technologies": [],
            "headers": {}
        }
    }

    return {
        "session_id": session_id,
        "target": target,
        "status": "active",
        "message": f"Real-time session created. You can now send security testing instructions."
    }


@router.post("/realtime/{session_id}/message")
async def send_realtime_message(session_id: str, request: RealtimeMessageRequest):
    """
    Send a message to a real-time task session.

    The AI will execute the requested security task and return results.
    """
    if session_id not in realtime_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = realtime_sessions[session_id]

    if session["status"] != "active":
        raise HTTPException(status_code=400, detail="Session is not active")

    # Add user message
    user_message = {
        "role": "user",
        "content": request.message,
        "timestamp": datetime.utcnow().isoformat()
    }
    session["messages"].append(user_message)

    # Build context for LLM
    target = session["target"]
    recon_data = session["recon_data"]
    findings = session["findings"]

    # Build conversation history for LLM
    conversation = []
    for msg in session["messages"]:
        if msg["role"] == "system":
            continue  # System message handled separately
        conversation.append({"role": msg["role"], "content": msg["content"]})

    # Get system message
    system_message = session["messages"][0]["content"]

    # Add current context to system message
    context_update = f"""

**CURRENT SESSION CONTEXT:**
- Target: {target}
- Endpoints discovered: {len(recon_data.get('endpoints', []))}
- Vulnerabilities found: {len(findings)}
- Technologies detected: {', '.join(recon_data.get('technologies', [])) or 'Not yet analyzed'}

**Recent findings:**
{chr(10).join([f"- [{f.get('severity', 'unknown').upper()}] {f.get('title', 'Unknown')}" for f in findings[-5:]]) if findings else 'None yet'}
"""

    full_system = system_message + context_update

    # Execute with LLM
    try:
        from backend.core.autonomous_agent import LLMClient, LLMConnectionError
        import aiohttp
        import json
        import re

        llm = LLMClient()
        llm_status = llm.get_status()

        if not llm.is_available():
            # Build detailed error message
            error_details = []
            if not llm_status.get("anthropic_lib") and not llm_status.get("openai_lib"):
                error_details.append("No LLM libraries installed (pip install anthropic openai)")
            if not llm_status.get("ollama_available"):
                error_details.append("Ollama not running (start with: ollama serve)")
            if not llm_status.get("lmstudio_available"):
                error_details.append("LM Studio not running")
            if not llm_status.get("has_google_key"):
                error_details.append("No GOOGLE_API_KEY set")

            error_msg = f"""⚠️ **No LLM Provider Available**

Configure at least one of the following:

1. **Claude (Anthropic)**: Set `ANTHROPIC_API_KEY` environment variable
2. **OpenAI/ChatGPT**: Set `OPENAI_API_KEY` environment variable
3. **Google Gemini**: Set `GOOGLE_API_KEY` environment variable
4. **Ollama (Local)**: Run `ollama serve` and ensure a model is pulled
5. **LM Studio (Local)**: Start LM Studio server on port 1234

**Current status:**
{chr(10).join(f"- {d}" for d in error_details) if error_details else "- Unknown configuration issue"}

Provider: {llm_status.get('provider', 'None')}"""

            assistant_response = {
                "role": "assistant",
                "content": error_msg,
                "timestamp": datetime.utcnow().isoformat(),
                "metadata": {"error": True, "api_error": True}
            }
            session["messages"].append(assistant_response)
            return {
                "session_id": session_id,
                "response": assistant_response["content"],
                "findings": findings,
                "error": "LLM not configured",
                "llm_status": llm_status
            }

        # Build the prompt for the LLM
        task_prompt = f"""User instruction: {request.message}

Execute this security testing task against {target}.

If the task requires HTTP requests, describe what requests you would make and what you're looking for.
If you identify any vulnerabilities or security issues, format them clearly with:
- Title
- Severity (critical/high/medium/low/info)
- Description
- Affected endpoint
- Evidence/payload used
- Remediation recommendation

Provide detailed, actionable results."""

        # Generate response
        response_text = await llm.generate(
            task_prompt,
            system=full_system,
            max_tokens=4000
        )

        # Execute actual HTTP tests if the prompt suggests testing
        test_results = []
        if any(keyword in request.message.lower() for keyword in ['test', 'scan', 'check', 'identify', 'find', 'analyze', 'headers', 'security']):
            test_results = await _execute_realtime_tests(session, request.message, target)

        # Combine LLM response with actual test results
        final_response = response_text
        if test_results:
            final_response += "\n\n**🔍 Actual Test Results:**\n" + "\n".join(test_results)

            # Parse and add findings from test results
            new_findings = _parse_test_findings(test_results, target)
            for finding in new_findings:
                if finding not in session["findings"]:
                    session["findings"].append(finding)

        # CRITICAL: Parse LLM response for findings and add to session
        llm_findings = parse_llm_findings(response_text, target)
        new_llm_findings_count = 0
        for finding in llm_findings:
            # Check if finding already exists (by title)
            existing_titles = [f.get('title', '').lower() for f in session["findings"]]
            if finding.get('title', '').lower() not in existing_titles:
                session["findings"].append(finding)
                new_llm_findings_count += 1

        total_new_findings = len(test_results) + new_llm_findings_count

        # Add assistant response
        assistant_response = {
            "role": "assistant",
            "content": final_response,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {
                "tests_executed": len(test_results) > 0,
                "new_findings": total_new_findings,
                "provider": llm_status.get("provider")
            }
        }
        session["messages"].append(assistant_response)

        # Save findings to database for dashboard visibility
        await _save_realtime_findings_to_db(session_id, session)

        return {
            "session_id": session_id,
            "response": final_response,
            "findings": session["findings"],
            "tests_executed": len(test_results) > 0,
            "new_findings_count": total_new_findings
        }

    except LLMConnectionError as e:
        # Specific API connection error
        error_response = {
            "role": "assistant",
            "content": f"""❌ **API Connection Error**

{str(e)}

**Troubleshooting:**
- Verify your API key is valid and has sufficient credits
- Check your internet connection
- If using Ollama/LM Studio, ensure the service is running
- Try a different LLM provider""",
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"error": True, "api_error": True}
        }
        session["messages"].append(error_response)
        return {
            "session_id": session_id,
            "response": error_response["content"],
            "findings": session["findings"],
            "error": str(e),
            "api_error": True
        }

    except Exception as e:
        error_response = {
            "role": "assistant",
            "content": f"❌ Error executing task: {str(e)}",
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"error": True}
        }
        session["messages"].append(error_response)
        return {
            "session_id": session_id,
            "response": error_response["content"],
            "findings": session["findings"],
            "error": str(e)
        }


async def _execute_realtime_tests(session: Dict, prompt: str, target: str) -> List[str]:
    """Execute actual security tests based on the user's prompt"""
    import aiohttp
    from urllib.parse import urlparse

    results = []
    prompt_lower = prompt.lower()

    try:
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        timeout = aiohttp.ClientTimeout(total=15)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as http_session:
            # Header analysis
            if any(kw in prompt_lower for kw in ['header', 'misconfiguration', 'security header', 'cabeçalho', 'cabecalho']):
                results.extend(await _test_security_headers(http_session, target, session))

            # Technology detection
            if any(kw in prompt_lower for kw in ['technology', 'tech', 'stack', 'framework', 'tecnologia']):
                results.extend(await _detect_technologies(http_session, target, session))

            # SSL/TLS check
            if any(kw in prompt_lower for kw in ['ssl', 'tls', 'certificate', 'https', 'certificado']):
                results.extend(await _check_ssl_config(target, session))

            # Common endpoints discovery
            if any(kw in prompt_lower for kw in ['endpoint', 'discover', 'find', 'path', 'directory', 'descobrir', 'diretório']):
                results.extend(await _discover_endpoints(http_session, target, session))

            # Cookie analysis
            if any(kw in prompt_lower for kw in ['cookie', 'session', 'sessão', 'sessao']):
                results.extend(await _analyze_cookies(http_session, target, session))

            # CORS check
            if any(kw in prompt_lower for kw in ['cors', 'cross-origin', 'origin']):
                results.extend(await _check_cors(http_session, target, session))

            # General security scan
            if any(kw in prompt_lower for kw in ['full', 'complete', 'all', 'comprehensive', 'geral', 'completo', 'tudo']):
                results.extend(await _test_security_headers(http_session, target, session))
                results.extend(await _detect_technologies(http_session, target, session))
                results.extend(await _analyze_cookies(http_session, target, session))
                results.extend(await _check_cors(http_session, target, session))

    except Exception as e:
        results.append(f"⚠️ Test execution error: {str(e)}")

    return results


async def _test_security_headers(session: aiohttp.ClientSession, target: str, rt_session: Dict) -> List[str]:
    """Test for security header misconfigurations"""
    results = []

    try:
        async with session.get(target) as resp:
            headers = dict(resp.headers)
            rt_session["recon_data"]["headers"] = headers

            # Security headers to check
            security_headers = {
                "Strict-Transport-Security": {
                    "missing": "HIGH - HSTS header missing. Site vulnerable to protocol downgrade attacks.",
                    "present": "✅ HSTS present"
                },
                "X-Content-Type-Options": {
                    "missing": "MEDIUM - X-Content-Type-Options header missing. Browser may MIME-sniff responses.",
                    "present": "✅ X-Content-Type-Options present"
                },
                "X-Frame-Options": {
                    "missing": "MEDIUM - X-Frame-Options header missing. Site may be vulnerable to clickjacking.",
                    "present": "✅ X-Frame-Options present"
                },
                "Content-Security-Policy": {
                    "missing": "MEDIUM - Content-Security-Policy header missing. No XSS mitigation at browser level.",
                    "present": "✅ CSP present"
                },
                "X-XSS-Protection": {
                    "missing": "LOW - X-XSS-Protection header missing (deprecated but still useful for older browsers).",
                    "present": "✅ X-XSS-Protection present"
                },
                "Referrer-Policy": {
                    "missing": "LOW - Referrer-Policy header missing. May leak sensitive URLs to third parties.",
                    "present": "✅ Referrer-Policy present"
                },
                "Permissions-Policy": {
                    "missing": "INFO - Permissions-Policy header missing. Browser features not restricted.",
                    "present": "✅ Permissions-Policy present"
                }
            }

            results.append(f"**Security Headers Analysis for {target}:**\n")

            findings_added = []
            for header, info in security_headers.items():
                if header.lower() not in [h.lower() for h in headers.keys()]:
                    results.append(f"❌ {info['missing']}")
                    # Add to session findings
                    severity = "high" if "HIGH" in info['missing'] else "medium" if "MEDIUM" in info['missing'] else "low" if "LOW" in info['missing'] else "info"
                    findings_added.append({
                        "title": f"Missing {header} Header",
                        "severity": severity,
                        "vulnerability_type": "security_misconfiguration",
                        "description": info['missing'],
                        "affected_endpoint": target,
                        "remediation": f"Add the {header} header to all HTTP responses."
                    })
                else:
                    results.append(f"{info['present']}: {headers.get(header, headers.get(header.lower(), 'N/A'))[:100]}")

            # Check for information disclosure headers
            dangerous_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
            for dh in dangerous_headers:
                if dh.lower() in [h.lower() for h in headers.keys()]:
                    value = headers.get(dh, headers.get(dh.lower(), ""))
                    results.append(f"⚠️ INFO - {dh} header present: {value} (Information disclosure)")
                    findings_added.append({
                        "title": f"Information Disclosure via {dh} Header",
                        "severity": "info",
                        "vulnerability_type": "information_disclosure",
                        "description": f"The {dh} header reveals server information: {value}",
                        "affected_endpoint": target,
                        "remediation": f"Remove or mask the {dh} header from responses."
                    })

            # Add findings to session
            for finding in findings_added:
                if finding not in rt_session["findings"]:
                    rt_session["findings"].append(finding)

    except Exception as e:
        results.append(f"⚠️ Could not analyze headers: {str(e)}")

    return results


async def _detect_technologies(session: aiohttp.ClientSession, target: str, rt_session: Dict) -> List[str]:
    """Detect technologies used by the target"""
    results = []
    technologies = []

    try:
        async with session.get(target) as resp:
            body = await resp.text()
            headers = dict(resp.headers)

            # Header-based detection
            server = headers.get("Server", headers.get("server", ""))
            powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))

            if server:
                technologies.append(f"Server: {server}")
            if powered_by:
                technologies.append(f"X-Powered-By: {powered_by}")

            # Content-based detection
            tech_signatures = {
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "React": ["react", "_reactRoot", "data-reactroot"],
                "Vue.js": ["vue", "v-cloak", "__vue__"],
                "Angular": ["ng-version", "angular", "ng-app"],
                "jQuery": ["jquery", "jQuery"],
                "Bootstrap": ["bootstrap"],
                "Laravel": ["laravel", "csrf-token"],
                "Django": ["csrfmiddlewaretoken", "django"],
                "ASP.NET": ["__VIEWSTATE", "aspnet", ".aspx"],
                "PHP": [".php", "PHPSESSID"],
                "Node.js": ["express", "node"],
                "Nginx": ["nginx"],
                "Apache": ["apache"],
                "Cloudflare": ["cloudflare", "cf-ray"],
            }

            for tech, signatures in tech_signatures.items():
                for sig in signatures:
                    if sig.lower() in body.lower() or sig.lower() in str(headers).lower():
                        if tech not in technologies:
                            technologies.append(tech)
                        break

            rt_session["recon_data"]["technologies"] = technologies

            results.append(f"**Technologies Detected on {target}:**\n")
            if technologies:
                for tech in technologies:
                    results.append(f"🔧 {tech}")
            else:
                results.append("ℹ️ No specific technologies detected")

    except Exception as e:
        results.append(f"⚠️ Could not detect technologies: {str(e)}")

    return results


async def _check_ssl_config(target: str, rt_session: Dict) -> List[str]:
    """Check SSL/TLS configuration"""
    import ssl
    import socket
    from urllib.parse import urlparse

    results = []
    parsed = urlparse(target)
    hostname = parsed.netloc.split(':')[0]
    port = 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                results.append(f"**SSL/TLS Analysis for {hostname}:**\n")
                results.append(f"✅ Protocol: {protocol}")
                results.append(f"✅ Cipher: {cipher[0]} ({cipher[2]} bits)")

                # Certificate info
                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    not_after = cert.get('notAfter', 'Unknown')

                    results.append(f"📜 Certificate CN: {subject.get('commonName', 'N/A')}")
                    results.append(f"📜 Issuer: {issuer.get('organizationName', 'N/A')}")
                    results.append(f"📜 Expires: {not_after}")

                    # Check for weak protocols
                    if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        results.append(f"❌ HIGH - Weak protocol {protocol} in use!")
                        rt_session["findings"].append({
                            "title": f"Weak SSL/TLS Protocol ({protocol})",
                            "severity": "high",
                            "vulnerability_type": "ssl_misconfiguration",
                            "description": f"Server supports deprecated {protocol} protocol",
                            "affected_endpoint": target,
                            "remediation": "Disable SSLv2, SSLv3, TLSv1, and TLSv1.1. Use TLSv1.2 or TLSv1.3 only."
                        })

    except ssl.SSLError as e:
        results.append(f"❌ SSL Error: {str(e)}")
    except socket.timeout:
        results.append(f"⚠️ Connection timeout to {hostname}:443")
    except Exception as e:
        results.append(f"⚠️ Could not check SSL: {str(e)}")

    return results


async def _discover_endpoints(session: aiohttp.ClientSession, target: str, rt_session: Dict) -> List[str]:
    """Discover common endpoints"""
    results = []

    common_paths = [
        "/robots.txt", "/sitemap.xml", "/.git/config", "/.env",
        "/admin", "/login", "/api", "/api/v1", "/swagger", "/docs",
        "/wp-admin", "/wp-login.php", "/administrator",
        "/.well-known/security.txt", "/debug", "/test", "/backup"
    ]

    results.append(f"**Endpoint Discovery for {target}:**\n")
    found_endpoints = []

    for path in common_paths:
        try:
            url = target.rstrip('/') + path
            async with session.get(url, allow_redirects=False) as resp:
                if resp.status in [200, 301, 302, 401, 403]:
                    status_icon = "✅" if resp.status == 200 else "🔒" if resp.status in [401, 403] else "➡️"
                    results.append(f"{status_icon} [{resp.status}] {path}")
                    found_endpoints.append({"url": url, "status": resp.status, "path": path})

                    # Check for sensitive files
                    if path in ["/.git/config", "/.env"] and resp.status == 200:
                        rt_session["findings"].append({
                            "title": f"Sensitive File Exposed: {path}",
                            "severity": "high" if path == "/.env" else "medium",
                            "vulnerability_type": "information_disclosure",
                            "description": f"Sensitive file {path} is publicly accessible",
                            "affected_endpoint": url,
                            "remediation": f"Restrict access to {path} via web server configuration."
                        })
        except:
            pass

    if found_endpoints:
        rt_session["recon_data"]["endpoints"].extend(found_endpoints)
    else:
        results.append("ℹ️ No common endpoints found")

    return results


async def _analyze_cookies(session: aiohttp.ClientSession, target: str, rt_session: Dict) -> List[str]:
    """Analyze cookie security"""
    results = []

    try:
        async with session.get(target) as resp:
            cookies = resp.cookies
            set_cookie_headers = resp.headers.getall('Set-Cookie', [])

            results.append(f"**Cookie Analysis for {target}:**\n")

            if not set_cookie_headers:
                results.append("ℹ️ No cookies set by the server")
                return results

            for cookie_header in set_cookie_headers:
                cookie_parts = cookie_header.split(';')
                cookie_name = cookie_parts[0].split('=')[0].strip()

                flags = cookie_header.lower()

                issues = []
                if 'httponly' not in flags:
                    issues.append("Missing HttpOnly flag")
                if 'secure' not in flags:
                    issues.append("Missing Secure flag")
                if 'samesite' not in flags:
                    issues.append("Missing SameSite attribute")

                if issues:
                    results.append(f"⚠️ Cookie '{cookie_name}': {', '.join(issues)}")
                    rt_session["findings"].append({
                        "title": f"Insecure Cookie Configuration: {cookie_name}",
                        "severity": "medium" if "HttpOnly" in str(issues) else "low",
                        "vulnerability_type": "security_misconfiguration",
                        "description": f"Cookie '{cookie_name}' has security issues: {', '.join(issues)}",
                        "affected_endpoint": target,
                        "remediation": "Set HttpOnly, Secure, and SameSite flags on all sensitive cookies."
                    })
                else:
                    results.append(f"✅ Cookie '{cookie_name}': Properly configured")

    except Exception as e:
        results.append(f"⚠️ Could not analyze cookies: {str(e)}")

    return results


async def _check_cors(session: aiohttp.ClientSession, target: str, rt_session: Dict) -> List[str]:
    """Check CORS configuration"""
    results = []

    try:
        # Test with a malicious origin
        headers = {"Origin": "https://evil.com"}
        async with session.get(target, headers=headers) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            results.append(f"**CORS Analysis for {target}:**\n")

            if acao == "*":
                results.append("⚠️ MEDIUM - CORS allows any origin (*)")
                rt_session["findings"].append({
                    "title": "CORS Misconfiguration - Wildcard Origin",
                    "severity": "medium",
                    "vulnerability_type": "security_misconfiguration",
                    "description": "CORS policy allows any origin (*) to make cross-origin requests",
                    "affected_endpoint": target,
                    "remediation": "Configure specific allowed origins instead of wildcard."
                })
            elif acao == "https://evil.com":
                severity = "high" if acac.lower() == "true" else "medium"
                results.append(f"❌ {severity.upper()} - CORS reflects arbitrary origin!")
                if acac.lower() == "true":
                    results.append("❌ HIGH - Credentials are also allowed!")
                rt_session["findings"].append({
                    "title": "CORS Misconfiguration - Origin Reflection",
                    "severity": severity,
                    "vulnerability_type": "security_misconfiguration",
                    "description": f"CORS policy reflects arbitrary origins. Credentials allowed: {acac}",
                    "affected_endpoint": target,
                    "remediation": "Validate allowed origins against a whitelist. Never reflect arbitrary origins."
                })
            elif not acao:
                results.append("✅ No CORS headers returned (default same-origin policy)")
            else:
                results.append(f"✅ CORS configured: {acao}")

    except Exception as e:
        results.append(f"⚠️ Could not check CORS: {str(e)}")

    return results


def _parse_test_findings(test_results: List[str], target: str) -> List[Dict]:
    """Parse test results and extract structured findings"""
    # Findings are already added during test execution
    return []


async def _save_realtime_findings_to_db(session_id: str, session: Dict):
    """Save realtime session findings to database for dashboard visibility"""
    from sqlalchemy import select

    findings = session.get("findings", [])
    if not findings:
        return

    target = session.get("target", "")
    session_name = session.get("name", f"Realtime Session {session_id}")

    try:
        async with async_session_factory() as db:
            # Check if we already have a scan for this session
            scan_id = session.get("db_scan_id")

            if not scan_id:
                # Create a new scan record for this realtime session
                scan = Scan(
                    name=f"Realtime: {session_name}",
                    status="running",
                    scan_type="realtime",
                    recon_enabled=True,
                    progress=50,
                    current_phase="testing",
                )
                db.add(scan)
                await db.commit()
                await db.refresh(scan)
                scan_id = scan.id
                session["db_scan_id"] = scan_id

                # Create target record
                target_record = Target(
                    scan_id=scan_id,
                    url=target,
                    status="active"
                )
                db.add(target_record)
                await db.commit()

            # Get existing vulnerability titles for this scan
            existing_result = await db.execute(
                select(Vulnerability.title).where(Vulnerability.scan_id == scan_id)
            )
            existing_titles = {row[0].lower() for row in existing_result.fetchall()}

            # Count severities
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            # Add new findings
            for finding in findings:
                title = finding.get("title", "Unknown Finding")
                if title.lower() in existing_titles:
                    continue

                severity = finding.get("severity", "info").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

                vuln = Vulnerability(
                    scan_id=scan_id,
                    title=title,
                    vulnerability_type=finding.get("vulnerability_type", "unknown"),
                    severity=severity,
                    cvss_score=finding.get("cvss_score"),
                    cvss_vector=finding.get("cvss_vector"),
                    cwe_id=finding.get("cwe_id"),
                    description=finding.get("description", ""),
                    affected_endpoint=finding.get("affected_endpoint", target),
                    poc_payload=finding.get("evidence", finding.get("payload", "")),
                    impact=finding.get("impact", ""),
                    remediation=finding.get("remediation", ""),
                    references=finding.get("references", []),
                    ai_analysis=f"Identified during realtime session {session_id}"
                )
                db.add(vuln)

            # Update scan counts
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.total_vulnerabilities = len(findings)
                scan.critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
                scan.high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
                scan.medium_count = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
                scan.low_count = sum(1 for f in findings if f.get("severity", "").lower() == "low")
                scan.info_count = sum(1 for f in findings if f.get("severity", "").lower() == "info")

            await db.commit()

    except Exception as e:
        print(f"Error saving realtime findings to DB: {e}")
        import traceback
        traceback.print_exc()


@router.get("/realtime/{session_id}")
async def get_realtime_session(session_id: str):
    """Get the current state of a real-time session"""
    if session_id not in realtime_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = realtime_sessions[session_id]

    return {
        "session_id": session_id,
        "name": session["name"],
        "target": session["target"],
        "status": session["status"],
        "created_at": session["created_at"],
        "messages": session["messages"][1:],  # Exclude system message
        "findings": session["findings"],
        "recon_data": session["recon_data"]
    }


@router.get("/realtime/{session_id}/report")
async def generate_realtime_report(session_id: str, format: str = "json"):
    """Generate a report from the real-time session findings

    Args:
        session_id: The session ID
        format: "json" (default) or "html" for full HTML report
    """
    if session_id not in realtime_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = realtime_sessions[session_id]
    findings = session["findings"]

    # Count severities
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Generate executive summary
    if severity_counts["critical"] > 0 or severity_counts["high"] > 0:
        risk_level = "HIGH"
        summary = f"Critical security issues identified. {severity_counts['critical']} critical and {severity_counts['high']} high severity vulnerabilities require immediate attention."
    elif severity_counts["medium"] > 0:
        risk_level = "MEDIUM"
        summary = f"Security improvements needed. {severity_counts['medium']} medium severity issues should be addressed."
    else:
        risk_level = "LOW"
        summary = "No critical issues found. Minor improvements recommended for defense in depth."

    # Generate HTML report if requested
    if format.lower() == "html":
        from fastapi.responses import HTMLResponse
        from backend.core.report_generator import HTMLReportGenerator

        generator = HTMLReportGenerator()

        session_data = {
            "name": session["name"],
            "target": session["target"],
            "created_at": session["created_at"],
            "recon_data": session["recon_data"]
        }

        # Get tool results if any
        tool_results = session.get("tool_results", [])

        html_content = generator.generate_report(
            session_data=session_data,
            findings=findings,
            scan_results=tool_results
        )

        return HTMLResponse(content=html_content, media_type="text/html")

    return {
        "session_id": session_id,
        "target": session["target"],
        "generated_at": datetime.utcnow().isoformat(),
        "risk_level": risk_level,
        "executive_summary": summary,
        "severity_breakdown": severity_counts,
        "total_findings": len(findings),
        "findings": findings,
        "technologies": session["recon_data"].get("technologies", []),
        "recommendations": [
            "Address all critical and high severity findings immediately",
            "Review and fix medium severity issues within 30 days",
            "Implement security headers across all endpoints",
            "Conduct regular security assessments"
        ]
    }


@router.delete("/realtime/{session_id}")
async def delete_realtime_session(session_id: str):
    """Delete a real-time session"""
    if session_id not in realtime_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    del realtime_sessions[session_id]
    return {"message": f"Session {session_id} deleted"}


@router.get("/realtime/sessions/list")
async def list_realtime_sessions():
    """List all active real-time sessions"""
    return {
        "sessions": [
            {
                "session_id": sid,
                "name": s["name"],
                "target": s["target"],
                "status": s["status"],
                "created_at": s["created_at"],
                "findings_count": len(s["findings"]),
                "messages_count": len(s["messages"]) - 1  # Exclude system message
            }
            for sid, s in realtime_sessions.items()
        ]
    }


# ==================== Tool Execution Endpoints ====================

class ToolExecutionRequest(BaseModel):
    """Request to execute a security tool"""
    tool: str = Field(..., description="Tool name (e.g., 'dirb', 'feroxbuster', 'nmap')")
    options: Optional[Dict] = Field(default=None, description="Additional tool options")
    timeout: Optional[int] = Field(default=300, description="Timeout in seconds")


@router.get("/realtime/tools/list")
async def list_available_tools():
    """List all available security tools"""
    from backend.core.tool_executor import SecurityTool

    return {
        "tools": [
            {
                "id": tool_id,
                "name": tool["name"],
                "description": tool["description"]
            }
            for tool_id, tool in SecurityTool.TOOLS.items()
        ]
    }


@router.get("/realtime/tools/status")
async def get_tools_status():
    """Check if Docker tool executor is available"""
    from backend.core.tool_executor import get_tool_executor

    try:
        executor = await get_tool_executor()
        return {
            "available": executor.is_available(),
            "docker_status": "running" if executor.is_available() else "not available",
            "active_containers": len(executor.active_containers),
            "tools_count": len(executor.get_available_tools())
        }
    except Exception as e:
        return {
            "available": False,
            "docker_status": "error",
            "error": str(e)
        }


@router.post("/realtime/{session_id}/execute-tool")
async def execute_security_tool(session_id: str, request: ToolExecutionRequest):
    """Execute a security tool against the session's target"""
    if session_id not in realtime_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = realtime_sessions[session_id]
    target = session["target"]

    from backend.core.tool_executor import get_tool_executor, ToolStatus

    try:
        executor = await get_tool_executor()

        if not executor.is_available():
            raise HTTPException(
                status_code=503,
                detail="Docker tool executor not available. Ensure Docker is running."
            )

        # Execute the tool
        result = await executor.execute_tool(
            tool_name=request.tool,
            target=target,
            options=request.options,
            timeout=request.timeout
        )

        # Store tool result in session
        if "tool_results" not in session:
            session["tool_results"] = []

        tool_result = {
            "tool": result.tool,
            "command": result.command,
            "status": result.status.value,
            "output": result.output[:10000],  # Limit output size
            "error": result.error,
            "duration_seconds": result.duration_seconds,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "findings_count": len(result.findings)
        }
        session["tool_results"].append(tool_result)

        # Add findings from tool to session findings
        for finding in result.findings:
            if finding not in session["findings"]:
                session["findings"].append(finding)

        # Add assistant message about tool execution
        tool_message = {
            "role": "assistant",
            "content": f"""🔧 **Tool Execution: {result.tool}**

**Command:** `{result.command}`
**Status:** {result.status.value.upper()}
**Duration:** {result.duration_seconds:.1f}s
**Findings:** {len(result.findings)} discovered

{f'**Output Preview:**' + chr(10) + '```' + chr(10) + result.output[:1500] + ('...' if len(result.output) > 1500 else '') + chr(10) + '```' if result.output else ''}
{f'**Error:** {result.error}' if result.error else ''}""",
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {
                "tool_execution": True,
                "tool": result.tool,
                "new_findings": len(result.findings)
            }
        }
        session["messages"].append(tool_message)

        return {
            "session_id": session_id,
            "tool": result.tool,
            "status": result.status.value,
            "duration_seconds": result.duration_seconds,
            "findings": result.findings,
            "output_preview": result.output[:2000] if result.output else None,
            "error": result.error if result.error else None
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Tool execution failed: {str(e)}")


# ==================== LLM Finding Parser ====================

def parse_llm_findings(llm_response: str, target: str) -> List[Dict]:
    """Parse findings from LLM response text with comprehensive pattern matching"""
    import re

    findings = []

    # CVSS and CWE mappings for common vulnerabilities
    VULN_METADATA = {
        "sql injection": {
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe_id": "CWE-89",
            "owasp": "A03:2021 - Injection"
        },
        "xss": {
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cwe_id": "CWE-79",
            "owasp": "A03:2021 - Injection"
        },
        "cross-site scripting": {
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cwe_id": "CWE-79",
            "owasp": "A03:2021 - Injection"
        },
        "command injection": {
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe_id": "CWE-78",
            "owasp": "A03:2021 - Injection"
        },
        "remote code execution": {
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cwe_id": "CWE-94",
            "owasp": "A03:2021 - Injection"
        },
        "ssrf": {
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe_id": "CWE-918",
            "owasp": "A10:2021 - SSRF"
        },
        "idor": {
            "cvss_score": 6.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "cwe_id": "CWE-639",
            "owasp": "A01:2021 - Broken Access Control"
        },
        "path traversal": {
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe_id": "CWE-22",
            "owasp": "A01:2021 - Broken Access Control"
        },
        "lfi": {
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe_id": "CWE-98",
            "owasp": "A01:2021 - Broken Access Control"
        },
        "authentication bypass": {
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe_id": "CWE-287",
            "owasp": "A07:2021 - Identification and Authentication Failures"
        },
        "csrf": {
            "cvss_score": 4.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "cwe_id": "CWE-352",
            "owasp": "A01:2021 - Broken Access Control"
        },
        "clickjacking": {
            "cvss_score": 4.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "cwe_id": "CWE-1021",
            "owasp": "A05:2021 - Security Misconfiguration"
        },
        "open redirect": {
            "cvss_score": 4.7,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
            "cwe_id": "CWE-601",
            "owasp": "A01:2021 - Broken Access Control"
        },
        "missing header": {
            "cvss_score": 3.7,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe_id": "CWE-693",
            "owasp": "A05:2021 - Security Misconfiguration"
        },
        "information disclosure": {
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe_id": "CWE-200",
            "owasp": "A01:2021 - Broken Access Control"
        },
        "cookie": {
            "cvss_score": 3.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "cwe_id": "CWE-614",
            "owasp": "A05:2021 - Security Misconfiguration"
        },
        "cors": {
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe_id": "CWE-942",
            "owasp": "A05:2021 - Security Misconfiguration"
        },
        "ssl": {
            "cvss_score": 5.9,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe_id": "CWE-295",
            "owasp": "A02:2021 - Cryptographic Failures"
        },
        "hsts": {
            "cvss_score": 4.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cwe_id": "CWE-319",
            "owasp": "A02:2021 - Cryptographic Failures"
        }
    }

    def get_vuln_metadata(text: str) -> Dict:
        """Get CVSS/CWE metadata based on vulnerability type"""
        text_lower = text.lower()
        for vuln_type, metadata in VULN_METADATA.items():
            if vuln_type in text_lower:
                return metadata
        return {
            "cvss_score": 5.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cwe_id": "CWE-1000",
            "owasp": "A00:2021 - Unclassified"
        }

    # Pattern 1: Structured finding format with various markdown styles
    structured_patterns = [
        # **Title:** xxx / **Severity:** xxx / **Description:** xxx
        r'\*\*(?:Title|Finding|Vulnerability)[:\s]*\*\*\s*([^\n*]+)[\s\S]*?'
        r'\*\*Severity[:\s]*\*\*\s*(critical|high|medium|low|info)[\s\S]*?'
        r'\*\*Description[:\s]*\*\*\s*([^\n]+)',

        # ### Finding Name followed by severity
        r'###\s+([^\n]+)\s*\n[\s\S]*?'
        r'(?:\*\*)?(?:Severity|Risk)[:\s]*(?:\*\*)?\s*(critical|high|medium|low|info)',

        # Numbered findings: 1. **Finding Name** - Severity: xxx
        r'\d+\.\s*\*\*([^*]+)\*\*[^\n]*(?:Severity|Risk)[:\s]*(critical|high|medium|low|info)',

        # - **Finding:** xxx | Severity: xxx
        r'-\s*\*\*(?:Finding|Issue)[:\s]*\*\*\s*([^\n|]+)\s*\|\s*(?:Severity|Risk)[:\s]*(critical|high|medium|low|info)',
    ]

    for pattern in structured_patterns:
        matches = re.finditer(pattern, llm_response, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            groups = match.groups()
            title = groups[0].strip().strip('*').strip()
            severity = groups[1].strip().lower() if len(groups) > 1 else "medium"
            description = groups[2].strip() if len(groups) > 2 else f"Security issue: {title}"

            # Skip if already found
            if any(f.get('title', '').lower() == title.lower() for f in findings):
                continue

            metadata = get_vuln_metadata(title + " " + description)

            findings.append({
                "title": title,
                "severity": severity,
                "vulnerability_type": "AI Identified",
                "description": description,
                "affected_endpoint": target,
                "evidence": "Identified by AI security analysis",
                "remediation": f"Review and address the {title} vulnerability",
                "cvss_score": metadata["cvss_score"],
                "cvss_vector": metadata["cvss_vector"],
                "cwe_id": metadata["cwe_id"],
                "owasp": metadata.get("owasp", "")
            })

    # Pattern 2: Vulnerability keyword detection with severity inference
    vuln_keywords = {
        "critical": [
            ("sql injection", "SQL Injection vulnerability allows attackers to manipulate database queries"),
            ("remote code execution", "Remote code execution allows arbitrary code execution on the server"),
            ("rce", "Remote code execution vulnerability detected"),
            ("authentication bypass", "Authentication can be bypassed allowing unauthorized access"),
            ("command injection", "Command injection allows executing arbitrary system commands"),
        ],
        "high": [
            ("xss", "Cross-Site Scripting allows injection of malicious scripts"),
            ("cross-site scripting", "XSS vulnerability allows script injection"),
            ("ssrf", "Server-Side Request Forgery allows making requests from the server"),
            ("idor", "Insecure Direct Object Reference allows accessing unauthorized data"),
            ("file upload", "Unrestricted file upload may allow malicious file execution"),
            ("path traversal", "Path traversal allows accessing files outside the web root"),
            ("lfi", "Local File Inclusion allows reading arbitrary server files"),
            ("rfi", "Remote File Inclusion allows including remote malicious files"),
            ("xxe", "XML External Entity injection detected"),
            ("deserialization", "Insecure deserialization vulnerability"),
        ],
        "medium": [
            ("csrf", "Cross-Site Request Forgery allows forging requests on behalf of users"),
            ("clickjacking", "Clickjacking allows UI redressing attacks"),
            ("open redirect", "Open redirect can be used for phishing attacks"),
            ("information disclosure", "Sensitive information is exposed"),
            ("sensitive data", "Sensitive data exposure detected"),
            ("session fixation", "Session fixation vulnerability"),
            ("host header injection", "Host header injection detected"),
        ],
        "low": [
            ("missing hsts", "HSTS header is missing, vulnerable to protocol downgrade"),
            ("missing x-frame-options", "X-Frame-Options missing, clickjacking possible"),
            ("missing x-content-type", "X-Content-Type-Options missing, MIME sniffing possible"),
            ("missing csp", "Content-Security-Policy missing"),
            ("cookie without httponly", "Cookie missing HttpOnly flag"),
            ("cookie without secure", "Cookie missing Secure flag"),
            ("directory listing", "Directory listing is enabled"),
            ("verbose error", "Verbose error messages may leak information"),
        ],
        "info": [
            ("technology detected", "Technology fingerprinting information"),
            ("version disclosed", "Software version information disclosed"),
            ("endpoint discovered", "Additional endpoint discovered"),
            ("robots.txt", "robots.txt file found"),
            ("sitemap", "Sitemap file found"),
            ("server header", "Server header reveals technology information"),
        ]
    }

    for severity, keyword_list in vuln_keywords.items():
        for keyword_tuple in keyword_list:
            keyword = keyword_tuple[0]
            default_desc = keyword_tuple[1]

            # Search for keyword with word boundaries
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, llm_response, re.IGNORECASE):
                # Check if we already have this finding
                already_found = any(
                    keyword.lower() in f.get('title', '').lower() or
                    keyword.lower() in f.get('description', '').lower()
                    for f in findings
                )
                if not already_found:
                    # Try to extract context around the keyword
                    match = re.search(pattern, llm_response, re.IGNORECASE)
                    if match:
                        idx = match.start()
                        start = max(0, idx - 150)
                        end = min(len(llm_response), idx + 250)
                        context = llm_response[start:end].strip()
                        # Clean up context
                        context = re.sub(r'\s+', ' ', context)

                    metadata = get_vuln_metadata(keyword)
                    title = f"{keyword.title()} Vulnerability" if "vulnerability" not in keyword.lower() else keyword.title()

                    findings.append({
                        "title": title,
                        "severity": severity,
                        "vulnerability_type": keyword.replace(" ", "_").upper(),
                        "description": default_desc,
                        "affected_endpoint": target,
                        "evidence": f"AI Analysis Context: ...{context}..." if context else "Detected in AI response",
                        "remediation": f"Investigate and remediate the {keyword} vulnerability",
                        "cvss_score": metadata["cvss_score"],
                        "cvss_vector": metadata["cvss_vector"],
                        "cwe_id": metadata["cwe_id"],
                        "owasp": metadata.get("owasp", "")
                    })

    # Pattern 3: Look for findings in bullet points or numbered lists
    list_pattern = r'[-•]\s*((?:Critical|High|Medium|Low|Info)[:\s]+)?([^:\n]+(?:vulnerability|issue|flaw|weakness|exposure|misconfiguration)[^\n]*)'
    for match in re.finditer(list_pattern, llm_response, re.IGNORECASE):
        severity_text = (match.group(1) or "").strip().lower().rstrip(':')
        title = match.group(2).strip()

        if len(title) < 10 or len(title) > 150:
            continue

        severity = "medium"
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_text:
                severity = sev
                break

        if not any(f.get('title', '').lower() == title.lower() for f in findings):
            metadata = get_vuln_metadata(title)
            findings.append({
                "title": title,
                "severity": severity,
                "vulnerability_type": "AI Identified",
                "description": f"Security finding: {title}",
                "affected_endpoint": target,
                "evidence": "Extracted from AI analysis",
                "remediation": "Review and address this security finding",
                "cvss_score": metadata["cvss_score"],
                "cvss_vector": metadata["cvss_vector"],
                "cwe_id": metadata["cwe_id"],
                "owasp": metadata.get("owasp", "")
            })

    return findings
