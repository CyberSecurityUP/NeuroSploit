"""
NeuroSploit v3 - Scheduler API Router

CRUD endpoints for managing scheduled scan jobs.
"""

import json
from pathlib import Path
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List, Dict

router = APIRouter()

CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "config.json"


class ScheduleJobRequest(BaseModel):
    """Request model for creating a scheduled job."""
    job_id: str
    target: str
    scan_type: str = "quick"
    cron_expression: Optional[str] = None
    interval_minutes: Optional[int] = None
    agent_role: Optional[str] = None
    llm_profile: Optional[str] = None


class ScheduleJobResponse(BaseModel):
    """Response model for a scheduled job."""
    id: str
    target: str
    scan_type: str
    schedule: str
    status: str
    next_run: Optional[str] = None
    last_run: Optional[str] = None
    run_count: int = 0


@router.get("/", response_model=List[Dict])
async def list_scheduled_jobs(request: Request):
    """List all scheduled scan jobs."""
    scheduler = getattr(request.app.state, 'scheduler', None)
    if not scheduler:
        return []
    return scheduler.list_jobs()


@router.post("/", response_model=Dict)
async def create_scheduled_job(job: ScheduleJobRequest, request: Request):
    """Create a new scheduled scan job."""
    scheduler = getattr(request.app.state, 'scheduler', None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not available")

    if not job.cron_expression and not job.interval_minutes:
        raise HTTPException(
            status_code=400,
            detail="Either cron_expression or interval_minutes must be provided"
        )

    result = scheduler.add_job(
        job_id=job.job_id,
        target=job.target,
        scan_type=job.scan_type,
        cron_expression=job.cron_expression,
        interval_minutes=job.interval_minutes,
        agent_role=job.agent_role,
        llm_profile=job.llm_profile
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@router.delete("/{job_id}")
async def delete_scheduled_job(job_id: str, request: Request):
    """Delete a scheduled scan job."""
    scheduler = getattr(request.app.state, 'scheduler', None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not available")

    success = scheduler.remove_job(job_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")

    return {"message": f"Job '{job_id}' deleted", "id": job_id}


@router.post("/{job_id}/pause")
async def pause_scheduled_job(job_id: str, request: Request):
    """Pause a scheduled scan job."""
    scheduler = getattr(request.app.state, 'scheduler', None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not available")

    success = scheduler.pause_job(job_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")

    return {"message": f"Job '{job_id}' paused", "id": job_id, "status": "paused"}


@router.post("/{job_id}/resume")
async def resume_scheduled_job(job_id: str, request: Request):
    """Resume a paused scheduled scan job."""
    scheduler = getattr(request.app.state, 'scheduler', None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not available")

    success = scheduler.resume_job(job_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")

    return {"message": f"Job '{job_id}' resumed", "id": job_id, "status": "active"}


@router.get("/agent-roles", response_model=List[Dict])
async def get_agent_roles():
    """Return available agent roles from config.json for scheduler dropdown."""
    try:
        if not CONFIG_PATH.exists():
            return []
        config = json.loads(CONFIG_PATH.read_text())
        roles = config.get("agent_roles", {})
        result = []
        for role_id, role_data in roles.items():
            if role_data.get("enabled", True):
                result.append({
                    "id": role_id,
                    "name": role_id.replace("_", " ").title(),
                    "description": role_data.get("description", ""),
                    "tools": role_data.get("tools_allowed", []),
                })
        return result
    except Exception:
        return []
