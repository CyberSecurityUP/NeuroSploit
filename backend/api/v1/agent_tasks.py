"""
NeuroSploit v3 - Agent Tasks API Endpoints
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from backend.db.database import get_db
from backend.models import AgentTask, Scan
from backend.schemas.agent_task import (
    AgentTaskResponse,
    AgentTaskListResponse,
    AgentTaskSummary
)

router = APIRouter()


@router.get("", response_model=AgentTaskListResponse)
async def list_agent_tasks(
    scan_id: str,
    status: Optional[str] = None,
    task_type: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """List all agent tasks for a scan"""
    # Verify scan exists
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Build query
    query = select(AgentTask).where(AgentTask.scan_id == scan_id)

    if status:
        query = query.where(AgentTask.status == status)
    if task_type:
        query = query.where(AgentTask.task_type == task_type)

    query = query.order_by(AgentTask.created_at.desc())

    # Get total count
    count_query = select(func.count()).select_from(AgentTask).where(AgentTask.scan_id == scan_id)
    if status:
        count_query = count_query.where(AgentTask.status == status)
    if task_type:
        count_query = count_query.where(AgentTask.task_type == task_type)
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Apply pagination
    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    tasks = result.scalars().all()

    return AgentTaskListResponse(
        tasks=[AgentTaskResponse(**t.to_dict()) for t in tasks],
        total=total,
        scan_id=scan_id
    )


@router.get("/summary", response_model=AgentTaskSummary)
async def get_agent_tasks_summary(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get summary statistics for agent tasks in a scan"""
    # Verify scan exists
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Total count
    total_result = await db.execute(
        select(func.count()).select_from(AgentTask).where(AgentTask.scan_id == scan_id)
    )
    total = total_result.scalar() or 0

    # Count by status
    status_counts = {}
    for status in ["pending", "running", "completed", "failed"]:
        count_result = await db.execute(
            select(func.count()).select_from(AgentTask)
            .where(AgentTask.scan_id == scan_id)
            .where(AgentTask.status == status)
        )
        status_counts[status] = count_result.scalar() or 0

    # Count by task type
    type_query = select(
        AgentTask.task_type,
        func.count(AgentTask.id).label("count")
    ).where(AgentTask.scan_id == scan_id).group_by(AgentTask.task_type)
    type_result = await db.execute(type_query)
    by_type = {row[0]: row[1] for row in type_result.all()}

    # Count by tool
    tool_query = select(
        AgentTask.tool_name,
        func.count(AgentTask.id).label("count")
    ).where(AgentTask.scan_id == scan_id).where(AgentTask.tool_name.isnot(None)).group_by(AgentTask.tool_name)
    tool_result = await db.execute(tool_query)
    by_tool = {row[0]: row[1] for row in tool_result.all()}

    return AgentTaskSummary(
        total=total,
        pending=status_counts.get("pending", 0),
        running=status_counts.get("running", 0),
        completed=status_counts.get("completed", 0),
        failed=status_counts.get("failed", 0),
        by_type=by_type,
        by_tool=by_tool
    )


@router.get("/{task_id}", response_model=AgentTaskResponse)
async def get_agent_task(
    task_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get a specific agent task by ID"""
    result = await db.execute(select(AgentTask).where(AgentTask.id == task_id))
    task = result.scalar_one_or_none()

    if not task:
        raise HTTPException(status_code=404, detail="Agent task not found")

    return AgentTaskResponse(**task.to_dict())


@router.get("/scan/{scan_id}/timeline")
async def get_agent_tasks_timeline(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get agent tasks as a timeline for visualization"""
    # Verify scan exists
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get all tasks ordered by creation time
    query = select(AgentTask).where(AgentTask.scan_id == scan_id).order_by(AgentTask.created_at.asc())
    result = await db.execute(query)
    tasks = result.scalars().all()

    timeline = []
    for task in tasks:
        timeline_item = {
            "id": task.id,
            "task_name": task.task_name,
            "task_type": task.task_type,
            "tool_name": task.tool_name,
            "status": task.status,
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "duration_ms": task.duration_ms,
            "items_processed": task.items_processed,
            "items_found": task.items_found,
            "result_summary": task.result_summary,
            "error_message": task.error_message
        }
        timeline.append(timeline_item)

    return {
        "scan_id": scan_id,
        "timeline": timeline,
        "total": len(timeline)
    }
