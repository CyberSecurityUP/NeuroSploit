"""
NeuroSploit v3 - Dashboard API Endpoints
"""
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta

from backend.db.database import get_db
from backend.models import Scan, Vulnerability, Endpoint, AgentTask, Report

router = APIRouter()


@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Get overall dashboard statistics"""
    # Total scans
    total_scans_result = await db.execute(select(func.count()).select_from(Scan))
    total_scans = total_scans_result.scalar() or 0

    # Scans by status
    running_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "running")
    )
    running_scans = running_result.scalar() or 0

    completed_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "completed")
    )
    completed_scans = completed_result.scalar() or 0

    stopped_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "stopped")
    )
    stopped_scans = stopped_result.scalar() or 0

    failed_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "failed")
    )
    failed_scans = failed_result.scalar() or 0

    pending_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "pending")
    )
    pending_scans = pending_result.scalar() or 0

    # Total vulnerabilities by severity
    vuln_counts = {}
    for severity in ["critical", "high", "medium", "low", "info"]:
        result = await db.execute(
            select(func.count()).select_from(Vulnerability).where(Vulnerability.severity == severity)
        )
        vuln_counts[severity] = result.scalar() or 0

    total_vulns = sum(vuln_counts.values())

    # Total endpoints
    endpoints_result = await db.execute(select(func.count()).select_from(Endpoint))
    total_endpoints = endpoints_result.scalar() or 0

    # Recent activity (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_scans_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.created_at >= week_ago)
    )
    recent_scans = recent_scans_result.scalar() or 0

    recent_vulns_result = await db.execute(
        select(func.count()).select_from(Vulnerability).where(Vulnerability.created_at >= week_ago)
    )
    recent_vulns = recent_vulns_result.scalar() or 0

    return {
        "scans": {
            "total": total_scans,
            "running": running_scans,
            "completed": completed_scans,
            "stopped": stopped_scans,
            "failed": failed_scans,
            "pending": pending_scans,
            "recent": recent_scans
        },
        "vulnerabilities": {
            "total": total_vulns,
            "critical": vuln_counts["critical"],
            "high": vuln_counts["high"],
            "medium": vuln_counts["medium"],
            "low": vuln_counts["low"],
            "info": vuln_counts["info"],
            "recent": recent_vulns
        },
        "endpoints": {
            "total": total_endpoints
        }
    }


@router.get("/recent")
async def get_recent_activity(
    limit: int = 10,
    db: AsyncSession = Depends(get_db)
):
    """Get recent scan activity"""
    # Recent scans
    scans_query = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    scans_result = await db.execute(scans_query)
    recent_scans = scans_result.scalars().all()

    # Recent vulnerabilities
    vulns_query = select(Vulnerability).order_by(Vulnerability.created_at.desc()).limit(limit)
    vulns_result = await db.execute(vulns_query)
    recent_vulns = vulns_result.scalars().all()

    return {
        "recent_scans": [s.to_dict() for s in recent_scans],
        "recent_vulnerabilities": [v.to_dict() for v in recent_vulns]
    }


@router.get("/findings")
async def get_recent_findings(
    limit: int = 20,
    severity: str = None,
    db: AsyncSession = Depends(get_db)
):
    """Get recent vulnerability findings"""
    query = select(Vulnerability).order_by(Vulnerability.created_at.desc())

    if severity:
        query = query.where(Vulnerability.severity == severity)

    query = query.limit(limit)
    result = await db.execute(query)
    vulnerabilities = result.scalars().all()

    return {
        "findings": [v.to_dict() for v in vulnerabilities],
        "total": len(vulnerabilities)
    }


@router.get("/vulnerability-types")
async def get_vulnerability_distribution(db: AsyncSession = Depends(get_db)):
    """Get vulnerability distribution by type"""
    query = select(
        Vulnerability.vulnerability_type,
        func.count(Vulnerability.id).label("count")
    ).group_by(Vulnerability.vulnerability_type)

    result = await db.execute(query)
    distribution = result.all()

    return {
        "distribution": [
            {"type": row[0], "count": row[1]}
            for row in distribution
        ]
    }


@router.get("/scan-history")
async def get_scan_history(
    days: int = 30,
    db: AsyncSession = Depends(get_db)
):
    """Get scan history for charts"""
    start_date = datetime.utcnow() - timedelta(days=days)

    # Get scans grouped by date
    scans = await db.execute(
        select(Scan).where(Scan.created_at >= start_date).order_by(Scan.created_at)
    )
    all_scans = scans.scalars().all()

    # Group by date
    history = {}
    for scan in all_scans:
        date_str = scan.created_at.strftime("%Y-%m-%d")
        if date_str not in history:
            history[date_str] = {
                "date": date_str,
                "scans": 0,
                "vulnerabilities": 0,
                "critical": 0,
                "high": 0
            }
        history[date_str]["scans"] += 1
        history[date_str]["vulnerabilities"] += scan.total_vulnerabilities
        history[date_str]["critical"] += scan.critical_count
        history[date_str]["high"] += scan.high_count

    return {"history": list(history.values())}


@router.get("/agent-tasks")
async def get_recent_agent_tasks(
    limit: int = 20,
    db: AsyncSession = Depends(get_db)
):
    """Get recent agent tasks across all scans"""
    query = (
        select(AgentTask)
        .order_by(AgentTask.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(query)
    tasks = result.scalars().all()

    return {
        "agent_tasks": [t.to_dict() for t in tasks],
        "total": len(tasks)
    }


@router.get("/activity-feed")
async def get_activity_feed(
    limit: int = 30,
    db: AsyncSession = Depends(get_db)
):
    """Get unified activity feed with all recent events"""
    activities = []

    # Get recent scans
    scans_result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(limit // 3)
    )
    for scan in scans_result.scalars().all():
        activities.append({
            "type": "scan",
            "action": f"Scan {scan.status}",
            "title": scan.name or "Unnamed Scan",
            "description": f"{scan.total_vulnerabilities} vulnerabilities found",
            "status": scan.status,
            "severity": None,
            "timestamp": scan.created_at.isoformat(),
            "scan_id": scan.id,
            "link": f"/scan/{scan.id}"
        })

    # Get recent vulnerabilities
    vulns_result = await db.execute(
        select(Vulnerability).order_by(Vulnerability.created_at.desc()).limit(limit // 3)
    )
    for vuln in vulns_result.scalars().all():
        activities.append({
            "type": "vulnerability",
            "action": "Vulnerability found",
            "title": vuln.title,
            "description": vuln.affected_endpoint or "",
            "status": None,
            "severity": vuln.severity,
            "timestamp": vuln.created_at.isoformat(),
            "scan_id": vuln.scan_id,
            "link": f"/scan/{vuln.scan_id}"
        })

    # Get recent agent tasks
    tasks_result = await db.execute(
        select(AgentTask).order_by(AgentTask.created_at.desc()).limit(limit // 3)
    )
    for task in tasks_result.scalars().all():
        activities.append({
            "type": "agent_task",
            "action": f"Task {task.status}",
            "title": task.task_name,
            "description": task.result_summary or task.description or "",
            "status": task.status,
            "severity": None,
            "timestamp": task.created_at.isoformat(),
            "scan_id": task.scan_id,
            "link": f"/scan/{task.scan_id}"
        })

    # Get recent reports
    reports_result = await db.execute(
        select(Report).order_by(Report.generated_at.desc()).limit(limit // 4)
    )
    for report in reports_result.scalars().all():
        activities.append({
            "type": "report",
            "action": "Report generated" if report.auto_generated else "Report created",
            "title": report.title or "Report",
            "description": f"{report.format.upper()} format",
            "status": "auto" if report.auto_generated else "manual",
            "severity": None,
            "timestamp": report.generated_at.isoformat(),
            "scan_id": report.scan_id,
            "link": f"/reports"
        })

    # Sort all activities by timestamp (newest first)
    activities.sort(key=lambda x: x["timestamp"], reverse=True)

    return {
        "activities": activities[:limit],
        "total": len(activities)
    }
