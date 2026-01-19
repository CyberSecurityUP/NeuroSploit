"""
NeuroSploit v3 - Scans API Endpoints
"""
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from urllib.parse import urlparse

from backend.db.database import get_db
from backend.models import Scan, Target, Endpoint, Vulnerability
from backend.schemas.scan import ScanCreate, ScanUpdate, ScanResponse, ScanListResponse, ScanProgress
from backend.services.scan_service import run_scan_task

router = APIRouter()


@router.get("", response_model=ScanListResponse)
async def list_scans(
    page: int = 1,
    per_page: int = 10,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all scans with pagination"""
    query = select(Scan).order_by(Scan.created_at.desc())

    if status:
        query = query.where(Scan.status == status)

    # Get total count
    count_query = select(func.count()).select_from(Scan)
    if status:
        count_query = count_query.where(Scan.status == status)
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Apply pagination
    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    scans = result.scalars().all()

    # Load targets for each scan
    scan_responses = []
    for scan in scans:
        targets_query = select(Target).where(Target.scan_id == scan.id)
        targets_result = await db.execute(targets_query)
        targets = targets_result.scalars().all()

        scan_dict = scan.to_dict()
        scan_dict["targets"] = [t.to_dict() for t in targets]
        scan_responses.append(ScanResponse(**scan_dict))

    return ScanListResponse(
        scans=scan_responses,
        total=total,
        page=page,
        per_page=per_page
    )


@router.post("", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Create a new scan with optional authentication for authenticated testing"""
    # Process authentication config
    auth_type = None
    auth_credentials = None
    if scan_data.auth:
        auth_type = scan_data.auth.auth_type
        auth_credentials = {}
        if scan_data.auth.cookie:
            auth_credentials["cookie"] = scan_data.auth.cookie
        if scan_data.auth.bearer_token:
            auth_credentials["bearer_token"] = scan_data.auth.bearer_token
        if scan_data.auth.username:
            auth_credentials["username"] = scan_data.auth.username
        if scan_data.auth.password:
            auth_credentials["password"] = scan_data.auth.password
        if scan_data.auth.header_name and scan_data.auth.header_value:
            auth_credentials["header_name"] = scan_data.auth.header_name
            auth_credentials["header_value"] = scan_data.auth.header_value

    # Create scan
    scan = Scan(
        name=scan_data.name or f"Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        scan_type=scan_data.scan_type,
        recon_enabled=scan_data.recon_enabled,
        custom_prompt=scan_data.custom_prompt,
        prompt_id=scan_data.prompt_id,
        config=scan_data.config,
        auth_type=auth_type,
        auth_credentials=auth_credentials,
        custom_headers=scan_data.custom_headers,
        status="pending"
    )
    db.add(scan)
    await db.flush()

    # Create targets
    targets = []
    for url in scan_data.targets:
        parsed = urlparse(url)
        target = Target(
            scan_id=scan.id,
            url=url,
            hostname=parsed.hostname,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            protocol=parsed.scheme or "https",
            path=parsed.path or "/"
        )
        db.add(target)
        targets.append(target)

    await db.commit()
    await db.refresh(scan)

    scan_dict = scan.to_dict()
    scan_dict["targets"] = [t.to_dict() for t in targets]

    return ScanResponse(**scan_dict)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get scan details by ID"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Load targets
    targets_result = await db.execute(select(Target).where(Target.scan_id == scan_id))
    targets = targets_result.scalars().all()

    scan_dict = scan.to_dict()
    scan_dict["targets"] = [t.to_dict() for t in targets]

    return ScanResponse(**scan_dict)


@router.post("/{scan_id}/start")
async def start_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Start a scan execution"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status == "running":
        raise HTTPException(status_code=400, detail="Scan is already running")

    # Update scan status
    scan.status = "running"
    scan.started_at = datetime.utcnow()
    scan.current_phase = "initializing"
    scan.progress = 0
    await db.commit()

    # Start scan in background with its own database session
    background_tasks.add_task(run_scan_task, scan_id)

    return {"message": "Scan started", "scan_id": scan_id}


@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Stop a running scan"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")

    scan.status = "stopped"
    scan.completed_at = datetime.utcnow()
    await db.commit()

    return {"message": "Scan stopped", "scan_id": scan_id}


@router.get("/{scan_id}/status", response_model=ScanProgress)
async def get_scan_status(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get scan progress and status"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanProgress(
        scan_id=scan.id,
        status=scan.status,
        progress=scan.progress,
        current_phase=scan.current_phase,
        total_endpoints=scan.total_endpoints,
        total_vulnerabilities=scan.total_vulnerabilities
    )


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a scan"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status == "running":
        raise HTTPException(status_code=400, detail="Cannot delete running scan")

    await db.delete(scan)
    await db.commit()

    return {"message": "Scan deleted", "scan_id": scan_id}


@router.get("/{scan_id}/endpoints")
async def get_scan_endpoints(
    scan_id: str,
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """Get endpoints discovered in a scan"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    query = select(Endpoint).where(Endpoint.scan_id == scan_id).order_by(Endpoint.discovered_at.desc())

    # Count
    count_result = await db.execute(select(func.count()).select_from(Endpoint).where(Endpoint.scan_id == scan_id))
    total = count_result.scalar()

    # Paginate
    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    endpoints = result.scalars().all()

    return {
        "endpoints": [e.to_dict() for e in endpoints],
        "total": total,
        "page": page,
        "per_page": per_page
    }


@router.get("/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """Get vulnerabilities found in a scan"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    query = select(Vulnerability).where(Vulnerability.scan_id == scan_id)

    if severity:
        query = query.where(Vulnerability.severity == severity)

    query = query.order_by(Vulnerability.created_at.desc())

    # Count
    count_query = select(func.count()).select_from(Vulnerability).where(Vulnerability.scan_id == scan_id)
    if severity:
        count_query = count_query.where(Vulnerability.severity == severity)
    count_result = await db.execute(count_query)
    total = count_result.scalar()

    # Paginate
    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    vulnerabilities = result.scalars().all()

    return {
        "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        "total": total,
        "page": page,
        "per_page": per_page
    }
