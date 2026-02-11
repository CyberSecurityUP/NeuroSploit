"""
NeuroSploit v3 - Reports API Endpoints
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pathlib import Path

from backend.db.database import get_db
from backend.models import Scan, Report, Vulnerability
from backend.schemas.report import ReportGenerate, ReportResponse, ReportListResponse
from backend.core.report_engine.generator import ReportGenerator
from backend.config import settings

router = APIRouter()


@router.get("", response_model=ReportListResponse)
async def list_reports(
    scan_id: Optional[str] = None,
    auto_generated: Optional[bool] = None,
    is_partial: Optional[bool] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all reports with optional filtering"""
    query = select(Report).order_by(Report.generated_at.desc())

    if scan_id:
        query = query.where(Report.scan_id == scan_id)

    if auto_generated is not None:
        query = query.where(Report.auto_generated == auto_generated)

    if is_partial is not None:
        query = query.where(Report.is_partial == is_partial)

    result = await db.execute(query)
    reports = result.scalars().all()

    return ReportListResponse(
        reports=[ReportResponse(**r.to_dict()) for r in reports],
        total=len(reports)
    )


@router.post("", response_model=ReportResponse)
async def generate_report(
    report_data: ReportGenerate,
    db: AsyncSession = Depends(get_db)
):
    """Generate a new report for a scan"""
    # Get scan
    scan_result = await db.execute(select(Scan).where(Scan.id == report_data.scan_id))
    scan = scan_result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get vulnerabilities
    vulns_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == report_data.scan_id)
    )
    vulnerabilities = vulns_result.scalars().all()

    # Try to get tool_executions from agent in-memory results
    tool_executions = []
    try:
        from backend.api.v1.agent import scan_to_agent, agent_results
        agent_id = scan_to_agent.get(report_data.scan_id)
        if agent_id and agent_id in agent_results:
            tool_executions = agent_results[agent_id].get("tool_executions", [])
            if not tool_executions:
                rpt = agent_results[agent_id].get("report", {})
                tool_executions = rpt.get("tool_executions", []) if isinstance(rpt, dict) else []
    except Exception:
        pass

    # Generate report
    generator = ReportGenerator()
    report_path, executive_summary = await generator.generate(
        scan=scan,
        vulnerabilities=vulnerabilities,
        format=report_data.format,
        title=report_data.title,
        include_executive_summary=report_data.include_executive_summary,
        include_poc=report_data.include_poc,
        include_remediation=report_data.include_remediation,
        tool_executions=tool_executions,
    )

    # Save report record
    report = Report(
        scan_id=scan.id,
        title=report_data.title or f"Report - {scan.name}",
        format=report_data.format,
        file_path=str(report_path),
        executive_summary=executive_summary
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return ReportResponse(**report.to_dict())


@router.post("/ai-generate", response_model=ReportResponse)
async def generate_ai_report(
    report_data: ReportGenerate,
    db: AsyncSession = Depends(get_db)
):
    """Generate an AI-enhanced report with LLM-written executive summary and per-finding analysis."""
    # Get scan
    scan_result = await db.execute(select(Scan).where(Scan.id == report_data.scan_id))
    scan = scan_result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get vulnerabilities
    vulns_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == report_data.scan_id)
    )
    vulnerabilities = vulns_result.scalars().all()

    # Try to get tool_executions from agent in-memory results
    tool_executions = []
    try:
        from backend.api.v1.agent import scan_to_agent, agent_results
        agent_id = scan_to_agent.get(report_data.scan_id)
        if agent_id and agent_id in agent_results:
            tool_executions = agent_results[agent_id].get("tool_executions", [])
            # Also check nested report
            if not tool_executions:
                rpt = agent_results[agent_id].get("report", {})
                tool_executions = rpt.get("tool_executions", []) if isinstance(rpt, dict) else []
    except Exception:
        pass

    # Generate AI report
    generator = ReportGenerator()
    report_path, ai_summary = await generator.generate_ai_report(
        scan=scan,
        vulnerabilities=vulnerabilities,
        tool_executions=tool_executions,
        title=report_data.title,
    )

    # Save report record
    report = Report(
        scan_id=scan.id,
        title=report_data.title or f"AI Report - {scan.name}",
        format="html",
        file_path=str(report_path),
        executive_summary=ai_summary[:2000] if ai_summary else None
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return ReportResponse(**report.to_dict())


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """Get report details"""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return ReportResponse(**report.to_dict())


@router.get("/{report_id}/view")
async def view_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """View report in browser (HTML)"""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if not report.file_path:
        raise HTTPException(status_code=404, detail="Report file not found")

    file_path = Path(report.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    if report.format == "html":
        content = file_path.read_text()
        return HTMLResponse(content=content)
    else:
        return FileResponse(
            path=str(file_path),
            media_type="application/octet-stream",
            filename=file_path.name
        )


@router.get("/{report_id}/download/{format}")
async def download_report(
    report_id: str,
    format: str,
    db: AsyncSession = Depends(get_db)
):
    """Download report in specified format"""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Get scan and vulnerabilities for generating report
    scan_result = await db.execute(select(Scan).where(Scan.id == report.scan_id))
    scan = scan_result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found for report")

    vulns_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == report.scan_id)
    )
    vulnerabilities = vulns_result.scalars().all()

    # Always generate fresh report file (handles auto-generated reports without file_path)
    generator = ReportGenerator()
    report_path, _ = await generator.generate(
        scan=scan,
        vulnerabilities=vulnerabilities,
        format=format,
        title=report.title
    )
    file_path = Path(report_path)

    # Update report with file path if not set
    if not report.file_path:
        report.file_path = str(file_path)
        report.format = format
        await db.commit()

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")

    media_types = {
        "html": "text/html",
        "pdf": "application/pdf",
        "json": "application/json"
    }

    return FileResponse(
        path=str(file_path),
        media_type=media_types.get(format, "application/octet-stream"),
        filename=file_path.name
    )


@router.get("/{report_id}/download-zip")
async def download_report_zip(
    report_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Download report as ZIP with screenshots included"""
    import zipfile
    import tempfile
    import hashlib

    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    scan_result = await db.execute(select(Scan).where(Scan.id == report.scan_id))
    scan = scan_result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found for report")

    vulns_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == report.scan_id)
    )
    vulnerabilities = vulns_result.scalars().all()

    # Generate HTML report
    generator = ReportGenerator()
    report_path, _ = await generator.generate(
        scan=scan,
        vulnerabilities=vulnerabilities,
        format="html",
        title=report.title
    )

    # Collect screenshots (use absolute path via settings.BASE_DIR)
    # Check scan-scoped path first, then legacy flat path
    screenshots_base = settings.BASE_DIR / "reports" / "screenshots"
    scan_id_str = str(scan.id) if scan else None
    screenshot_files = []
    for vuln in vulnerabilities:
        # Finding ID is md5(vuln_type+url+param)[:8]
        vuln_url = getattr(vuln, 'url', None) or vuln.affected_endpoint or ''
        vuln_param = getattr(vuln, 'parameter', None) or getattr(vuln, 'poc_parameter', None) or ''
        finding_id = hashlib.md5(
            f"{vuln.vulnerability_type}{vuln_url}{vuln_param}".encode()
        ).hexdigest()[:8]
        # Scan-scoped path: reports/screenshots/{scan_id}/{finding_id}/
        finding_dir = None
        if scan_id_str:
            scan_dir = screenshots_base / scan_id_str / finding_id
            if scan_dir.exists():
                finding_dir = scan_dir
        if not finding_dir:
            legacy_dir = screenshots_base / finding_id
            if legacy_dir.exists():
                finding_dir = legacy_dir
        if finding_dir:
            for img in finding_dir.glob("*.png"):
                screenshot_files.append((img, f"screenshots/{finding_id}/{img.name}"))
        # Also include base64 screenshots from DB as files in the ZIP
        db_screenshots = getattr(vuln, 'screenshots', None) or []
        for idx, ss in enumerate(db_screenshots):
            if isinstance(ss, str) and ss.startswith("data:image/"):
                # Will be embedded in HTML, but also save as file
                import base64 as b64
                try:
                    b64_data = ss.split(",", 1)[1]
                    img_bytes = b64.b64decode(b64_data)
                    img_name = f"screenshots/{finding_id}/evidence_{idx+1}.png"
                    # Write to temp for ZIP inclusion
                    tmp_img = Path(tempfile.gettempdir()) / f"ss_{finding_id}_{idx}.png"
                    tmp_img.write_bytes(img_bytes)
                    screenshot_files.append((tmp_img, img_name))
                except Exception:
                    pass

    # Create ZIP
    zip_name = Path(report_path).stem + ".zip"
    zip_path = Path(tempfile.gettempdir()) / zip_name

    with zipfile.ZipFile(str(zip_path), 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(report_path, "report.html")
        for src_path, arc_name in screenshot_files:
            zf.write(str(src_path), arc_name)

    return FileResponse(
        path=str(zip_path),
        media_type="application/zip",
        filename=zip_name
    )


@router.delete("/{report_id}")
async def delete_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a report"""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Delete file if exists
    if report.file_path:
        file_path = Path(report.file_path)
        if file_path.exists():
            file_path.unlink()

    await db.delete(report)
    await db.commit()

    return {"message": "Report deleted"}
