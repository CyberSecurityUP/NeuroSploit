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
    db: AsyncSession = Depends(get_db)
):
    """List all reports"""
    query = select(Report).order_by(Report.generated_at.desc())

    if scan_id:
        query = query.where(Report.scan_id == scan_id)

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

    # Generate report
    generator = ReportGenerator()
    report_path, executive_summary = await generator.generate(
        scan=scan,
        vulnerabilities=vulnerabilities,
        format=report_data.format,
        title=report_data.title,
        include_executive_summary=report_data.include_executive_summary,
        include_poc=report_data.include_poc,
        include_remediation=report_data.include_remediation
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
