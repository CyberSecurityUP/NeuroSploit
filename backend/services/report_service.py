"""
NeuroSploit v3 - Report Service

Handles automatic report generation on scan completion/stop.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.models import Scan, Report, Vulnerability
from backend.core.report_engine.generator import ReportGenerator
from backend.api.websocket import manager as ws_manager


class ReportService:
    """Service for automatic report generation"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.generator = ReportGenerator()

    async def auto_generate_report(
        self,
        scan_id: str,
        is_partial: bool = False,
        format: str = "html"
    ) -> Report:
        """
        Automatically generate a report for a scan.

        Args:
            scan_id: The scan ID to generate report for
            is_partial: True if scan was stopped/incomplete
            format: Report format (html, pdf, json)

        Returns:
            The generated Report model instance
        """
        # Get scan
        scan_result = await self.db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()

        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        # Get vulnerabilities
        vulns_result = await self.db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        vulnerabilities = vulns_result.scalars().all()

        # Generate title
        if is_partial:
            title = f"Partial Report - {scan.name or 'Unnamed Scan'}"
        else:
            title = f"Security Assessment Report - {scan.name or 'Unnamed Scan'}"

        # Generate report
        try:
            report_path, executive_summary = await self.generator.generate(
                scan=scan,
                vulnerabilities=vulnerabilities,
                format=format,
                title=title,
                include_executive_summary=True,
                include_poc=True,
                include_remediation=True
            )

            # Create report record
            report = Report(
                scan_id=scan_id,
                title=title,
                format=format,
                file_path=str(report_path) if report_path else None,
                executive_summary=executive_summary,
                auto_generated=True,
                is_partial=is_partial
            )
            self.db.add(report)
            await self.db.commit()
            await self.db.refresh(report)

            # Broadcast report generated event
            await ws_manager.broadcast_report_generated(scan_id, report.to_dict())
            await ws_manager.broadcast_log(
                scan_id,
                "info",
                f"Report auto-generated: {title}"
            )

            return report

        except Exception as e:
            await ws_manager.broadcast_log(
                scan_id,
                "error",
                f"Failed to auto-generate report: {str(e)}"
            )
            raise


async def auto_generate_report(db: AsyncSession, scan_id: str, is_partial: bool = False) -> Report:
    """Helper function to auto-generate a report"""
    service = ReportService(db)
    return await service.auto_generate_report(scan_id, is_partial)
