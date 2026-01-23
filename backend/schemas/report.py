"""
NeuroSploit v3 - Report Schemas
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class ReportGenerate(BaseModel):
    """Schema for generating a report"""
    scan_id: str = Field(..., description="Scan ID to generate report for")
    format: str = Field("html", description="Report format: html, pdf, json")
    title: Optional[str] = Field(None, description="Custom report title")
    include_executive_summary: bool = Field(True, description="Include executive summary")
    include_poc: bool = Field(True, description="Include proof of concept")
    include_remediation: bool = Field(True, description="Include remediation steps")


class ReportResponse(BaseModel):
    """Schema for report response"""
    id: str
    scan_id: str
    title: Optional[str]
    format: str
    file_path: Optional[str]
    executive_summary: Optional[str]
    auto_generated: bool = False
    is_partial: bool = False
    generated_at: datetime

    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    """Schema for list of reports"""
    reports: List[ReportResponse]
    total: int
