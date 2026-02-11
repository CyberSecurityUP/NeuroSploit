"""
NeuroSploit v3 - Vulnerability Lab Challenge Model

Tracks isolated vulnerability testing sessions (labs, CTFs, PortSwigger, etc.)
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from backend.db.database import Base
import uuid


class VulnLabChallenge(Base):
    """Individual vulnerability lab/challenge test record"""
    __tablename__ = "vuln_lab_challenges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Target info
    target_url: Mapped[str] = mapped_column(Text)
    challenge_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Vulnerability scope
    vuln_type: Mapped[str] = mapped_column(String(100))  # e.g. xss_reflected, sqli_union
    vuln_category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # injection, auth, client_side, etc.

    # Authentication
    auth_type: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # cookie, bearer, basic, header
    auth_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Execution state
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, running, completed, failed, stopped
    result: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # detected, not_detected, error

    # Agent linkage
    agent_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Results
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)

    # Findings detail (JSON list of finding summaries)
    findings_detail: Mapped[List] = mapped_column(JSON, default=list)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # seconds

    # Notes
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Logs (JSON list of log entries persisted after completion)
    logs: Mapped[List] = mapped_column(JSON, default=list)

    # Endpoints discovered count
    endpoints_count: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target_url": self.target_url,
            "challenge_name": self.challenge_name,
            "vuln_type": self.vuln_type,
            "vuln_category": self.vuln_category,
            "auth_type": self.auth_type,
            "status": self.status,
            "result": self.result,
            "agent_id": self.agent_id,
            "scan_id": self.scan_id,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "findings_detail": self.findings_detail or [],
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration": self.duration,
            "notes": self.notes,
            "logs": self.logs or [],
            "endpoints_count": self.endpoints_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
