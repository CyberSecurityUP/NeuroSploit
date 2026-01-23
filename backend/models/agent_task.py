"""
NeuroSploit v3 - Agent Task Model

Tracks all agent activities during scans for dashboard visibility.
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.db.database import Base
import uuid


class AgentTask(Base):
    """Agent task record for tracking scan activities"""
    __tablename__ = "agent_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"))

    # Task identification
    task_type: Mapped[str] = mapped_column(String(50))  # recon, analysis, testing, reporting
    task_name: Mapped[str] = mapped_column(String(255))  # Human-readable name
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Tool information
    tool_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # nmap, nuclei, claude, httpx, etc.
    tool_category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # scanner, analyzer, ai, crawler

    # Status tracking
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, running, completed, failed, cancelled

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # Duration in milliseconds

    # Results
    items_processed: Mapped[int] = mapped_column(Integer, default=0)  # URLs tested, hosts scanned, etc.
    items_found: Mapped[int] = mapped_column(Integer, default=0)  # Endpoints found, vulns found, etc.
    result_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Brief summary of results

    # Error handling
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="agent_tasks")

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "task_type": self.task_type,
            "task_name": self.task_name,
            "description": self.description,
            "tool_name": self.tool_name,
            "tool_category": self.tool_category,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
            "items_processed": self.items_processed,
            "items_found": self.items_found,
            "result_summary": self.result_summary,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

    def start(self):
        """Mark task as started"""
        self.status = "running"
        self.started_at = datetime.utcnow()

    def complete(self, items_processed: int = 0, items_found: int = 0, summary: str = None):
        """Mark task as completed"""
        self.status = "completed"
        self.completed_at = datetime.utcnow()
        self.items_processed = items_processed
        self.items_found = items_found
        self.result_summary = summary
        if self.started_at:
            self.duration_ms = int((self.completed_at - self.started_at).total_seconds() * 1000)

    def fail(self, error: str):
        """Mark task as failed"""
        self.status = "failed"
        self.completed_at = datetime.utcnow()
        self.error_message = error
        if self.started_at:
            self.duration_ms = int((self.completed_at - self.started_at).total_seconds() * 1000)
