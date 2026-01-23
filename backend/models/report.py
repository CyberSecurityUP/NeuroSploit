"""
NeuroSploit v3 - Report Model
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.db.database import Base
import uuid


class Report(Base):
    """Report model"""
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"))

    # Report details
    title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    format: Mapped[str] = mapped_column(String(20), default="html")  # html, pdf, json
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Content
    executive_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Auto-generation flags
    auto_generated: Mapped[bool] = mapped_column(Boolean, default=False)  # True if auto-generated on scan completion/stop
    is_partial: Mapped[bool] = mapped_column(Boolean, default=False)  # True if generated from stopped/incomplete scan

    # Timestamps
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationship
    scan: Mapped["Scan"] = relationship("Scan", back_populates="reports")

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "format": self.format,
            "file_path": self.file_path,
            "executive_summary": self.executive_summary,
            "auto_generated": self.auto_generated,
            "is_partial": self.is_partial,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None
        }
