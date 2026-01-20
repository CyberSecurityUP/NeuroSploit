"""
NeuroSploit v3 - Endpoint Model
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.db.database import Base
import uuid


class Endpoint(Base):
    """Discovered endpoint model"""
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"))
    target_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)

    # Endpoint details
    url: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(10), default="GET")
    path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Parameters
    parameters: Mapped[List] = mapped_column(JSON, default=list)  # [{name, type, value}]
    headers: Mapped[dict] = mapped_column(JSON, default=dict)

    # Response info
    response_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    content_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Detection
    technologies: Mapped[List] = mapped_column(JSON, default=list)
    interesting: Mapped[bool] = mapped_column(default=False)  # Marked as interesting for testing

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="endpoints")

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "target_id": self.target_id,
            "url": self.url,
            "method": self.method,
            "path": self.path,
            "parameters": self.parameters,
            "headers": self.headers,
            "response_status": self.response_status,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "technologies": self.technologies,
            "interesting": self.interesting,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None
        }
