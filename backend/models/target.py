"""
NeuroSploit v3 - Target Model
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.db.database import Base
import uuid


class Target(Base):
    """Target URL model"""
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"))

    # URL details
    url: Mapped[str] = mapped_column(String(2048))
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)

    # Status
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, scanning, completed, failed

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationship
    scan: Mapped["Scan"] = relationship("Scan", back_populates="targets")

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "url": self.url,
            "hostname": self.hostname,
            "port": self.port,
            "protocol": self.protocol,
            "path": self.path,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
