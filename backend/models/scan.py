"""
NeuroSploit v3 - Scan Model
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, Boolean, DateTime, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.db.database import Base
import uuid


class Scan(Base):
    """Scan model representing a penetration test scan"""
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, running, completed, failed, stopped
    scan_type: Mapped[str] = mapped_column(String(50), default="full")  # quick, full, custom
    recon_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Progress tracking
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_phase: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # recon, testing, reporting

    # Configuration
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    # Custom prompt (if any)
    custom_prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    prompt_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # Authentication for testing (IMPORTANT: Use responsibly with authorization)
    auth_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # none, cookie, header, basic, bearer
    auth_credentials: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # Stores auth data securely
    custom_headers: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # Additional HTTP headers

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # Duration in seconds

    # Error handling
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Statistics (updated during scan)
    total_endpoints: Mapped[int] = mapped_column(Integer, default=0)
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    targets: Mapped[List["Target"]] = relationship("Target", back_populates="scan", cascade="all, delete-orphan")
    endpoints: Mapped[List["Endpoint"]] = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[List["Report"]] = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    agent_tasks: Mapped[List["AgentTask"]] = relationship("AgentTask", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "scan_type": self.scan_type,
            "recon_enabled": self.recon_enabled,
            "progress": self.progress,
            "current_phase": self.current_phase,
            "config": self.config,
            "custom_prompt": self.custom_prompt,
            "prompt_id": self.prompt_id,
            "auth_type": self.auth_type,
            "auth_credentials": self.auth_credentials,  # Careful: may contain sensitive data
            "custom_headers": self.custom_headers,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration": self.duration,
            "error_message": self.error_message,
            "total_endpoints": self.total_endpoints,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count
        }
