"""
NeuroSploit v3 - Prompt Model
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Boolean, DateTime, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column
from backend.db.database import Base
import uuid


class Prompt(Base):
    """Prompt model for storing custom and preset prompts"""
    __tablename__ = "prompts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content: Mapped[str] = mapped_column(Text)

    # Categorization
    is_preset: Mapped[bool] = mapped_column(Boolean, default=False)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # pentest, bug_bounty, api, etc.

    # Parsed vulnerabilities (extracted by AI)
    parsed_vulnerabilities: Mapped[List] = mapped_column(JSON, default=list)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "content": self.content,
            "is_preset": self.is_preset,
            "category": self.category,
            "parsed_vulnerabilities": self.parsed_vulnerabilities,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
