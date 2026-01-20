"""
NeuroSploit v3 - Prompt Schemas
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class PromptCreate(BaseModel):
    """Schema for creating a prompt"""
    name: str = Field(..., max_length=255, description="Prompt name")
    description: Optional[str] = Field(None, description="Prompt description")
    content: str = Field(..., min_length=10, description="Prompt content")
    category: Optional[str] = Field(None, description="Prompt category")


class PromptUpdate(BaseModel):
    """Schema for updating a prompt"""
    name: Optional[str] = None
    description: Optional[str] = None
    content: Optional[str] = None
    category: Optional[str] = None


class PromptParse(BaseModel):
    """Schema for parsing a prompt"""
    content: str = Field(..., min_length=10, description="Prompt content to parse")


class VulnerabilityTypeExtracted(BaseModel):
    """Extracted vulnerability type from prompt"""
    type: str
    category: str
    confidence: float
    context: Optional[str] = None


class TestingScope(BaseModel):
    """Testing scope extracted from prompt"""
    include_recon: bool = True
    depth: str = "standard"  # quick, standard, thorough, exhaustive
    max_requests_per_endpoint: Optional[int] = None
    time_limit_minutes: Optional[int] = None


class PromptParseResult(BaseModel):
    """Result of prompt parsing"""
    vulnerabilities_to_test: List[VulnerabilityTypeExtracted]
    testing_scope: TestingScope
    special_instructions: List[str] = []
    target_filters: dict = {}
    output_preferences: dict = {}


class PromptResponse(BaseModel):
    """Schema for prompt response"""
    id: str
    name: str
    description: Optional[str]
    content: str
    is_preset: bool
    category: Optional[str]
    parsed_vulnerabilities: List
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PromptPreset(BaseModel):
    """Schema for preset prompt"""
    id: str
    name: str
    description: str
    category: str
    vulnerability_count: int
