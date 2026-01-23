"""
NeuroSploit v3 - Agent Task Schemas
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class AgentTaskCreate(BaseModel):
    """Schema for creating an agent task"""
    scan_id: str = Field(..., description="Scan ID this task belongs to")
    task_type: str = Field(..., description="Task type: recon, analysis, testing, reporting")
    task_name: str = Field(..., description="Human-readable task name")
    description: Optional[str] = Field(None, description="Task description")
    tool_name: Optional[str] = Field(None, description="Tool being used")
    tool_category: Optional[str] = Field(None, description="Tool category")


class AgentTaskUpdate(BaseModel):
    """Schema for updating an agent task"""
    status: Optional[str] = Field(None, description="Task status")
    items_processed: Optional[int] = Field(None, description="Items processed")
    items_found: Optional[int] = Field(None, description="Items found")
    result_summary: Optional[str] = Field(None, description="Result summary")
    error_message: Optional[str] = Field(None, description="Error message if failed")


class AgentTaskResponse(BaseModel):
    """Schema for agent task response"""
    id: str
    scan_id: str
    task_type: str
    task_name: str
    description: Optional[str]
    tool_name: Optional[str]
    tool_category: Optional[str]
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_ms: Optional[int]
    items_processed: int
    items_found: int
    result_summary: Optional[str]
    error_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class AgentTaskListResponse(BaseModel):
    """Schema for list of agent tasks"""
    tasks: List[AgentTaskResponse]
    total: int
    scan_id: str


class AgentTaskSummary(BaseModel):
    """Schema for agent task summary statistics"""
    total: int
    pending: int
    running: int
    completed: int
    failed: int
    by_type: dict  # recon, analysis, testing, reporting counts
    by_tool: dict  # tool name -> count
