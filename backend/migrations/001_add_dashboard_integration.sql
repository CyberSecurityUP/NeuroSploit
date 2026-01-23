-- Migration: Add Dashboard Integration Columns
-- Date: 2026-01-23
-- Description: Adds duration column to scans, auto_generated/is_partial to reports, and creates agent_tasks table

-- Add duration column to scans table
ALTER TABLE scans ADD COLUMN duration INTEGER;

-- Add auto_generated and is_partial columns to reports table
ALTER TABLE reports ADD COLUMN auto_generated BOOLEAN DEFAULT 0;
ALTER TABLE reports ADD COLUMN is_partial BOOLEAN DEFAULT 0;

-- Create agent_tasks table
CREATE TABLE IF NOT EXISTS agent_tasks (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL,
    task_type VARCHAR(50) NOT NULL,
    task_name VARCHAR(255) NOT NULL,
    description TEXT,
    tool_name VARCHAR(100),
    tool_category VARCHAR(100),
    status VARCHAR(20) DEFAULT 'pending',
    started_at DATETIME,
    completed_at DATETIME,
    duration_ms INTEGER,
    items_processed INTEGER DEFAULT 0,
    items_found INTEGER DEFAULT 0,
    result_summary TEXT,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_agent_tasks_scan_id ON agent_tasks(scan_id);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_status ON agent_tasks(status);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_task_type ON agent_tasks(task_type);
