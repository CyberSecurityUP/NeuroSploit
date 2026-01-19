// Scan types
export interface Scan {
  id: string
  name: string | null
  status: 'pending' | 'running' | 'completed' | 'failed' | 'stopped'
  scan_type: 'quick' | 'full' | 'custom'
  recon_enabled: boolean
  progress: number
  current_phase: string | null
  config: Record<string, unknown>
  custom_prompt: string | null
  prompt_id: string | null
  created_at: string
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  total_endpoints: number
  total_vulnerabilities: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  targets: Target[]
}

export interface Target {
  id: string
  scan_id: string
  url: string
  hostname: string | null
  port: number | null
  protocol: string | null
  path: string | null
  status: string
  created_at: string
}

// Vulnerability types
export interface Vulnerability {
  id: string
  scan_id: string
  title: string
  vulnerability_type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  cvss_score: number | null
  cvss_vector: string | null
  cwe_id: string | null
  description: string | null
  affected_endpoint: string | null
  poc_request: string | null
  poc_response: string | null
  poc_payload: string | null
  impact: string | null
  remediation: string | null
  references: string[]
  ai_analysis: string | null
  created_at: string
}

// Endpoint types
export interface Endpoint {
  id: string
  scan_id: string
  url: string
  method: string
  path: string | null
  parameters: unknown[]
  response_status: number | null
  content_type: string | null
  technologies: string[]
  discovered_at: string
}

// Prompt types
export interface Prompt {
  id: string
  name: string
  description: string | null
  content: string
  is_preset: boolean
  category: string | null
  parsed_vulnerabilities: unknown[]
  created_at: string
  updated_at: string
}

export interface PromptPreset {
  id: string
  name: string
  description: string
  category: string
  vulnerability_count: number
}

// Report types
export interface Report {
  id: string
  scan_id: string
  title: string | null
  format: 'html' | 'pdf' | 'json'
  file_path: string | null
  executive_summary: string | null
  generated_at: string
}

// Dashboard types
export interface DashboardStats {
  scans: {
    total: number
    running: number
    completed: number
    recent: number
  }
  vulnerabilities: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
    recent: number
  }
  endpoints: {
    total: number
  }
}

// WebSocket message types
export interface WSMessage {
  type: string
  scan_id: string
  [key: string]: unknown
}

// Agent types
export type AgentMode = 'full_auto' | 'recon_only' | 'prompt_only' | 'analyze_only'

export interface AgentTask {
  id: string
  name: string
  description: string
  category: string
  prompt: string
  system_prompt?: string
  tools_required: string[]
  tags: string[]
  is_preset: boolean
  estimated_tokens: number
  created_at?: string
  updated_at?: string
}

export interface AgentRequest {
  target: string
  mode: AgentMode
  task_id?: string
  prompt?: string
  auth_type?: 'cookie' | 'bearer' | 'basic' | 'header'
  auth_value?: string
  custom_headers?: Record<string, string>
  max_depth?: number
}

export interface AgentResponse {
  agent_id: string
  status: string
  mode: string
  message: string
}

export interface AgentStatus {
  agent_id: string
  scan_id?: string  // Link to database scan
  status: 'running' | 'completed' | 'error' | 'stopped'
  mode: string
  target: string
  task?: string
  progress: number
  phase: string
  started_at?: string
  completed_at?: string
  logs_count: number
  findings_count: number
  findings: AgentFinding[]
  report?: AgentReport
  error?: string
}

export interface AgentFinding {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  vulnerability_type: string
  cvss_score: number
  cvss_vector: string
  cwe_id: string
  description: string
  affected_endpoint: string
  parameter?: string
  payload?: string
  evidence?: string
  request?: string
  response?: string
  impact: string
  poc_code: string
  remediation: string
  references: string[]
  ai_verified: boolean
  confidence?: string
}

export interface AgentReport {
  summary: {
    target: string
    mode: string
    duration: string
    total_findings: number
    severity_breakdown: Record<string, number>
  }
  findings: AgentFinding[]
  recommendations: string[]
  executive_summary?: string
}

export interface AgentLog {
  level: string
  message: string
  time: string
  source?: 'script' | 'llm'  // Identifies if log is from script or LLM
}

// Real-time Task types
export interface RealtimeMessageMetadata {
  error?: boolean
  api_error?: boolean
  tests_executed?: boolean
  new_findings?: number
  provider?: string
  tool_execution?: boolean
  tool?: string
}

export interface RealtimeMessage {
  role: 'user' | 'assistant' | 'system' | 'tool'
  content: string
  timestamp: string
  metadata?: RealtimeMessageMetadata
}

export interface RealtimeSession {
  session_id: string
  name: string
  target: string
  status: 'active' | 'completed' | 'error'
  created_at: string
  messages: RealtimeMessage[]
  findings: RealtimeFinding[]
  recon_data: {
    endpoints: Array<{ url: string; status: number; path: string }>
    parameters: Record<string, string[]>
    technologies: string[]
    headers: Record<string, string>
  }
}

export interface RealtimeFinding {
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  vulnerability_type: string
  description: string
  affected_endpoint: string
  remediation: string
  evidence?: string
  references?: string[]
  cvss_score?: number
  cvss_vector?: string
  cwe_id?: string
  owasp?: string
  impact?: string
}

export interface RealtimeSessionSummary {
  session_id: string
  name: string
  target: string
  status: string
  created_at: string
  findings_count: number
  messages_count: number
}
