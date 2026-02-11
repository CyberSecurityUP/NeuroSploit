// Scan types
export interface Scan {
  id: string
  name: string | null
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'stopped'
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
  duration: number | null  // Duration in seconds
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
  poc_parameter: string | null
  poc_evidence: string | null
  impact: string | null
  remediation: string | null
  references: string[]
  ai_analysis: string | null
  poc_code?: string | null
  validation_status?: 'ai_confirmed' | 'ai_rejected' | 'validated' | 'false_positive' | 'pending_review'
  ai_rejection_reason?: string | null
  confidence_score?: number            // 0-100 numeric (from agent findings)
  confidence_breakdown?: Record<string, number>
  proof_of_execution?: string
  negative_controls?: string
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
  auto_generated: boolean
  is_partial: boolean
  generated_at: string
}

// Dashboard types
export interface DashboardStats {
  scans: {
    total: number
    running: number
    completed: number
    stopped: number
    failed: number
    pending: number
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

// Scan Agent Task (different from AgentTask which is for the task library)
export interface ScanAgentTask {
  id: string
  scan_id: string
  task_type: 'recon' | 'analysis' | 'testing' | 'reporting'
  task_name: string
  description: string | null
  tool_name: string | null
  tool_category: string | null
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  started_at: string | null
  completed_at: string | null
  duration_ms: number | null
  items_processed: number
  items_found: number
  result_summary: string | null
  error_message: string | null
  created_at: string
}

// Agent types
export type AgentMode = 'full_auto' | 'recon_only' | 'prompt_only' | 'analyze_only' | 'auto_pentest'

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
  subdomain_discovery?: boolean
  targets?: string[]
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
  status: 'running' | 'paused' | 'completed' | 'error' | 'stopped'
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
  rejected_findings_count?: number
  rejected_findings?: AgentFinding[]
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
  confidence_score?: number            // 0-100 numeric
  confidence_breakdown?: Record<string, number>  // Scoring breakdown
  proof_of_execution?: string          // What proof was found
  negative_controls?: string           // Control test results
  ai_status?: 'confirmed' | 'rejected' | 'pending'
  rejection_reason?: string
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

// Agent Role type (from config.json)
export interface AgentRole {
  id: string
  name: string
  description: string
  tools: string[]
}

// Scheduler types
export interface ScheduleJob {
  id: string
  target: string
  scan_type: string
  schedule: string
  status: 'active' | 'paused'
  next_run: string | null
  last_run: string | null
  run_count: number
  agent_role: string | null
  llm_profile: string | null
}

export interface ScheduleJobRequest {
  job_id: string
  target: string
  scan_type: string
  cron_expression?: string
  interval_minutes?: number
  agent_role?: string
  llm_profile?: string
}

// Vulnerability Lab types
export interface VulnLabLogEntry {
  level: string
  message: string
  time: string
  source: string
}

export interface VulnLabChallenge {
  id: string
  target_url: string
  challenge_name: string | null
  vuln_type: string
  vuln_category: string | null
  auth_type: string | null
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'stopped'
  result: 'detected' | 'not_detected' | 'error' | null
  agent_id: string | null
  scan_id: string | null
  findings_count: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  findings_detail: Array<{
    title: string
    vulnerability_type: string
    severity: string
    affected_endpoint: string
    evidence: string
    payload?: string
  }>
  started_at: string | null
  completed_at: string | null
  duration: number | null
  notes: string | null
  logs?: VulnLabLogEntry[]
  logs_count?: number
  endpoints_count?: number
  created_at: string | null
}

export interface VulnLabRunRequest {
  target_url: string
  vuln_type: string
  challenge_name?: string
  auth_type?: string
  auth_value?: string
  custom_headers?: Record<string, string>
  notes?: string
}

export interface VulnLabRunResponse {
  challenge_id: string
  agent_id: string
  status: string
  message: string
}

export interface VulnLabRealtimeStatus {
  challenge_id: string
  status: string
  progress: number
  phase: string
  findings_count: number
  findings: any[]
  logs_count: number
  logs?: VulnLabLogEntry[]
  error: string | null
  result: string | null
  scan_id: string | null
  agent_id: string | null
  vuln_type?: string
  target?: string
  source: string
}

export interface VulnTypeCategory {
  label: string
  types: Array<{
    key: string
    title: string
    severity: string
    cwe_id: string
    description: string
  }>
  count: number
}

export interface VulnLabStats {
  total: number
  running: number
  status_counts: Record<string, number>
  result_counts: Record<string, number>
  detection_rate: number
  by_type: Record<string, { detected: number; not_detected: number; error: number; total: number }>
  by_category: Record<string, { detected: number; not_detected: number; error: number; total: number }>
}

// Sandbox Container types
export interface SandboxContainer {
  scan_id: string
  container_name: string
  available: boolean
  installed_tools: string[]
  created_at: string | null
  uptime_seconds: number
}

export interface SandboxPoolStatus {
  pool: {
    active: number
    max_concurrent: number
    image: string
    container_ttl_minutes: number
    docker_available: boolean
  }
  containers: SandboxContainer[]
  error?: string
}

// Activity Feed types
export interface ActivityFeedItem {
  type: 'scan' | 'vulnerability' | 'agent_task' | 'report'
  action: string
  title: string
  description: string
  status: string | null
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null
  timestamp: string
  scan_id: string
  link: string
}
