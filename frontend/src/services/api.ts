import axios from 'axios'
import type {
  Scan, Vulnerability, Prompt, PromptPreset, Report, DashboardStats,
  AgentTask, AgentRequest, AgentResponse, AgentStatus, AgentLog, AgentMode,
  ScanAgentTask, ActivityFeedItem, ScheduleJob, ScheduleJobRequest, AgentRole,
  VulnLabChallenge, VulnLabRunRequest, VulnLabRunResponse, VulnLabRealtimeStatus,
  VulnTypeCategory, VulnLabStats, SandboxPoolStatus
} from '../types'

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Scans API
export const scansApi = {
  list: async (page = 1, perPage = 10, status?: string) => {
    const params = new URLSearchParams({ page: String(page), per_page: String(perPage) })
    if (status) params.append('status', status)
    const response = await api.get(`/scans?${params}`)
    return response.data
  },

  get: async (scanId: string): Promise<Scan> => {
    const response = await api.get(`/scans/${scanId}`)
    return response.data
  },

  create: async (data: {
    name?: string
    targets: string[]
    scan_type?: string
    recon_enabled?: boolean
    custom_prompt?: string
    prompt_id?: string
  }): Promise<Scan> => {
    const response = await api.post('/scans', data)
    return response.data
  },

  start: async (scanId: string) => {
    const response = await api.post(`/scans/${scanId}/start`)
    return response.data
  },

  stop: async (scanId: string) => {
    const response = await api.post(`/scans/${scanId}/stop`)
    return response.data
  },

  pause: async (scanId: string) => {
    const response = await api.post(`/scans/${scanId}/pause`)
    return response.data
  },

  resume: async (scanId: string) => {
    const response = await api.post(`/scans/${scanId}/resume`)
    return response.data
  },

  delete: async (scanId: string) => {
    const response = await api.delete(`/scans/${scanId}`)
    return response.data
  },

  skipToPhase: async (scanId: string, phase: string) => {
    const response = await api.post(`/scans/${scanId}/skip-to/${phase}`)
    return response.data
  },

  getEndpoints: async (scanId: string, page = 1, perPage = 50) => {
    const response = await api.get(`/scans/${scanId}/endpoints?page=${page}&per_page=${perPage}`)
    return response.data
  },

  getVulnerabilities: async (scanId: string, severity?: string, page = 1, perPage = 50) => {
    const params = new URLSearchParams({ page: String(page), per_page: String(perPage) })
    if (severity) params.append('severity', severity)
    const response = await api.get(`/scans/${scanId}/vulnerabilities?${params}`)
    return response.data
  },
}

// Targets API
export const targetsApi = {
  validate: async (url: string) => {
    const response = await api.post('/targets/validate', { url })
    return response.data
  },

  validateBulk: async (urls: string[]) => {
    const response = await api.post('/targets/validate/bulk', { urls })
    return response.data
  },

  upload: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/targets/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return response.data
  },
}

// Prompts API
export const promptsApi = {
  getPresets: async (): Promise<PromptPreset[]> => {
    const response = await api.get('/prompts/presets')
    return response.data
  },

  getPreset: async (presetId: string) => {
    const response = await api.get(`/prompts/presets/${presetId}`)
    return response.data
  },

  parse: async (content: string) => {
    const response = await api.post('/prompts/parse', { content })
    return response.data
  },

  list: async (category?: string): Promise<Prompt[]> => {
    const params = category ? `?category=${category}` : ''
    const response = await api.get(`/prompts${params}`)
    return response.data
  },

  create: async (data: { name: string; description?: string; content: string; category?: string }): Promise<Prompt> => {
    const response = await api.post('/prompts', data)
    return response.data
  },

  upload: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/prompts/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return response.data
  },
}

// CLI Agent API
export const cliAgentApi = {
  getProviders: async (): Promise<{ enabled: boolean; providers: Array<{ id: string; name: string; connected: boolean; account_label?: string; source?: string }>; connected_count: number }> => {
    const response = await api.get('/cli-agent/providers')
    return response.data
  },
  getMethodologies: async (): Promise<{ methodologies: Array<{ name: string; path: string; size: number; size_human: string; is_default: boolean }>; total: number }> => {
    const response = await api.get('/cli-agent/methodologies')
    return response.data
  },
}

// Reports API
export const reportsApi = {
  list: async (options?: { scanId?: string; autoGenerated?: boolean }): Promise<{ reports: Report[]; total: number }> => {
    const params = new URLSearchParams()
    if (options?.scanId) params.append('scan_id', options.scanId)
    if (options?.autoGenerated !== undefined) params.append('auto_generated', String(options.autoGenerated))
    const queryString = params.toString()
    const response = await api.get(`/reports${queryString ? `?${queryString}` : ''}`)
    return response.data
  },

  get: async (reportId: string): Promise<Report> => {
    const response = await api.get(`/reports/${reportId}`)
    return response.data
  },

  generate: async (data: {
    scan_id: string
    format?: string
    title?: string
    include_executive_summary?: boolean
    include_poc?: boolean
    include_remediation?: boolean
  }): Promise<Report> => {
    const response = await api.post('/reports', data)
    return response.data
  },

  generateAiReport: async (data: {
    scan_id: string
    title?: string
    preferred_provider?: string
    preferred_model?: string
  }): Promise<Report> => {
    const response = await api.post('/reports/ai-generate', data)
    return response.data
  },

  getViewUrl: (reportId: string) => `/api/v1/reports/${reportId}/view`,

  getDownloadUrl: (reportId: string, format: string) => `/api/v1/reports/${reportId}/download/${format}`,

  getDownloadZipUrl: (reportId: string) => `/api/v1/reports/${reportId}/download-zip`,

  delete: async (reportId: string) => {
    const response = await api.delete(`/reports/${reportId}`)
    return response.data
  },
}

// Dashboard API
export const dashboardApi = {
  getStats: async (): Promise<DashboardStats> => {
    const response = await api.get('/dashboard/stats')
    return response.data
  },

  getRecent: async (limit = 10) => {
    const response = await api.get(`/dashboard/recent?limit=${limit}`)
    return response.data
  },

  getFindings: async (limit = 20, severity?: string) => {
    const params = new URLSearchParams({ limit: String(limit) })
    if (severity) params.append('severity', severity)
    const response = await api.get(`/dashboard/findings?${params}`)
    return response.data
  },

  getVulnerabilityTypes: async () => {
    const response = await api.get('/dashboard/vulnerability-types')
    return response.data
  },

  getAgentTasks: async (limit = 20) => {
    const response = await api.get(`/dashboard/agent-tasks?limit=${limit}`)
    return response.data
  },

  getActivityFeed: async (limit = 30): Promise<{ activities: ActivityFeedItem[]; total: number }> => {
    const response = await api.get(`/dashboard/activity-feed?limit=${limit}`)
    return response.data
  },
}

// Vulnerabilities API
export const vulnerabilitiesApi = {
  getTypes: async () => {
    const response = await api.get('/vulnerabilities/types')
    return response.data
  },

  get: async (vulnId: string): Promise<Vulnerability> => {
    const response = await api.get(`/vulnerabilities/${vulnId}`)
    return response.data
  },

  validate: async (vulnId: string, validationStatus: string, notes?: string) => {
    const response = await api.patch(`/scans/vulnerabilities/${vulnId}/validate`, {
      validation_status: validationStatus,
      notes,
    })
    return response.data
  },

  submitFeedback: async (vulnId: string, isTruePositive: boolean, explanation: string) => {
    const response = await api.post(`/scans/vulnerabilities/${vulnId}/feedback`, {
      is_true_positive: isTruePositive,
      explanation,
    })
    return response.data
  },

  getLearningStats: async () => {
    const response = await api.get('/scans/vulnerabilities/learning/stats')
    return response.data
  },
}

// Scan Agent Tasks API (for tracking scan-specific tasks)
export const agentTasksApi = {
  list: async (scanId: string, status?: string, taskType?: string): Promise<{ tasks: ScanAgentTask[]; total: number; scan_id: string }> => {
    const params = new URLSearchParams()
    params.append('scan_id', scanId)
    if (status) params.append('status', status)
    if (taskType) params.append('task_type', taskType)
    const response = await api.get(`/agent-tasks?${params}`)
    return response.data
  },

  get: async (taskId: string): Promise<ScanAgentTask> => {
    const response = await api.get(`/agent-tasks/${taskId}`)
    return response.data
  },

  getSummary: async (scanId: string): Promise<{
    total: number
    pending: number
    running: number
    completed: number
    failed: number
    by_type: Record<string, number>
    by_tool: Record<string, number>
  }> => {
    const response = await api.get(`/agent-tasks/summary?scan_id=${scanId}`)
    return response.data
  },

  getTimeline: async (scanId: string): Promise<{ scan_id: string; timeline: ScanAgentTask[]; total: number }> => {
    const response = await api.get(`/agent-tasks/scan/${scanId}/timeline`)
    return response.data
  },
}

// Agent API (Autonomous AI Agent like PentAGI)
export const agentApi = {
  // Run the autonomous agent
  run: async (request: AgentRequest): Promise<AgentResponse> => {
    const response = await api.post('/agent/run', request)
    return response.data
  },

  // Get agent status and results
  getStatus: async (agentId: string): Promise<AgentStatus> => {
    const response = await api.get(`/agent/status/${agentId}`)
    return response.data
  },

  // Get agent status by scan_id (reverse lookup)
  getByScan: async (scanId: string): Promise<AgentStatus | null> => {
    try {
      const response = await api.get(`/agent/by-scan/${scanId}`)
      return response.data
    } catch {
      return null
    }
  },

  // Get agent logs
  getLogs: async (agentId: string, limit = 100): Promise<{ agent_id: string; total_logs: number; logs: AgentLog[] }> => {
    const response = await api.get(`/agent/logs/${agentId}?limit=${limit}`)
    return response.data
  },

  // Get findings with details
  getFindings: async (agentId: string) => {
    const response = await api.get(`/agent/findings/${agentId}`)
    return response.data
  },

  // Delete agent results
  delete: async (agentId: string) => {
    const response = await api.delete(`/agent/${agentId}`)
    return response.data
  },

  // Stop a running agent
  stop: async (agentId: string) => {
    const response = await api.post(`/agent/stop/${agentId}`)
    return response.data
  },

  // Pause a running agent
  pause: async (agentId: string) => {
    const response = await api.post(`/agent/pause/${agentId}`)
    return response.data
  },

  // Resume a paused agent
  resume: async (agentId: string) => {
    const response = await api.post(`/agent/resume/${agentId}`)
    return response.data
  },

  // Skip to a specific phase
  skipToPhase: async (agentId: string, phase: string) => {
    const response = await api.post(`/agent/skip-to/${agentId}/${phase}`)
    return response.data
  },

  // Send custom prompt to agent
  sendPrompt: async (agentId: string, prompt: string) => {
    const response = await api.post(`/agent/prompt/${agentId}`, { prompt })
    return response.data
  },

  // One-click auto pentest
  autoPentest: async (target: string, options?: { subdomain_discovery?: boolean; targets?: string[]; auth_type?: string; auth_value?: string; prompt?: string; enable_kali_sandbox?: boolean; custom_prompt_ids?: string[]; preferred_provider?: string; preferred_model?: string; mode?: string; enable_cli_agent?: boolean; cli_agent_provider?: string; methodology_file?: string; selected_md_agents?: string[] }): Promise<AgentResponse> => {
    const response = await api.post('/agent/run', {
      target,
      mode: options?.mode || 'auto_pentest',
      subdomain_discovery: options?.subdomain_discovery || false,
      targets: options?.targets,
      auth_type: options?.auth_type,
      auth_value: options?.auth_value,
      prompt: options?.prompt,
      enable_kali_sandbox: options?.enable_kali_sandbox || false,
      custom_prompt_ids: options?.custom_prompt_ids,
      preferred_provider: options?.preferred_provider || undefined,
      preferred_model: options?.preferred_model || undefined,
      enable_cli_agent: options?.enable_cli_agent || false,
      cli_agent_provider: options?.cli_agent_provider || undefined,
      methodology_file: options?.methodology_file || undefined,
      selected_md_agents: options?.selected_md_agents || undefined,
    })
    return response.data
  },

  // List all active/recent agent sessions
  listActive: async (): Promise<{
    agents: Array<{
      agent_id: string
      target: string
      status: string
      progress: number
      phase: string
      scan_id: string | null
      started_at: string
      findings_count: number
      mode: string
    }>
    max_concurrent: number
    running_count: number
  }> => {
    const response = await api.get('/agent/active')
    return response.data
  },

  // Quick synchronous run (for small targets)
  quickRun: async (target: string, mode: AgentMode = 'full_auto') => {
    const response = await api.post(`/agent/quick?target=${encodeURIComponent(target)}&mode=${mode}`)
    return response.data
  },

  // Get per-vulnerability-type agent statuses (orchestration dashboard)
  getVulnAgents: async (agentId: string) => {
    const response = await api.get(`/agent/vuln-agents/${agentId}`)
    return response.data
  },

  // Task Library
  tasks: {
    list: async (category?: string): Promise<AgentTask[]> => {
      const params = category ? `?category=${category}` : ''
      const response = await api.get(`/agent/tasks${params}`)
      return response.data
    },

    get: async (taskId: string): Promise<AgentTask> => {
      const response = await api.get(`/agent/tasks/${taskId}`)
      return response.data
    },

    create: async (task: {
      name: string
      description: string
      category?: string
      prompt: string
      system_prompt?: string
      tags?: string[]
    }): Promise<{ message: string; task_id: string }> => {
      const response = await api.post('/agent/tasks', task)
      return response.data
    },

    delete: async (taskId: string) => {
      const response = await api.delete(`/agent/tasks/${taskId}`)
      return response.data
    },
  },

  // Real-time Task API
  realtime: {
    createSession: async (target: string, name?: string) => {
      const response = await api.post('/agent/realtime/session', { target, name })
      return response.data
    },

    sendMessage: async (sessionId: string, message: string) => {
      const response = await api.post(`/agent/realtime/${sessionId}/message`, { message })
      return response.data
    },

    getSession: async (sessionId: string) => {
      const response = await api.get(`/agent/realtime/${sessionId}`)
      return response.data
    },

    getReport: async (sessionId: string) => {
      const response = await api.get(`/agent/realtime/${sessionId}/report`)
      return response.data
    },

    deleteSession: async (sessionId: string) => {
      const response = await api.delete(`/agent/realtime/${sessionId}`)
      return response.data
    },

    listSessions: async () => {
      const response = await api.get('/agent/realtime/sessions/list')
      return response.data
    },

    getLlmStatus: async () => {
      const response = await api.get('/agent/realtime/llm-status')
      return response.data
    },

    getReportHtml: async (sessionId: string) => {
      const response = await api.get(`/agent/realtime/${sessionId}/report?format=html`, {
        responseType: 'text'
      })
      return response.data
    },

    getToolsList: async () => {
      const response = await api.get('/agent/realtime/tools/list')
      return response.data
    },

    getToolsStatus: async () => {
      const response = await api.get('/agent/realtime/tools/status')
      return response.data
    },

    executeTool: async (sessionId: string, tool: string, options?: Record<string, any>, timeout?: number) => {
      const response = await api.post(`/agent/realtime/${sessionId}/execute-tool`, {
        tool,
        options,
        timeout: timeout || 300
      })
      return response.data
    },
  },

  // History
  getHistory: async (page = 1, perPage = 20, targetFilter = '') => {
    const params = new URLSearchParams({ page: String(page), per_page: String(perPage) })
    if (targetFilter) params.append('target_filter', targetFilter)
    const response = await api.get(`/agent/history?${params}`)
    return response.data
  },

  // Triple-check
  tripleCheck: async (scanId: string, preferredProvider?: string, preferredModel?: string) => {
    const response = await api.post(`/agent/triple-check/${scanId}`, {
      preferred_provider: preferredProvider || undefined,
      preferred_model: preferredModel || undefined,
    })
    return response.data
  },
}

// Providers API
export const providersApi = {
  list: async () => {
    const response = await api.get('/providers')
    return response.data
  },

  getStatus: async () => {
    const response = await api.get('/providers/status')
    return response.data
  },

  detectAll: async () => {
    const response = await api.post('/providers/detect-all')
    return response.data
  },

  detect: async (providerId: string) => {
    const response = await api.post(`/providers/${providerId}/detect`)
    return response.data
  },

  connect: async (providerId: string, credential: string, label?: string, modelOverride?: string) => {
    const response = await api.post(`/providers/${providerId}/connect`, {
      credential,
      label: label || 'Manual API Key',
      model_override: modelOverride || undefined,
    })
    return response.data
  },

  removeAccount: async (providerId: string, accountId: string) => {
    const response = await api.delete(`/providers/${providerId}/accounts/${accountId}`)
    return response.data
  },

  testConnection: async (providerId: string, accountId: string) => {
    const response = await api.post(`/providers/test/${providerId}/${accountId}`)
    return response.data
  },

  toggle: async (providerId: string, enabled: boolean) => {
    const response = await api.post(`/providers/${providerId}/toggle`, { enabled })
    return response.data
  },

  getAvailableModels: async () => {
    const response = await api.get('/providers/available-models')
    return response.data
  },

  getEnv: async () => {
    const response = await api.get('/providers/env')
    return response.data
  },

  updateEnv: async (key: string, value: string) => {
    const response = await api.post('/providers/env', { key, value })
    return response.data
  },
}

// Vulnerability Lab API
export const vulnLabApi = {
  getTypes: async (): Promise<{ categories: Record<string, VulnTypeCategory>; total_types: number }> => {
    const response = await api.get('/vuln-lab/types')
    return response.data
  },

  run: async (request: VulnLabRunRequest): Promise<VulnLabRunResponse> => {
    const response = await api.post('/vuln-lab/run', request)
    return response.data
  },

  listChallenges: async (filters?: {
    vuln_type?: string
    vuln_category?: string
    status?: string
    result?: string
    limit?: number
  }): Promise<{ challenges: VulnLabChallenge[]; total: number }> => {
    const params = new URLSearchParams()
    if (filters?.vuln_type) params.append('vuln_type', filters.vuln_type)
    if (filters?.vuln_category) params.append('vuln_category', filters.vuln_category)
    if (filters?.status) params.append('status', filters.status)
    if (filters?.result) params.append('result', filters.result)
    if (filters?.limit) params.append('limit', String(filters.limit))
    const qs = params.toString()
    const response = await api.get(`/vuln-lab/challenges${qs ? `?${qs}` : ''}`)
    return response.data
  },

  getChallenge: async (challengeId: string): Promise<VulnLabRealtimeStatus | VulnLabChallenge> => {
    const response = await api.get(`/vuln-lab/challenges/${challengeId}`)
    return response.data
  },

  getStats: async (): Promise<VulnLabStats> => {
    const response = await api.get('/vuln-lab/stats')
    return response.data
  },

  stopChallenge: async (challengeId: string) => {
    const response = await api.post(`/vuln-lab/challenges/${challengeId}/stop`)
    return response.data
  },

  deleteChallenge: async (challengeId: string) => {
    const response = await api.delete(`/vuln-lab/challenges/${challengeId}`)
    return response.data
  },

  getLogs: async (challengeId: string, limit = 100) => {
    const response = await api.get(`/vuln-lab/logs/${challengeId}?limit=${limit}`)
    return response.data
  },
}

// Scheduler API
export const schedulerApi = {
  list: async (): Promise<ScheduleJob[]> => {
    const response = await api.get('/scheduler/')
    return response.data
  },

  create: async (data: ScheduleJobRequest): Promise<ScheduleJob> => {
    const response = await api.post('/scheduler/', data)
    return response.data
  },

  delete: async (jobId: string) => {
    const response = await api.delete(`/scheduler/${jobId}`)
    return response.data
  },

  pause: async (jobId: string) => {
    const response = await api.post(`/scheduler/${jobId}/pause`)
    return response.data
  },

  resume: async (jobId: string) => {
    const response = await api.post(`/scheduler/${jobId}/resume`)
    return response.data
  },

  getAgentRoles: async (): Promise<AgentRole[]> => {
    const response = await api.get('/scheduler/agent-roles')
    return response.data
  },
}

// Terminal Agent API
export const terminalApi = {
  createSession: async (target: string, name?: string, template_id?: string) => {
    const response = await api.post('/terminal/session', { target, name, template_id })
    return response.data
  },

  listSessions: async () => {
    const response = await api.get('/terminal/sessions')
    return response.data
  },

  getSession: async (sessionId: string) => {
    const response = await api.get(`/terminal/sessions/${sessionId}`)
    return response.data
  },

  deleteSession: async (sessionId: string) => {
    const response = await api.delete(`/terminal/sessions/${sessionId}`)
    return response.data
  },

  sendMessage: async (sessionId: string, message: string) => {
    const response = await api.post(`/terminal/sessions/${sessionId}/message`, { message })
    return response.data
  },

  executeCommand: async (sessionId: string, command: string, execution_method: string) => {
    const response = await api.post(`/terminal/sessions/${sessionId}/execute`, { command, execution_method })
    return response.data
  },

  addExploitationStep: async (sessionId: string, step: { description: string; command: string; result: string; step_type: string }) => {
    const response = await api.post(`/terminal/sessions/${sessionId}/exploitation-path`, step)
    return response.data
  },

  getExploitationPath: async (sessionId: string) => {
    const response = await api.get(`/terminal/sessions/${sessionId}/exploitation-path`)
    return response.data
  },

  getVpnStatus: async (sessionId: string) => {
    const response = await api.get(`/terminal/sessions/${sessionId}/vpn-status`)
    return response.data
  },

  listTemplates: async () => {
    const response = await api.get('/terminal/templates')
    return response.data
  },

  // VPN management
  uploadVpnConfig: async (
    sessionId: string,
    file: File,
    username?: string,
    password?: string,
  ) => {
    const formData = new FormData()
    formData.append('ovpn_file', file)
    if (username) formData.append('username', username)
    if (password) formData.append('password', password)
    const response = await api.post(
      `/terminal/sessions/${sessionId}/vpn/upload`,
      formData,
      { headers: { 'Content-Type': 'multipart/form-data' } },
    )
    return response.data
  },

  connectVpn: async (sessionId: string) => {
    const response = await api.post(`/terminal/sessions/${sessionId}/vpn/connect`)
    return response.data
  },

  disconnectVpn: async (sessionId: string) => {
    const response = await api.post(`/terminal/sessions/${sessionId}/vpn/disconnect`)
    return response.data
  },
}

// Sandbox API
export const sandboxApi = {
  list: async (): Promise<SandboxPoolStatus> => {
    const response = await api.get('/sandbox/')
    return response.data
  },

  healthCheck: async (scanId: string) => {
    const response = await api.get(`/sandbox/${scanId}`)
    return response.data
  },

  destroy: async (scanId: string) => {
    const response = await api.delete(`/sandbox/${scanId}`)
    return response.data
  },

  cleanup: async () => {
    const response = await api.post('/sandbox/cleanup')
    return response.data
  },

  cleanupOrphans: async () => {
    const response = await api.post('/sandbox/cleanup-orphans')
    return response.data
  },
}

// Knowledge API
export const knowledgeApi = {
  upload: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/knowledge/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return response.data
  },

  listDocuments: async () => {
    const response = await api.get('/knowledge/documents')
    return response.data
  },

  getDocument: async (docId: string) => {
    const response = await api.get(`/knowledge/documents/${docId}`)
    return response.data
  },

  deleteDocument: async (docId: string) => {
    const response = await api.delete(`/knowledge/documents/${docId}`)
    return response.data
  },

  search: async (vulnType: string) => {
    const response = await api.get(`/knowledge/search?vuln_type=${encodeURIComponent(vulnType)}`)
    return response.data
  },

  getStats: async () => {
    const response = await api.get('/knowledge/stats')
    return response.data
  },
}

// MCP Servers API
export const mcpApi = {
  listServers: async () => {
    const response = await api.get('/mcp/servers')
    return response.data
  },

  getServer: async (name: string) => {
    const response = await api.get(`/mcp/servers/${encodeURIComponent(name)}`)
    return response.data
  },

  createServer: async (data: { name: string; transport: string; command?: string; args?: string[]; url?: string; env?: Record<string, string>; description?: string }) => {
    const response = await api.post('/mcp/servers', data)
    return response.data
  },

  updateServer: async (name: string, data: Record<string, unknown>) => {
    const response = await api.put(`/mcp/servers/${encodeURIComponent(name)}`, data)
    return response.data
  },

  deleteServer: async (name: string) => {
    const response = await api.delete(`/mcp/servers/${encodeURIComponent(name)}`)
    return response.data
  },

  toggleServer: async (name: string) => {
    const response = await api.post(`/mcp/servers/${encodeURIComponent(name)}/toggle`)
    return response.data
  },

  testServer: async (name: string) => {
    const response = await api.post(`/mcp/servers/${encodeURIComponent(name)}/test`)
    return response.data
  },

  listTools: async (name: string) => {
    const response = await api.get(`/mcp/servers/${encodeURIComponent(name)}/tools`)
    return response.data
  },
}

export default api
