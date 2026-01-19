import { useEffect, useState, useRef } from 'react'
import {
  MessageSquare, Send, Target, Shield, Trash2,
  RefreshCw, XCircle, Globe, Bot, ChevronDown, ChevronRight, Plus,
  Terminal, Zap, Search, AlertCircle, CheckCircle2, FileText, Wrench,
  ExternalLink, Code
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { SeverityBadge } from '../components/common/Badge'
import { agentApi } from '../services/api'
import type { RealtimeSession, RealtimeMessage, RealtimeSessionSummary } from '../types'

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-gray-500'
}

export default function RealtimeTaskPage() {
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // Session state
  const [sessions, setSessions] = useState<RealtimeSessionSummary[]>([])
  const [activeSession, setActiveSession] = useState<RealtimeSession | null>(null)
  const [error, setError] = useState<string | null>(null)

  // New session form
  const [showNewSession, setShowNewSession] = useState(false)
  const [newTarget, setNewTarget] = useState('')
  const [newSessionName, setNewSessionName] = useState('')
  const [isCreating, setIsCreating] = useState(false)

  // Chat state
  const [message, setMessage] = useState('')
  const [isSending, setIsSending] = useState(false)
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set())
  const [expandedMessages, setExpandedMessages] = useState<Set<number>>(new Set())

  // LLM status
  const [llmStatus, setLlmStatus] = useState<{
    available: boolean
    provider: string | null
    error: string | null
  } | null>(null)

  // Tools state
  const [showToolsModal, setShowToolsModal] = useState(false)
  const [toolsStatus, setToolsStatus] = useState<{ available: boolean; docker_status: string } | null>(null)
  const [executingTool, setExecutingTool] = useState<string | null>(null)

  // Report state
  const [generatingReport, setGeneratingReport] = useState(false)

  // Message truncation config
  const MESSAGE_MAX_LENGTH = 600

  // Quick prompts for common tasks
  const quickPrompts = [
    { label: 'Security Headers', prompt: 'Analyze security headers and identify misconfigurations', icon: '🛡️' },
    { label: 'Full Scan', prompt: 'Perform a comprehensive security assessment including headers, cookies, CORS, and endpoint discovery', icon: '🔍' },
    { label: 'XSS Test', prompt: 'Test for Cross-Site Scripting (XSS) vulnerabilities in all input fields', icon: '💉' },
    { label: 'SQL Injection', prompt: 'Check for SQL injection vulnerabilities in parameters and forms', icon: '🗃️' },
    { label: 'Directory Enum', prompt: 'Discover hidden directories, files, and endpoints using common wordlists', icon: '📁' },
    { label: 'Tech Stack', prompt: 'Detect technologies, frameworks, and versions used by this application', icon: '⚙️' },
  ]

  // Tool categories with icons
  const toolPrompts = [
    { tool: 'ffuf', label: 'FFUF', description: 'Fast web fuzzer', icon: '⚡' },
    { tool: 'feroxbuster', label: 'Feroxbuster', description: 'Directory brute-force', icon: '🦀' },
    { tool: 'nuclei', label: 'Nuclei', description: 'Vulnerability scanner', icon: '☢️' },
    { tool: 'nmap', label: 'Nmap', description: 'Port scanner', icon: '🔌' },
    { tool: 'nikto', label: 'Nikto', description: 'Web server scanner', icon: '🕷️' },
    { tool: 'httpx', label: 'HTTPX', description: 'HTTP toolkit', icon: '🌐' },
  ]

  // Load sessions and check status on mount
  useEffect(() => {
    loadSessions()
    checkLlmStatus()
    loadToolsInfo()
  }, [])

  const checkLlmStatus = async () => {
    try {
      const status = await agentApi.realtime.getLlmStatus()
      setLlmStatus({
        available: status.available,
        provider: status.provider,
        error: status.error
      })
    } catch (err) {
      console.error('Failed to check LLM status:', err)
      setLlmStatus({
        available: false,
        provider: null,
        error: 'Failed to connect to backend'
      })
    }
  }

  const loadToolsInfo = async () => {
    try {
      const status = await agentApi.realtime.getToolsStatus()
      setToolsStatus(status)
    } catch (err) {
      console.error('Failed to load tools info:', err)
    }
  }

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [activeSession?.messages])

  const loadSessions = async () => {
    try {
      const data = await agentApi.realtime.listSessions()
      setSessions(data.sessions || [])
    } catch (err) {
      console.error('Failed to load sessions:', err)
    }
  }

  const createSession = async () => {
    if (!newTarget.trim()) return
    setIsCreating(true)
    setError(null)

    try {
      const result = await agentApi.realtime.createSession(newTarget, newSessionName || undefined)
      await loadSessions()
      await loadSession(result.session_id)
      setShowNewSession(false)
      setNewTarget('')
      setNewSessionName('')
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create session')
    } finally {
      setIsCreating(false)
    }
  }

  const loadSession = async (sessionId: string) => {
    setError(null)

    try {
      const data = await agentApi.realtime.getSession(sessionId)
      setActiveSession(data)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load session')
    }
  }

  const sendMessage = async (prompt?: string) => {
    const messageToSend = prompt || message
    if (!messageToSend.trim() || !activeSession) return

    setIsSending(true)
    setMessage('')

    // Optimistically add user message
    const userMessage: RealtimeMessage = {
      role: 'user',
      content: messageToSend,
      timestamp: new Date().toISOString()
    }

    setActiveSession(prev => prev ? {
      ...prev,
      messages: [...prev.messages, userMessage]
    } : null)

    try {
      const result = await agentApi.realtime.sendMessage(activeSession.session_id, messageToSend)

      // Add assistant response
      const assistantMessage: RealtimeMessage = {
        role: 'assistant',
        content: result.response,
        timestamp: new Date().toISOString(),
        metadata: { tests_executed: result.tests_executed }
      }

      setActiveSession(prev => prev ? {
        ...prev,
        messages: [...prev.messages, assistantMessage],
        findings: result.findings || prev.findings
      } : null)

      // Focus input for next message
      inputRef.current?.focus()
    } catch (err: any) {
      // Add error message
      const errorMessage: RealtimeMessage = {
        role: 'assistant',
        content: `Error: ${err.response?.data?.detail || err.message || 'Failed to send message'}`,
        timestamp: new Date().toISOString(),
        metadata: { error: true }
      }

      setActiveSession(prev => prev ? {
        ...prev,
        messages: [...prev.messages, errorMessage]
      } : null)
    } finally {
      setIsSending(false)
    }
  }

  const executeTool = async (toolId: string) => {
    if (!activeSession) return

    setExecutingTool(toolId)
    setShowToolsModal(false)

    // Add user message about tool execution
    const userMessage: RealtimeMessage = {
      role: 'user',
      content: `Execute ${toolId} scan on target`,
      timestamp: new Date().toISOString()
    }

    setActiveSession(prev => prev ? {
      ...prev,
      messages: [...prev.messages, userMessage]
    } : null)

    try {
      await agentApi.realtime.executeTool(activeSession.session_id, toolId)

      // Reload session to get updated messages and findings
      await loadSession(activeSession.session_id)
    } catch (err: any) {
      const errorMessage: RealtimeMessage = {
        role: 'assistant',
        content: `Tool execution failed: ${err.response?.data?.detail || err.message}`,
        timestamp: new Date().toISOString(),
        metadata: { error: true }
      }

      setActiveSession(prev => prev ? {
        ...prev,
        messages: [...prev.messages, errorMessage]
      } : null)
    } finally {
      setExecutingTool(null)
    }
  }

  const deleteSession = async (sessionId: string) => {
    if (!confirm('Delete this session?')) return

    try {
      await agentApi.realtime.deleteSession(sessionId)
      if (activeSession?.session_id === sessionId) {
        setActiveSession(null)
      }
      await loadSessions()
    } catch (err) {
      console.error('Failed to delete session:', err)
    }
  }

  const downloadReportHtml = async () => {
    if (!activeSession) return

    setGeneratingReport(true)
    try {
      const htmlContent = await agentApi.realtime.getReportHtml(activeSession.session_id)

      // Open in new tab
      const newWindow = window.open('', '_blank')
      if (newWindow) {
        newWindow.document.write(htmlContent)
        newWindow.document.close()
      }
    } catch (err) {
      console.error('Failed to generate HTML report:', err)
    } finally {
      setGeneratingReport(false)
    }
  }

  const downloadReportJson = async () => {
    if (!activeSession) return

    try {
      const report = await agentApi.realtime.getReport(activeSession.session_id)
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `report-${activeSession.session_id}-${new Date().toISOString().split('T')[0]}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Failed to generate report:', err)
    }
  }

  const toggleFinding = (index: number) => {
    const newExpanded = new Set(expandedFindings)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedFindings(newExpanded)
  }

  const toggleMessage = (index: number) => {
    const newExpanded = new Set(expandedMessages)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedMessages(newExpanded)
  }

  const renderMessage = (msg: RealtimeMessage, index: number) => {
    const isUser = msg.role === 'user'
    const isError = msg.metadata?.error
    const isApiError = msg.metadata?.api_error
    const isToolExecution = msg.metadata?.tool_execution
    const isExpanded = expandedMessages.has(index)
    const shouldTruncate = !isUser && msg.content.length > MESSAGE_MAX_LENGTH && !isExpanded

    const displayContent = shouldTruncate
      ? msg.content.substring(0, MESSAGE_MAX_LENGTH) + '...'
      : msg.content

    return (
      <div
        key={index}
        className={`flex ${isUser ? 'justify-end' : 'justify-start'} animate-fadeIn`}
      >
        <div
          className={`max-w-[85%] rounded-xl px-4 py-3 shadow-lg overflow-hidden ${
            isUser
              ? 'bg-gradient-to-r from-primary-600 to-primary-500 text-white'
              : isError || isApiError
              ? 'bg-red-500/10 border border-red-500/30 text-red-300'
              : isToolExecution
              ? 'bg-purple-500/10 border border-purple-500/30 text-purple-200'
              : 'bg-dark-800/80 border border-dark-700 text-dark-200'
          }`}
        >
          {!isUser && (
            <div className="flex items-center gap-2 mb-2 text-xs text-dark-400">
              {isToolExecution ? (
                <Wrench className="w-3 h-3 text-purple-400" />
              ) : (
                <Bot className="w-3 h-3" />
              )}
              <span>{isToolExecution ? 'Tool Execution' : 'NeuroSploit AI'}</span>
              {isApiError && (
                <span className="bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded text-[10px]">
                  API Error
                </span>
              )}
              {msg.metadata?.tests_executed && (
                <span className="bg-green-500/20 text-green-400 px-1.5 py-0.5 rounded text-[10px]">
                  Tests Executed
                </span>
              )}
              {msg.metadata?.new_findings && msg.metadata.new_findings > 0 && (
                <span className="bg-orange-500/20 text-orange-400 px-1.5 py-0.5 rounded text-[10px]">
                  +{msg.metadata.new_findings} findings
                </span>
              )}
            </div>
          )}
          <div className="whitespace-pre-wrap text-sm leading-relaxed prose prose-invert prose-sm max-w-none break-words overflow-x-auto">
            {displayContent}
          </div>
          {!isUser && msg.content.length > MESSAGE_MAX_LENGTH && (
            <button
              onClick={() => toggleMessage(index)}
              className="mt-3 text-xs text-primary-400 hover:text-primary-300 transition-colors flex items-center gap-1 font-medium"
            >
              {isExpanded ? (
                <>
                  <ChevronDown className="w-3 h-3" />
                  Show less
                </>
              ) : (
                <>
                  <ChevronRight className="w-3 h-3" />
                  Show more ({Math.ceil((msg.content.length - MESSAGE_MAX_LENGTH) / 100) * 100}+ chars)
                </>
              )}
            </button>
          )}
          <div className={`text-[10px] mt-2 ${isUser ? 'text-primary-200' : 'text-dark-500'}`}>
            {new Date(msg.timestamp).toLocaleTimeString()}
          </div>
        </div>
      </div>
    )
  }

  const sortedFindings = activeSession?.findings
    ? [...activeSession.findings].sort((a, b) =>
        (SEVERITY_ORDER[a.severity] || 4) - (SEVERITY_ORDER[b.severity] || 4)
      )
    : []

  // Calculate severity stats
  const severityStats = sortedFindings.reduce((acc, f) => {
    const sev = f.severity?.toLowerCase() || 'info'
    acc[sev] = (acc[sev] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <Zap className="w-7 h-7 text-yellow-500" />
            Real-time Task
          </h2>
          <p className="text-dark-400 mt-1">
            Interactive AI-powered security testing with real tool execution
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {/* LLM Status Indicator */}
          {llmStatus && (
            <div
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs cursor-help ${
                llmStatus.available
                  ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                  : 'bg-red-500/20 text-red-400 border border-red-500/30'
              }`}
              title={llmStatus.error || `Connected to ${llmStatus.provider}`}
            >
              {llmStatus.available ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span className="font-medium">{llmStatus.provider?.toUpperCase()}</span>
                </>
              ) : (
                <>
                  <AlertCircle className="w-3.5 h-3.5" />
                  <span>No AI</span>
                </>
              )}
            </div>
          )}
          {/* Docker Status */}
          {toolsStatus && (
            <div
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs cursor-help ${
                toolsStatus.available
                  ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                  : 'bg-dark-700 text-dark-400 border border-dark-600'
              }`}
              title={toolsStatus.available ? 'Docker tools ready' : 'Docker not available'}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>{toolsStatus.available ? 'Tools Ready' : 'No Docker'}</span>
            </div>
          )}
          <Button onClick={() => setShowNewSession(true)}>
            <Plus className="w-4 h-4 mr-2" />
            New Session
          </Button>
        </div>
      </div>

      {/* New Session Modal */}
      {showNewSession && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <Card className="w-full max-w-md mx-4 shadow-2xl">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Target className="w-5 h-5 text-primary-500" />
              Create New Session
            </h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm text-dark-300 mb-1">Target URL *</label>
                <input
                  type="text"
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full bg-dark-800 border border-dark-600 rounded-lg px-4 py-2.5 text-white placeholder-dark-400 focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500"
                  autoFocus
                />
              </div>

              <div>
                <label className="block text-sm text-dark-300 mb-1">Session Name (optional)</label>
                <input
                  type="text"
                  value={newSessionName}
                  onChange={(e) => setNewSessionName(e.target.value)}
                  placeholder="My Security Test"
                  className="w-full bg-dark-800 border border-dark-600 rounded-lg px-4 py-2.5 text-white placeholder-dark-400 focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500"
                />
              </div>

              {error && (
                <div className="text-red-400 text-sm flex items-center gap-2 bg-red-500/10 p-3 rounded-lg">
                  <XCircle className="w-4 h-4 flex-shrink-0" />
                  {error}
                </div>
              )}

              <div className="flex justify-end gap-2 pt-2">
                <Button variant="secondary" onClick={() => setShowNewSession(false)}>
                  Cancel
                </Button>
                <Button onClick={createSession} isLoading={isCreating} disabled={!newTarget.trim()}>
                  Create Session
                </Button>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Tools Modal */}
      {showToolsModal && activeSession && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <Card className="w-full max-w-2xl mx-4 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Wrench className="w-5 h-5 text-purple-500" />
                Execute Security Tool
              </h3>
              <button onClick={() => setShowToolsModal(false)} className="text-dark-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <p className="text-dark-400 text-sm mb-4">
              Target: <span className="text-white font-mono">{activeSession.target}</span>
            </p>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {toolPrompts.map((tool) => (
                <button
                  key={tool.tool}
                  onClick={() => executeTool(tool.tool)}
                  disabled={executingTool !== null || !toolsStatus?.available}
                  className="p-4 bg-dark-800 hover:bg-dark-700 border border-dark-600 hover:border-purple-500/50 rounded-xl transition-all text-left disabled:opacity-50 disabled:cursor-not-allowed group"
                >
                  <div className="text-2xl mb-2">{tool.icon}</div>
                  <div className="font-medium text-white group-hover:text-purple-400 transition-colors">
                    {tool.label}
                  </div>
                  <div className="text-xs text-dark-400 mt-1">{tool.description}</div>
                </button>
              ))}
            </div>

            {!toolsStatus?.available && (
              <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm">
                <AlertCircle className="w-4 h-4 inline mr-2" />
                Docker is not available. Tools require Docker to be running.
              </div>
            )}
          </Card>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Sessions List */}
        <div className="lg:col-span-1">
          <Card title="Sessions" className="h-fit">
            <div className="space-y-2 max-h-[400px] overflow-y-auto">
              {sessions.length === 0 ? (
                <p className="text-dark-400 text-sm text-center py-4">
                  No sessions yet. Create one to start testing.
                </p>
              ) : (
                sessions.map((s) => (
                  <div
                    key={s.session_id}
                    className={`p-3 rounded-xl cursor-pointer transition-all ${
                      activeSession?.session_id === s.session_id
                        ? 'bg-primary-500/20 border border-primary-500/50 shadow-lg shadow-primary-500/10'
                        : 'bg-dark-800/50 hover:bg-dark-800 border border-transparent hover:border-dark-600'
                    }`}
                    onClick={() => loadSession(s.session_id)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1 min-w-0">
                        <p className="text-white font-medium truncate text-sm">{s.name}</p>
                        <p className="text-dark-400 text-xs truncate flex items-center gap-1 mt-0.5">
                          <Globe className="w-3 h-3" />
                          {s.target}
                        </p>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          deleteSession(s.session_id)
                        }}
                        className="p-1.5 text-dark-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                    <div className="flex items-center gap-2 mt-2 text-xs">
                      <span className="text-dark-400">{s.messages_count} msgs</span>
                      {s.findings_count > 0 && (
                        <span className="bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full font-medium">
                          {s.findings_count} findings
                        </span>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>

        {/* Chat Area */}
        <div className="lg:col-span-2">
          {activeSession ? (
            <Card className="flex flex-col h-[calc(100vh-220px)]">
              {/* Session Header */}
              <div className="flex items-center justify-between pb-4 border-b border-dark-700">
                <div className="flex-1 min-w-0">
                  <h3 className="text-white font-medium flex items-center gap-2">
                    <Target className="w-4 h-4 text-primary-500 flex-shrink-0" />
                    <span className="truncate">{activeSession.name}</span>
                  </h3>
                  <p className="text-dark-400 text-sm truncate">{activeSession.target}</p>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => setShowToolsModal(true)}
                    disabled={executingTool !== null}
                  >
                    <Wrench className="w-4 h-4 mr-1" />
                    Tools
                  </Button>
                  <div className="relative group">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={downloadReportHtml}
                      isLoading={generatingReport}
                    >
                      <FileText className="w-4 h-4 mr-1" />
                      Report
                    </Button>
                    {/* Dropdown for report options */}
                    <div className="absolute right-0 mt-1 w-40 bg-dark-800 border border-dark-600 rounded-lg shadow-xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                      <button
                        onClick={downloadReportHtml}
                        className="w-full px-3 py-2 text-left text-sm text-dark-300 hover:bg-dark-700 hover:text-white rounded-t-lg flex items-center gap-2"
                      >
                        <ExternalLink className="w-3 h-3" />
                        Open HTML Report
                      </button>
                      <button
                        onClick={downloadReportJson}
                        className="w-full px-3 py-2 text-left text-sm text-dark-300 hover:bg-dark-700 hover:text-white rounded-b-lg flex items-center gap-2"
                      >
                        <Code className="w-3 h-3" />
                        Download JSON
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Messages */}
              <div className="flex-1 overflow-y-auto py-4 space-y-4 scroll-smooth">
                {activeSession.messages.length === 0 ? (
                  <div className="text-center py-12">
                    <MessageSquare className="w-12 h-12 text-dark-600 mx-auto mb-3" />
                    <p className="text-dark-400">
                      Start by typing a security testing instruction or use a quick prompt
                    </p>
                  </div>
                ) : (
                  activeSession.messages.map((msg, i) => renderMessage(msg, i))
                )}
                {(isSending || executingTool) && (
                  <div className="flex justify-start">
                    <div className="bg-dark-800 border border-dark-700 rounded-xl px-4 py-3 flex items-center gap-3 text-dark-400">
                      <RefreshCw className="w-4 h-4 animate-spin text-primary-500" />
                      <span>{executingTool ? `Running ${executingTool}...` : 'Analyzing and testing...'}</span>
                    </div>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>

              {/* Quick Prompts */}
              <div className="flex flex-wrap gap-2 py-3 border-t border-dark-700">
                {quickPrompts.map((qp, i) => (
                  <button
                    key={i}
                    onClick={() => sendMessage(qp.prompt)}
                    disabled={isSending || executingTool !== null}
                    className="px-3 py-1.5 text-xs bg-dark-800 hover:bg-dark-700 text-dark-300 hover:text-white rounded-full transition-all disabled:opacity-50 flex items-center gap-1.5 border border-dark-700 hover:border-dark-600"
                  >
                    <span>{qp.icon}</span>
                    {qp.label}
                  </button>
                ))}
              </div>

              {/* Input */}
              <div className="flex gap-2 pt-2">
                <input
                  ref={inputRef}
                  type="text"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && sendMessage()}
                  placeholder="Type your security testing instruction..."
                  disabled={isSending || executingTool !== null}
                  className="flex-1 bg-dark-800 border border-dark-600 rounded-xl px-4 py-3 text-white placeholder-dark-400 focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500 disabled:opacity-50"
                />
                <Button
                  onClick={() => sendMessage()}
                  isLoading={isSending}
                  disabled={!message.trim() || executingTool !== null}
                  className="px-4"
                >
                  <Send className="w-4 h-4" />
                </Button>
              </div>
            </Card>
          ) : (
            <Card className="flex flex-col items-center justify-center h-[calc(100vh-220px)]">
              <div className="text-center">
                <div className="w-20 h-20 bg-gradient-to-br from-primary-500/20 to-purple-500/20 rounded-2xl flex items-center justify-center mx-auto mb-6">
                  <Terminal className="w-10 h-10 text-primary-400" />
                </div>
                <h3 className="text-white text-lg font-medium mb-2">No Session Selected</h3>
                <p className="text-dark-400 text-center mb-6 max-w-sm">
                  Select a session from the list or create a new one to start interactive security testing
                </p>
                <Button onClick={() => setShowNewSession(true)} className="mx-auto">
                  <Plus className="w-4 h-4 mr-2" />
                  Create New Session
                </Button>
              </div>
            </Card>
          )}
        </div>

        {/* Findings Panel */}
        <div className="lg:col-span-1 space-y-4">
          {/* Severity Summary */}
          {sortedFindings.length > 0 && (
            <Card className="!p-3">
              <div className="flex items-center gap-2 flex-wrap">
                {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
                  const count = severityStats[sev] || 0
                  if (count === 0) return null
                  return (
                    <div
                      key={sev}
                      className={`px-2 py-1 rounded-lg text-xs font-medium flex items-center gap-1 ${
                        sev === 'critical' ? 'bg-red-500/20 text-red-400' :
                        sev === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        sev === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        sev === 'low' ? 'bg-blue-500/20 text-blue-400' :
                        'bg-gray-500/20 text-gray-400'
                      }`}
                    >
                      <span className={`w-2 h-2 rounded-full ${SEVERITY_COLORS[sev]}`} />
                      {count} {sev}
                    </div>
                  )
                })}
              </div>
            </Card>
          )}

          <Card
            title={
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-red-400" />
                <span>Findings</span>
                {sortedFindings.length > 0 && (
                  <span className="bg-red-500/20 text-red-400 text-xs px-2 py-0.5 rounded-full font-medium">
                    {sortedFindings.length}
                  </span>
                )}
              </div>
            }
            className="h-fit max-h-[calc(100vh-320px)] overflow-y-auto"
          >
            {sortedFindings.length === 0 ? (
              <div className="text-center py-8">
                <Search className="w-8 h-8 text-dark-600 mx-auto mb-2" />
                <p className="text-dark-400 text-sm">
                  No findings yet. Send a testing instruction to discover vulnerabilities.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {sortedFindings.map((finding, i) => (
                  <div
                    key={i}
                    className="bg-dark-900/50 rounded-xl border border-dark-700 overflow-hidden hover:border-dark-600 transition-colors"
                  >
                    <div
                      className="p-3 cursor-pointer hover:bg-dark-800/50 transition-colors"
                      onClick={() => toggleFinding(i)}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-start gap-2 flex-1 min-w-0">
                          {expandedFindings.has(i) ? (
                            <ChevronDown className="w-4 h-4 mt-0.5 text-dark-400 flex-shrink-0" />
                          ) : (
                            <ChevronRight className="w-4 h-4 mt-0.5 text-dark-400 flex-shrink-0" />
                          )}
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-white truncate">{finding.title}</p>
                            <div className="flex items-center gap-2 mt-0.5">
                              <p className="text-xs text-dark-400 truncate flex-1">{finding.affected_endpoint}</p>
                              {finding.cvss_score && (
                                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                                  finding.cvss_score >= 9.0 ? 'bg-red-500/20 text-red-400' :
                                  finding.cvss_score >= 7.0 ? 'bg-orange-500/20 text-orange-400' :
                                  finding.cvss_score >= 4.0 ? 'bg-yellow-500/20 text-yellow-400' :
                                  'bg-blue-500/20 text-blue-400'
                                }`}>
                                  {finding.cvss_score}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <SeverityBadge severity={finding.severity} />
                      </div>
                    </div>

                    {expandedFindings.has(i) && (
                      <div className="px-3 pb-3 pt-0 space-y-3 border-t border-dark-700 overflow-hidden">
                        {/* CVSS/CWE/OWASP badges */}
                        {(finding.cvss_score || finding.cwe_id || finding.owasp) && (
                          <div className="mt-3 flex flex-wrap gap-2">
                            {finding.cvss_score && (
                              <div className="bg-dark-800 px-2 py-1 rounded text-xs">
                                <span className="text-dark-500">CVSS:</span>{' '}
                                <span className={`font-bold ${
                                  finding.cvss_score >= 9.0 ? 'text-red-400' :
                                  finding.cvss_score >= 7.0 ? 'text-orange-400' :
                                  finding.cvss_score >= 4.0 ? 'text-yellow-400' :
                                  'text-blue-400'
                                }`}>{finding.cvss_score}</span>
                              </div>
                            )}
                            {finding.cwe_id && (
                              <div className="bg-dark-800 px-2 py-1 rounded text-xs">
                                <span className="text-dark-500">CWE:</span>{' '}
                                <span className="text-blue-400">{finding.cwe_id}</span>
                              </div>
                            )}
                            {finding.owasp && (
                              <div className="bg-dark-800 px-2 py-1 rounded text-xs">
                                <span className="text-dark-500">OWASP:</span>{' '}
                                <span className="text-yellow-400 truncate">{finding.owasp.split(' - ')[0]}</span>
                              </div>
                            )}
                          </div>
                        )}
                        <div className="mt-3">
                          <p className="text-[10px] text-dark-500 uppercase tracking-wider font-medium">Type</p>
                          <p className="text-sm text-dark-300 break-words">{finding.vulnerability_type}</p>
                        </div>
                        <div>
                          <p className="text-[10px] text-dark-500 uppercase tracking-wider font-medium">Description</p>
                          <p className="text-sm text-dark-300 break-words">{finding.description}</p>
                        </div>
                        {finding.evidence && (
                          <div>
                            <p className="text-[10px] text-dark-500 uppercase tracking-wider font-medium">Evidence</p>
                            <p className="text-sm text-dark-300 font-mono bg-dark-800 p-2 rounded-lg text-xs overflow-x-auto break-all max-h-32 overflow-y-auto">
                              {finding.evidence}
                            </p>
                          </div>
                        )}
                        <div>
                          <p className="text-[10px] text-dark-500 uppercase tracking-wider font-medium">Remediation</p>
                          <p className="text-sm text-green-400 break-words">{finding.remediation}</p>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Technologies Detected */}
          {activeSession && activeSession.recon_data?.technologies && activeSession.recon_data.technologies.length > 0 && (
            <Card title="Technologies" className="!p-4">
              <div className="flex flex-wrap gap-2">
                {activeSession.recon_data.technologies.map((tech, i) => (
                  <span
                    key={i}
                    className="px-2.5 py-1 text-xs bg-dark-800 text-dark-300 rounded-lg border border-dark-700"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
