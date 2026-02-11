import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  FlaskConical, ChevronDown, ChevronUp, Loader2, Lock,
  AlertTriangle, CheckCircle2, XCircle, Play, Square,
  Trash2, Eye, Search, BarChart3, Clock, Target,
  Terminal, Shield, Globe, FileText, ChevronRight
} from 'lucide-react'
import { vulnLabApi } from '../services/api'
import type { VulnTypeCategory, VulnLabChallenge, VulnLabStats, VulnLabLogEntry } from '../types'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-gray-500',
}

const RESULT_BADGE: Record<string, { bg: string; text: string; label: string }> = {
  detected: { bg: 'bg-green-500/20', text: 'text-green-400', label: 'Detected' },
  not_detected: { bg: 'bg-red-500/20', text: 'text-red-400', label: 'Not Detected' },
  error: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'Error' },
}

const STATUS_BADGE: Record<string, { bg: string; text: string }> = {
  running: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  completed: { bg: 'bg-green-500/20', text: 'text-green-400' },
  failed: { bg: 'bg-red-500/20', text: 'text-red-400' },
  stopped: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  pending: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
}

const LOG_LEVEL_COLORS: Record<string, string> = {
  error: 'text-red-400',
  warning: 'text-yellow-400',
  info: 'text-blue-300',
  debug: 'text-dark-500',
  critical: 'text-red-500 font-bold',
}

function LogLine({ log }: { log: VulnLabLogEntry }) {
  const color = LOG_LEVEL_COLORS[log.level] || 'text-dark-400'
  const time = log.time ? new Date(log.time).toLocaleTimeString() : ''
  const isLlm = log.source === 'llm'

  return (
    <div className={`flex gap-2 text-xs font-mono leading-relaxed ${color}`}>
      <span className="text-dark-600 shrink-0 w-16">{time}</span>
      <span className={`shrink-0 w-12 uppercase ${
        log.level === 'error' ? 'text-red-500' :
        log.level === 'warning' ? 'text-yellow-500' :
        'text-dark-600'
      }`}>{log.level}</span>
      {isLlm && <span className="text-purple-500 shrink-0">[AI]</span>}
      <span className="break-all">{log.message}</span>
    </div>
  )
}

export default function VulnLabPage() {
  const navigate = useNavigate()

  // Form state
  const [targetUrl, setTargetUrl] = useState('')
  const [challengeName, setChallengeName] = useState('')
  const [selectedVulnType, setSelectedVulnType] = useState('')
  const [showAuth, setShowAuth] = useState(false)
  const [authType, setAuthType] = useState('')
  const [authValue, setAuthValue] = useState('')
  const [notes, setNotes] = useState('')
  const [searchFilter, setSearchFilter] = useState('')

  // Data state
  const [categories, setCategories] = useState<Record<string, VulnTypeCategory>>({})
  const [expandedCat, setExpandedCat] = useState<string | null>(null)
  const [challenges, setChallenges] = useState<VulnLabChallenge[]>([])
  const [stats, setStats] = useState<VulnLabStats | null>(null)

  // Running state
  const [isRunning, setIsRunning] = useState(false)
  const [runningChallengeId, setRunningChallengeId] = useState<string | null>(null)
  const [runningStatus, setRunningStatus] = useState<any>(null)
  const [runningLogs, setRunningLogs] = useState<VulnLabLogEntry[]>([])
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'test' | 'history' | 'stats'>('test')
  const [showLogs, setShowLogs] = useState(true)
  const [logFilter, setLogFilter] = useState<'all' | 'info' | 'warning' | 'error'>('all')

  // History expansion state
  const [expandedChallenge, setExpandedChallenge] = useState<string | null>(null)
  const [expandedChallengeData, setExpandedChallengeData] = useState<any>(null)
  const [loadingChallenge, setLoadingChallenge] = useState(false)

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const logsEndRef = useRef<HTMLDivElement>(null)
  const autoScrollRef = useRef(true)

  // Load vuln types on mount
  useEffect(() => {
    vulnLabApi.getTypes().then(data => {
      setCategories(data.categories)
    }).catch(() => {})

    loadChallenges()
    loadStats()
  }, [])

  // Auto-scroll logs
  useEffect(() => {
    if (autoScrollRef.current && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [runningLogs])

  // Poll running challenge (3s for faster updates)
  useEffect(() => {
    if (!runningChallengeId || !isRunning) return

    const poll = async () => {
      try {
        const s = await vulnLabApi.getChallenge(runningChallengeId)
        setRunningStatus(s)
        if (s.logs) setRunningLogs(s.logs)
        if (['completed', 'failed', 'stopped', 'error'].includes(s.status)) {
          setIsRunning(false)
          if (pollRef.current) clearInterval(pollRef.current)
          loadChallenges()
          loadStats()
        }
      } catch {}
    }

    poll()
    pollRef.current = setInterval(poll, 3000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [runningChallengeId, isRunning])

  const loadChallenges = async () => {
    try {
      const data = await vulnLabApi.listChallenges({ limit: 50 })
      setChallenges(data.challenges)
    } catch {}
  }

  const loadStats = async () => {
    try {
      const data = await vulnLabApi.getStats()
      setStats(data)
    } catch {}
  }

  const handleStart = async () => {
    if (!targetUrl.trim() || !selectedVulnType) return

    setError(null)
    setIsRunning(true)
    setRunningStatus(null)
    setRunningLogs([])
    setShowLogs(true)

    try {
      const resp = await vulnLabApi.run({
        target_url: targetUrl.trim(),
        vuln_type: selectedVulnType,
        challenge_name: challengeName || undefined,
        auth_type: authType || undefined,
        auth_value: authValue || undefined,
        notes: notes || undefined,
      })
      setRunningChallengeId(resp.challenge_id)
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to start test')
      setIsRunning(false)
    }
  }

  const handleStop = async () => {
    if (!runningChallengeId) return
    try {
      await vulnLabApi.stopChallenge(runningChallengeId)
      setIsRunning(false)
    } catch {}
  }

  const handleDelete = async (id: string) => {
    try {
      await vulnLabApi.deleteChallenge(id)
      if (expandedChallenge === id) {
        setExpandedChallenge(null)
        setExpandedChallengeData(null)
      }
      loadChallenges()
      loadStats()
    } catch {}
  }

  const toggleChallengeExpand = useCallback(async (challengeId: string) => {
    if (expandedChallenge === challengeId) {
      setExpandedChallenge(null)
      setExpandedChallengeData(null)
      return
    }

    setExpandedChallenge(challengeId)
    setLoadingChallenge(true)
    try {
      const data = await vulnLabApi.getChallenge(challengeId)
      setExpandedChallengeData(data)
    } catch {
      setExpandedChallengeData(null)
    } finally {
      setLoadingChallenge(false)
    }
  }, [expandedChallenge])

  // Get selected vuln type info
  const getSelectedVulnInfo = () => {
    for (const cat of Object.values(categories)) {
      const found = cat.types.find(t => t.key === selectedVulnType)
      if (found) return found
    }
    return null
  }

  const selectedInfo = getSelectedVulnInfo()

  // Filter vuln types by search
  const filteredCategories = Object.entries(categories).map(([key, cat]) => {
    const filtered = searchFilter
      ? cat.types.filter(t =>
          t.key.includes(searchFilter.toLowerCase()) ||
          t.title.toLowerCase().includes(searchFilter.toLowerCase())
        )
      : cat.types
    return { key, ...cat, types: filtered }
  }).filter(c => c.types.length > 0)

  const formatDuration = (seconds: number | null | undefined) => {
    if (!seconds) return '-'
    if (seconds < 60) return `${seconds}s`
    const m = Math.floor(seconds / 60)
    const s = seconds % 60
    return `${m}m ${s}s`
  }

  // Filter running logs
  const filteredLogs = logFilter === 'all'
    ? runningLogs
    : runningLogs.filter(l => l.level === logFilter)

  return (
    <div className="min-h-screen flex flex-col items-center py-8 px-4">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-purple-500/20 rounded-2xl mb-4">
          <FlaskConical className="w-8 h-8 text-purple-400" />
        </div>
        <h1 className="text-3xl font-bold text-white mb-2">Vulnerability Lab</h1>
        <p className="text-dark-400 max-w-lg">
          Test individual vulnerability types against labs, CTFs, and PortSwigger challenges.
          Track detection performance per vuln type.
        </p>
      </div>

      {/* Tab Bar */}
      <div className="flex gap-2 mb-6">
        {[
          { key: 'test' as const, label: 'New Test', icon: Play },
          { key: 'history' as const, label: 'History', icon: Clock },
          { key: 'stats' as const, label: 'Stats', icon: BarChart3 },
        ].map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium transition-colors ${
              activeTab === tab.key
                ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                : 'bg-dark-800 text-dark-400 border border-dark-700 hover:text-white'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* ========== NEW TEST TAB ========== */}
      {activeTab === 'test' && (
        <div className="w-full max-w-3xl">
          <div className="bg-dark-800 border border-dark-700 rounded-2xl p-8">
            {/* Target URL */}
            <div className="mb-6">
              <label className="block text-sm font-medium text-dark-300 mb-2">Target URL</label>
              <input
                type="url"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                placeholder="https://lab.example.com/vuln-page"
                disabled={isRunning}
                className="w-full px-4 py-4 bg-dark-900 border border-dark-600 rounded-xl text-white text-lg placeholder-dark-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500 disabled:opacity-50"
              />
            </div>

            {/* Challenge Name (optional) */}
            <div className="mb-6">
              <label className="block text-sm font-medium text-dark-300 mb-2">Challenge Name (optional)</label>
              <input
                type="text"
                value={challengeName}
                onChange={e => setChallengeName(e.target.value)}
                placeholder={selectedVulnType?.startsWith('xss')
                  ? 'e.g. "Reflected XSS with most tags and attributes blocked"'
                  : "e.g. PortSwigger Lab: Reflected XSS into HTML context"}
                disabled={isRunning}
                className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white placeholder-dark-500 focus:outline-none focus:border-purple-500 disabled:opacity-50"
              />
            </div>

            {/* Vulnerability Type Selector */}
            <div className="mb-6">
              <label className="block text-sm font-medium text-dark-300 mb-2">
                Vulnerability Type {selectedInfo && (
                  <span className={`ml-2 px-2 py-0.5 rounded text-xs ${SEVERITY_COLORS[selectedInfo.severity]} text-white`}>
                    {selectedInfo.severity}
                  </span>
                )}
              </label>

              {/* Search */}
              <div className="relative mb-3">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-500" />
                <input
                  type="text"
                  value={searchFilter}
                  onChange={e => setSearchFilter(e.target.value)}
                  placeholder="Search vuln types..."
                  disabled={isRunning}
                  className="w-full pl-10 pr-4 py-2.5 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm placeholder-dark-500 focus:outline-none focus:border-purple-500 disabled:opacity-50"
                />
              </div>

              {/* Selected indicator */}
              {selectedInfo && (
                <div className="mb-3 p-3 bg-purple-500/10 border border-purple-500/20 rounded-lg flex items-center justify-between">
                  <div>
                    <span className="text-purple-400 font-medium">{selectedInfo.title}</span>
                    {selectedInfo.cwe_id && (
                      <span className="ml-2 text-dark-500 text-xs">{selectedInfo.cwe_id}</span>
                    )}
                  </div>
                  <button
                    onClick={() => setSelectedVulnType('')}
                    disabled={isRunning}
                    className="text-dark-500 hover:text-white text-xs"
                  >
                    Clear
                  </button>
                </div>
              )}

              {/* Category accordion */}
              <div className="max-h-80 overflow-y-auto border border-dark-600 rounded-xl bg-dark-900">
                {filteredCategories.map(cat => (
                  <div key={cat.key} className="border-b border-dark-700 last:border-b-0">
                    <button
                      onClick={() => setExpandedCat(expandedCat === cat.key ? null : cat.key)}
                      disabled={isRunning}
                      className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-dark-300 hover:text-white hover:bg-dark-800 transition-colors disabled:opacity-50"
                    >
                      <span>{cat.label} ({cat.types.length})</span>
                      {expandedCat === cat.key ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                    {expandedCat === cat.key && (
                      <div className="px-2 pb-2">
                        {cat.types.map(vtype => (
                          <button
                            key={vtype.key}
                            onClick={() => setSelectedVulnType(vtype.key)}
                            disabled={isRunning}
                            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-colors disabled:opacity-50 ${
                              selectedVulnType === vtype.key
                                ? 'bg-purple-500/20 text-purple-400'
                                : 'text-dark-400 hover:bg-dark-800 hover:text-white'
                            }`}
                          >
                            <span className="text-left">{vtype.title}</span>
                            <div className="flex items-center gap-2">
                              {vtype.cwe_id && <span className="text-dark-600 text-xs">{vtype.cwe_id}</span>}
                              <span className={`w-2 h-2 rounded-full ${SEVERITY_COLORS[vtype.severity]}`} />
                            </div>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Auth Section */}
            <div className="mb-6">
              <button
                onClick={() => setShowAuth(!showAuth)}
                disabled={isRunning}
                className="flex items-center gap-2 text-sm text-dark-400 hover:text-white transition-colors disabled:opacity-50"
              >
                <Lock className="w-4 h-4" />
                <span>Authentication (Optional)</span>
                {showAuth ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
              {showAuth && (
                <div className="mt-3 space-y-3 pl-6">
                  <select
                    value={authType}
                    onChange={e => setAuthType(e.target.value)}
                    disabled={isRunning}
                    className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm focus:outline-none focus:border-purple-500"
                  >
                    <option value="">No Authentication</option>
                    <option value="bearer">Bearer Token</option>
                    <option value="cookie">Cookie</option>
                    <option value="basic">Basic Auth (user:pass)</option>
                    <option value="header">Custom Header (Name:Value)</option>
                  </select>
                  {authType && (
                    <input
                      type="text"
                      value={authValue}
                      onChange={e => setAuthValue(e.target.value)}
                      disabled={isRunning}
                      placeholder={
                        authType === 'bearer' ? 'eyJhbGciOiJIUzI1NiIs...' :
                        authType === 'cookie' ? 'session=abc123; token=xyz' :
                        authType === 'basic' ? 'admin:password123' :
                        'X-API-Key:your-api-key'
                      }
                      className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm placeholder-dark-500 focus:outline-none focus:border-purple-500"
                    />
                  )}
                </div>
              )}
            </div>

            {/* Notes */}
            <div className="mb-6">
              <label className="block text-sm font-medium text-dark-300 mb-2">Notes (optional)</label>
              <textarea
                value={notes}
                onChange={e => setNotes(e.target.value)}
                rows={2}
                disabled={isRunning}
                placeholder={selectedVulnType?.startsWith('xss')
                  ? "Hints: blocked chars/tags, encoding observed, context (e.g. 'angle brackets HTML-encoded, input in onclick attribute')"
                  : "e.g. PortSwigger Apprentice level, no WAF"}
                className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white placeholder-dark-500 focus:outline-none focus:border-purple-500 disabled:opacity-50"
              />
            </div>

            {/* Error */}
            {error && (
              <div className="mb-6 p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                <span className="text-red-400 text-sm">{error}</span>
              </div>
            )}

            {/* Start/Stop */}
            {!isRunning ? (
              <button
                onClick={handleStart}
                disabled={!targetUrl.trim() || !selectedVulnType}
                className="w-full py-4 bg-purple-500 hover:bg-purple-600 disabled:bg-dark-600 disabled:text-dark-400 text-white font-bold text-lg rounded-xl transition-colors flex items-center justify-center gap-3"
              >
                <FlaskConical className="w-6 h-6" />
                START TEST
              </button>
            ) : (
              <button
                onClick={handleStop}
                className="w-full py-4 bg-red-500 hover:bg-red-600 text-white font-bold text-lg rounded-xl transition-colors flex items-center justify-center gap-3"
              >
                <Square className="w-6 h-6" />
                STOP TEST
              </button>
            )}
          </div>

          {/* Running Progress + Live Logs */}
          {runningStatus && (
            <div className="mt-6 space-y-4">
              {/* Status Card */}
              <div className="bg-dark-800 border border-dark-700 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-white font-semibold flex items-center gap-2">
                    {runningStatus.status === 'running' && <Loader2 className="w-5 h-5 animate-spin text-purple-400" />}
                    {runningStatus.status === 'completed' && <CheckCircle2 className="w-5 h-5 text-green-400" />}
                    {['failed', 'error'].includes(runningStatus.status) && <XCircle className="w-5 h-5 text-red-400" />}
                    {runningStatus.status === 'stopped' && <Square className="w-5 h-5 text-orange-400" />}
                    {selectedInfo?.title || selectedVulnType}
                  </h3>
                  <span className="text-sm text-dark-400">{runningStatus.progress || 0}%</span>
                </div>

                {/* Progress bar */}
                <div className="w-full bg-dark-900 rounded-full h-2 mb-4">
                  <div
                    className={`h-2 rounded-full transition-all duration-500 ${
                      runningStatus.status === 'completed' ? 'bg-green-500' :
                      runningStatus.status === 'error' || runningStatus.status === 'failed' ? 'bg-red-500' :
                      'bg-purple-500'
                    }`}
                    style={{ width: `${runningStatus.progress || 0}%` }}
                  />
                </div>

                {/* Info row */}
                <div className="flex items-center gap-4 text-sm text-dark-400 mb-3">
                  {runningStatus.phase && (
                    <span className="flex items-center gap-1">
                      <Shield className="w-3.5 h-3.5" />
                      {runningStatus.phase}
                    </span>
                  )}
                  <span className="flex items-center gap-1">
                    <Terminal className="w-3.5 h-3.5" />
                    {runningLogs.length} log entries
                  </span>
                  {runningStatus.findings_count > 0 && (
                    <span className="flex items-center gap-1 text-green-400">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      {runningStatus.findings_count} finding(s)
                    </span>
                  )}
                </div>

                {/* Findings preview */}
                {runningStatus.findings && runningStatus.findings.length > 0 && (
                  <div className="mb-3 space-y-2">
                    {runningStatus.findings.slice(-3).map((f: any, i: number) => (
                      <div key={i} className="p-2 bg-green-500/5 border border-green-500/20 rounded-lg">
                        <div className="flex items-center gap-2">
                          <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${SEVERITY_COLORS[f.severity || 'medium']} text-white`}>
                            {(f.severity || 'medium').toUpperCase()}
                          </span>
                          <span className="text-sm text-green-300">{f.title || f.vulnerability_type || 'Finding'}</span>
                        </div>
                        {f.affected_endpoint && (
                          <p className="text-xs text-dark-500 mt-1 truncate">{f.affected_endpoint}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Result badge on completion */}
                {runningStatus.result && (
                  <div className="mt-4 flex items-center gap-3">
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                      RESULT_BADGE[runningStatus.result]?.bg || 'bg-gray-500/20'
                    } ${RESULT_BADGE[runningStatus.result]?.text || 'text-gray-400'}`}>
                      {RESULT_BADGE[runningStatus.result]?.label || runningStatus.result}
                    </span>
                    {runningStatus.scan_id && (
                      <button
                        onClick={() => navigate(`/scan/${runningStatus.scan_id}`)}
                        className="text-sm text-purple-400 hover:text-purple-300 flex items-center gap-1"
                      >
                        <Eye className="w-4 h-4" /> View Scan Details
                      </button>
                    )}
                  </div>
                )}

                {/* Error */}
                {runningStatus.error && (
                  <div className="mt-3 p-2 bg-red-500/10 border border-red-500/20 rounded text-red-400 text-sm">
                    {runningStatus.error}
                  </div>
                )}
              </div>

              {/* Live Logs Panel */}
              <div className="bg-dark-800 border border-dark-700 rounded-2xl overflow-hidden">
                <div className="flex items-center justify-between px-4 py-3 border-b border-dark-700">
                  <button
                    onClick={() => setShowLogs(!showLogs)}
                    className="flex items-center gap-2 text-sm font-medium text-dark-300 hover:text-white transition-colors"
                  >
                    <Terminal className="w-4 h-4 text-purple-400" />
                    Live Agent Logs
                    <span className="text-dark-600 text-xs">({runningLogs.length})</span>
                    {showLogs ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                  {showLogs && (
                    <div className="flex items-center gap-1">
                      {(['all', 'info', 'warning', 'error'] as const).map(level => (
                        <button
                          key={level}
                          onClick={() => setLogFilter(level)}
                          className={`px-2 py-1 rounded text-xs transition-colors ${
                            logFilter === level
                              ? 'bg-purple-500/20 text-purple-400'
                              : 'text-dark-500 hover:text-white'
                          }`}
                        >
                          {level}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                {showLogs && (
                  <div
                    className="p-3 bg-dark-900 max-h-80 overflow-y-auto space-y-0.5"
                    onScroll={(e) => {
                      const el = e.currentTarget
                      autoScrollRef.current = el.scrollTop + el.clientHeight >= el.scrollHeight - 50
                    }}
                  >
                    {filteredLogs.length === 0 ? (
                      <p className="text-dark-600 text-xs font-mono">Waiting for logs...</p>
                    ) : (
                      filteredLogs.map((log, i) => <LogLine key={i} log={log} />)
                    )}
                    <div ref={logsEndRef} />
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========== HISTORY TAB ========== */}
      {activeTab === 'history' && (
        <div className="w-full max-w-4xl">
          <div className="bg-dark-800 border border-dark-700 rounded-2xl overflow-hidden">
            <div className="p-4 border-b border-dark-700 flex items-center justify-between">
              <h3 className="text-white font-semibold">Challenge History ({challenges.length})</h3>
              <button
                onClick={loadChallenges}
                className="text-sm text-dark-400 hover:text-white"
              >
                Refresh
              </button>
            </div>

            {challenges.length === 0 ? (
              <div className="p-8 text-center text-dark-500">
                No challenges yet. Start your first test!
              </div>
            ) : (
              <div className="divide-y divide-dark-700">
                {challenges.map(ch => {
                  const statusBadge = STATUS_BADGE[ch.status] || STATUS_BADGE.pending
                  const resultBadge = ch.result ? RESULT_BADGE[ch.result] : null
                  const isExpanded = expandedChallenge === ch.id

                  return (
                    <div key={ch.id}>
                      {/* Challenge row */}
                      <div
                        className={`p-4 cursor-pointer transition-colors ${
                          isExpanded ? 'bg-dark-900/80' : 'hover:bg-dark-900/50'
                        }`}
                        onClick={() => toggleChallengeExpand(ch.id)}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-3">
                            <ChevronRight className={`w-4 h-4 text-dark-500 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                            <span className="text-white font-medium">
                              {ch.challenge_name || ch.vuln_type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-xs ${statusBadge.bg} ${statusBadge.text}`}>
                              {ch.status}
                            </span>
                            {resultBadge && (
                              <span className={`px-2 py-0.5 rounded text-xs ${resultBadge.bg} ${resultBadge.text}`}>
                                {resultBadge.label}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
                            {ch.scan_id && (
                              <button
                                onClick={() => navigate(`/scan/${ch.scan_id}`)}
                                className="p-1.5 text-dark-400 hover:text-white rounded"
                                title="View scan details"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                            )}
                            <button
                              onClick={() => handleDelete(ch.id)}
                              className="p-1.5 text-dark-400 hover:text-red-400 rounded"
                              title="Delete"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </div>

                        <div className="flex items-center gap-4 text-xs text-dark-500 ml-7">
                          <span className="flex items-center gap-1">
                            <Target className="w-3 h-3" />
                            {ch.target_url.length > 50 ? ch.target_url.slice(0, 50) + '...' : ch.target_url}
                          </span>
                          <span className="text-dark-600">|</span>
                          <span>{ch.vuln_type}</span>
                          {ch.vuln_category && (
                            <>
                              <span className="text-dark-600">|</span>
                              <span>{ch.vuln_category}</span>
                            </>
                          )}
                          <span className="text-dark-600">|</span>
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {formatDuration(ch.duration)}
                          </span>
                          {(ch.endpoints_count ?? 0) > 0 && (
                            <>
                              <span className="text-dark-600">|</span>
                              <span className="flex items-center gap-1">
                                <Globe className="w-3 h-3" />
                                {ch.endpoints_count} endpoints
                              </span>
                            </>
                          )}
                          {(ch.logs_count ?? 0) > 0 && (
                            <>
                              <span className="text-dark-600">|</span>
                              <span className="flex items-center gap-1">
                                <Terminal className="w-3 h-3" />
                                {ch.logs_count} logs
                              </span>
                            </>
                          )}
                        </div>

                        {/* Findings summary */}
                        {ch.findings_count > 0 && (
                          <div className="flex gap-2 mt-2 ml-7">
                            {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
                              const count = ch[`${sev}_count` as keyof VulnLabChallenge] as number
                              if (!count) return null
                              return (
                                <span key={sev} className={`${SEVERITY_COLORS[sev]} text-white px-2 py-0.5 rounded text-xs font-bold`}>
                                  {count} {sev}
                                </span>
                              )
                            })}
                          </div>
                        )}
                      </div>

                      {/* Expanded detail section */}
                      {isExpanded && (
                        <div className="border-t border-dark-700 bg-dark-900/50">
                          {loadingChallenge ? (
                            <div className="p-6 flex items-center justify-center gap-2 text-dark-400">
                              <Loader2 className="w-5 h-5 animate-spin" />
                              Loading details...
                            </div>
                          ) : expandedChallengeData ? (
                            <div className="p-4 space-y-4">
                              {/* Findings Detail */}
                              {(expandedChallengeData.findings_detail || expandedChallengeData.findings || []).length > 0 && (
                                <div>
                                  <h4 className="text-sm font-medium text-dark-300 mb-2 flex items-center gap-2">
                                    <Shield className="w-4 h-4 text-green-400" />
                                    Findings ({(expandedChallengeData.findings_detail || expandedChallengeData.findings || []).length})
                                  </h4>
                                  <div className="space-y-2">
                                    {(expandedChallengeData.findings_detail || expandedChallengeData.findings || []).map((f: any, i: number) => (
                                      <div key={i} className="p-3 bg-dark-800 border border-dark-700 rounded-lg">
                                        <div className="flex items-center gap-2 mb-1">
                                          <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${SEVERITY_COLORS[f.severity || 'medium']} text-white`}>
                                            {(f.severity || 'medium').toUpperCase()}
                                          </span>
                                          <span className="text-sm text-white font-medium">
                                            {f.title || f.vulnerability_type || 'Finding'}
                                          </span>
                                        </div>
                                        {f.vulnerability_type && (
                                          <p className="text-xs text-dark-500 mb-1">Type: {f.vulnerability_type}</p>
                                        )}
                                        {f.affected_endpoint && (
                                          <p className="text-xs text-dark-400 mb-1 flex items-center gap-1">
                                            <Globe className="w-3 h-3" />
                                            {f.affected_endpoint}
                                          </p>
                                        )}
                                        {f.payload && (
                                          <div className="mt-1">
                                            <span className="text-xs text-dark-600">Payload: </span>
                                            <code className="text-xs text-purple-400 bg-dark-900 px-1.5 py-0.5 rounded break-all">
                                              {f.payload}
                                            </code>
                                          </div>
                                        )}
                                        {f.evidence && (
                                          <div className="mt-1">
                                            <span className="text-xs text-dark-600">Evidence: </span>
                                            <span className="text-xs text-dark-400">{f.evidence.slice(0, 300)}</span>
                                          </div>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* No findings message */}
                              {(expandedChallengeData.findings_detail || expandedChallengeData.findings || []).length === 0 &&
                               expandedChallengeData.status !== 'running' && (
                                <div className="p-3 bg-dark-800 border border-dark-700 rounded-lg text-center text-dark-500 text-sm">
                                  No findings detected for this challenge.
                                </div>
                              )}

                              {/* Agent Logs */}
                              {(expandedChallengeData.logs || []).length > 0 && (
                                <ChallengeLogsViewer logs={expandedChallengeData.logs} />
                              )}

                              {/* Notes */}
                              {expandedChallengeData.notes && (
                                <div className="p-3 bg-dark-800 border border-dark-700 rounded-lg">
                                  <h4 className="text-xs font-medium text-dark-500 mb-1 flex items-center gap-1">
                                    <FileText className="w-3 h-3" /> Notes
                                  </h4>
                                  <p className="text-sm text-dark-300">{expandedChallengeData.notes}</p>
                                </div>
                              )}
                            </div>
                          ) : (
                            <div className="p-6 text-center text-dark-500 text-sm">
                              Failed to load challenge details.
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========== STATS TAB ========== */}
      {activeTab === 'stats' && (
        <div className="w-full max-w-4xl">
          {!stats ? (
            <div className="text-center text-dark-500 py-12">Loading stats...</div>
          ) : (
            <div className="space-y-6">
              {/* Overview cards */}
              <div className="grid grid-cols-4 gap-4">
                {[
                  { label: 'Total Tests', value: stats.total, color: 'text-white' },
                  { label: 'Running', value: stats.running, color: 'text-blue-400' },
                  { label: 'Detection Rate', value: `${stats.detection_rate}%`, color: 'text-green-400' },
                  { label: 'Detected', value: stats.result_counts?.detected || 0, color: 'text-green-400' },
                ].map((card, i) => (
                  <div key={i} className="bg-dark-800 border border-dark-700 rounded-xl p-4 text-center">
                    <div className={`text-2xl font-bold ${card.color}`}>{card.value}</div>
                    <div className="text-xs text-dark-500 mt-1">{card.label}</div>
                  </div>
                ))}
              </div>

              {/* Per-category breakdown */}
              {Object.keys(stats.by_category).length > 0 && (
                <div className="bg-dark-800 border border-dark-700 rounded-2xl p-6">
                  <h3 className="text-white font-semibold mb-4">Detection by Category</h3>
                  <div className="space-y-3">
                    {Object.entries(stats.by_category).map(([cat, data]) => {
                      const rate = data.total > 0 ? Math.round(data.detected / data.total * 100) : 0
                      const catLabel = categories[cat]?.label || cat
                      return (
                        <div key={cat}>
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-sm text-dark-300">{catLabel}</span>
                            <span className="text-sm text-dark-400">
                              {data.detected}/{data.total} ({rate}%)
                            </span>
                          </div>
                          <div className="w-full bg-dark-900 rounded-full h-2">
                            <div
                              className={`h-2 rounded-full transition-all ${rate >= 70 ? 'bg-green-500' : rate >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`}
                              style={{ width: `${rate}%` }}
                            />
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Per-type breakdown */}
              {Object.keys(stats.by_type).length > 0 && (
                <div className="bg-dark-800 border border-dark-700 rounded-2xl p-6">
                  <h3 className="text-white font-semibold mb-4">Detection by Vulnerability Type</h3>
                  <div className="grid grid-cols-2 gap-3">
                    {Object.entries(stats.by_type).map(([vtype, data]) => {
                      const rate = data.total > 0 ? Math.round(data.detected / data.total * 100) : 0
                      return (
                        <div key={vtype} className="flex items-center justify-between p-2 bg-dark-900 rounded-lg">
                          <span className="text-sm text-dark-300">{vtype.replace(/_/g, ' ')}</span>
                          <div className="flex items-center gap-2">
                            <span className={`text-xs font-bold ${rate >= 70 ? 'text-green-400' : rate >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>
                              {rate}%
                            </span>
                            <span className="text-xs text-dark-600">({data.detected}/{data.total})</span>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {stats.total === 0 && (
                <div className="text-center text-dark-500 py-8">
                  No test data yet. Run some vulnerability tests to see stats!
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}


/* ===== Challenge Logs Viewer Component ===== */
function ChallengeLogsViewer({ logs }: { logs: VulnLabLogEntry[] }) {
  const [expanded, setExpanded] = useState(false)
  const [filter, setFilter] = useState<'all' | 'info' | 'warning' | 'error'>('all')

  const filtered = filter === 'all' ? logs : logs.filter(l => l.level === filter)
  const displayed = expanded ? filtered : filtered.slice(-30)

  const errorCount = logs.filter(l => l.level === 'error').length
  const warnCount = logs.filter(l => l.level === 'warning').length

  return (
    <div className="border border-dark-700 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 bg-dark-800 border-b border-dark-700">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-2 text-sm font-medium text-dark-300 hover:text-white transition-colors"
        >
          <Terminal className="w-4 h-4 text-purple-400" />
          Agent Logs ({logs.length})
          {errorCount > 0 && <span className="text-red-400 text-xs">({errorCount} errors)</span>}
          {warnCount > 0 && <span className="text-yellow-400 text-xs">({warnCount} warnings)</span>}
          {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </button>
        <div className="flex items-center gap-1">
          {(['all', 'info', 'warning', 'error'] as const).map(level => (
            <button
              key={level}
              onClick={() => setFilter(level)}
              className={`px-2 py-0.5 rounded text-xs transition-colors ${
                filter === level
                  ? 'bg-purple-500/20 text-purple-400'
                  : 'text-dark-600 hover:text-white'
              }`}
            >
              {level}
            </button>
          ))}
        </div>
      </div>
      <div className={`p-2 bg-dark-900 overflow-y-auto space-y-0.5 ${expanded ? 'max-h-96' : 'max-h-48'}`}>
        {!expanded && filtered.length > 30 && (
          <p className="text-dark-600 text-xs font-mono mb-1">
            ... {filtered.length - 30} older entries hidden (click to expand)
          </p>
        )}
        {displayed.map((log, i) => <LogLine key={i} log={log} />)}
        {displayed.length === 0 && (
          <p className="text-dark-600 text-xs font-mono">No logs matching filter.</p>
        )}
      </div>
    </div>
  )
}
