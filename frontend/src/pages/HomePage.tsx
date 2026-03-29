import { useEffect, useMemo, useState, useCallback, useRef } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity, Shield, AlertTriangle, Plus, ArrowRight, CheckCircle,
  FileText, Cpu, Globe, Zap, Terminal, Bug, FlaskConical,
  ChevronRight, X, RefreshCw, WifiOff, Play
} from 'lucide-react'
import {
  PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer
} from 'recharts'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { SeverityBadge } from '../components/common/Badge'
import { dashboardApi, agentApi } from '../services/api'
import { useDashboardStore } from '../store'
import type { ActivityFeedItem } from '../types'

/* ─── Constants ──────────────────────────────────────────────── */

const SEVERITY_CHART_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
}

const STATUS_CHART_COLORS: Record<string, string> = {
  running: '#22c55e',
  completed: '#6366f1',
  stopped: '#eab308',
  failed: '#ef4444',
  pending: '#6b7280',
  paused: '#f59e0b',
}

/* ─── Helpers ────────────────────────────────────────────────── */

function relativeTime(ts: string): string {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

/* ─── Toast System ───────────────────────────────────────────── */

interface Toast { id: number; message: string; severity: 'info' | 'success' | 'warning' | 'error' }

let _toastId = 0

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null
  const border: Record<string, string> = {
    info: 'border-blue-500', success: 'border-green-500',
    warning: 'border-yellow-500', error: 'border-red-500',
  }
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`bg-dark-800 border-l-4 ${border[t.severity]} rounded-lg px-4 py-3 shadow-xl flex items-start gap-3`}
          style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
        >
          <span className="text-sm text-dark-200 flex-1">{t.message}</span>
          <button onClick={() => onDismiss(t.id)} className="text-dark-500 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
    </div>
  )
}

/* ─── Donut Chart ────────────────────────────────────────────── */

function DonutChart({ data }: { data: Array<{ name: string; value: number; color: string }> }) {
  const filtered = data.filter(d => d.value > 0)
  if (filtered.length === 0) return <p className="text-dark-500 text-center py-8 text-sm">No data yet</p>
  const total = filtered.reduce((s, d) => s + d.value, 0)

  return (
    <div className="flex items-center gap-4">
      <ResponsiveContainer width={140} height={140}>
        <PieChart>
          <Pie
            data={filtered}
            dataKey="value"
            cx="50%"
            cy="50%"
            innerRadius={38}
            outerRadius={62}
            paddingAngle={2}
            strokeWidth={0}
          >
            {filtered.map((d, i) => (
              <Cell key={i} fill={d.color} />
            ))}
          </Pie>
          <RechartsTooltip
            contentStyle={{ background: '#1a1a2e', border: '1px solid #2a2a3e', borderRadius: 8, fontSize: 12 }}
            itemStyle={{ color: '#e2e8f0' }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="flex flex-col gap-1.5">
        {filtered.map(d => (
          <div key={d.name} className="flex items-center gap-2 text-sm">
            <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: d.color }} />
            <span className="text-dark-300 whitespace-nowrap">{d.name}</span>
            <span className="text-white font-semibold ml-auto tabular-nums">{d.value}</span>
            <span className="text-dark-500 text-xs w-10 text-right">{((d.value / total) * 100).toFixed(0)}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ─── Active Agent Card ──────────────────────────────────────── */

interface ActiveAgent {
  agent_id: string
  target: string
  status: string
  progress: number
  phase: string
  scan_id: string | null
  started_at: string
  findings_count: number
  mode: string
}

function ActiveAgentCard({ agent }: { agent: ActiveAgent }) {
  return (
    <Link
      to={agent.scan_id ? `/scan/${agent.scan_id}` : '#'}
      className="flex items-center gap-4 p-3 bg-dark-900/60 rounded-lg hover:bg-dark-900 transition-colors group"
    >
      {/* Pulse indicator */}
      <div className="relative flex-shrink-0">
        <div className={`w-3 h-3 rounded-full ${agent.status === 'running' ? 'bg-green-500' : 'bg-yellow-500'}`} />
        {agent.status === 'running' && (
          <div className="absolute inset-0 w-3 h-3 rounded-full bg-green-500 animate-ping opacity-40" />
        )}
      </div>

      {/* Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-white truncate max-w-[180px] sm:max-w-[300px]">
            {agent.target}
          </span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-dark-700 text-dark-300 uppercase hidden sm:inline">
            {agent.mode.replace('_', ' ')}
          </span>
        </div>
        <div className="flex items-center gap-2 mt-1">
          <div className="flex-1 h-1.5 bg-dark-700 rounded-full overflow-hidden max-w-[200px]">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${agent.progress}%`,
                background: 'linear-gradient(90deg, #22c55e, #16a34a)',
              }}
            />
          </div>
          <span className="text-xs text-dark-400 tabular-nums w-8">{agent.progress}%</span>
          <span className="text-xs text-dark-500 hidden sm:inline">{agent.phase}</span>
        </div>
      </div>

      {/* Findings + arrow */}
      <div className="flex items-center gap-2">
        {agent.findings_count > 0 && (
          <div className="flex items-center gap-1">
            <Bug className="w-3 h-3 text-red-400" />
            <span className="text-xs text-red-400 font-medium tabular-nums">{agent.findings_count}</span>
          </div>
        )}
        <ChevronRight className="w-4 h-4 text-dark-600 group-hover:text-dark-400 transition-colors" />
      </div>
    </Link>
  )
}

/* ═══════════════════════════════════════════════════════════════
   Main Dashboard Component
   ═══════════════════════════════════════════════════════════════ */

export default function HomePage() {
  const {
    stats, recentScans, recentVulnerabilities,
    setStats, setRecentScans, setRecentVulnerabilities, setLoading,
  } = useDashboardStore()

  const [activityFeed, setActivityFeed] = useState<ActivityFeedItem[]>([])
  const [activeAgents, setActiveAgents] = useState<ActiveAgent[]>([])
  const [maxConcurrent, setMaxConcurrent] = useState(5)
  const [toasts, setToasts] = useState<Toast[]>([])
  const [connectionLost, setConnectionLost] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [activityFilter, setActivityFilter] = useState<string>('all')

  const consecutiveErrorsRef = useRef(0)
  const prevFindingsCountRef = useRef(-1)
  const prevRunningCountRef = useRef(-1)

  /* ── Toast helpers ──────────────────────────────────────────── */

  const addToast = useCallback((message: string, severity: Toast['severity'] = 'info') => {
    const id = ++_toastId
    setToasts(prev => [...prev.slice(-4), { id, message, severity }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  /* ── Data fetch ─────────────────────────────────────────────── */

  const fetchData = useCallback(async () => {
    try {
      const [statsData, recentData, activityData, agentsData] = await Promise.all([
        dashboardApi.getStats(),
        dashboardApi.getRecent(5),
        dashboardApi.getActivityFeed(20),
        agentApi.listActive().catch(() => ({ agents: [] as ActiveAgent[], max_concurrent: 5, running_count: 0 })),
      ])

      setStats(statsData)
      setRecentScans(recentData.recent_scans)
      setRecentVulnerabilities(recentData.recent_vulnerabilities)
      setActivityFeed(activityData.activities)
      setActiveAgents(agentsData.agents || [])
      setMaxConcurrent(agentsData.max_concurrent || 5)

      // Detect new findings
      const totalFindings = statsData.vulnerabilities.total
      if (prevFindingsCountRef.current >= 0 && totalFindings > prevFindingsCountRef.current) {
        const diff = totalFindings - prevFindingsCountRef.current
        addToast(`${diff} new finding${diff > 1 ? 's' : ''} discovered`, 'warning')
      }
      prevFindingsCountRef.current = totalFindings

      // Detect scan completions
      const runningCount = (agentsData.agents || []).filter((a: ActiveAgent) => a.status === 'running').length
      if (prevRunningCountRef.current > 0 && runningCount < prevRunningCountRef.current) {
        addToast('A scan has completed', 'success')
      }
      prevRunningCountRef.current = runningCount

      // Connection restored
      if (consecutiveErrorsRef.current >= 3) {
        setConnectionLost(false)
        addToast('Connection restored', 'success')
      }
      consecutiveErrorsRef.current = 0
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error)
      consecutiveErrorsRef.current++
      if (consecutiveErrorsRef.current >= 3) setConnectionLost(true)
    }
  }, [setStats, setRecentScans, setRecentVulnerabilities, addToast])

  useEffect(() => {
    setLoading(true)
    fetchData().finally(() => setLoading(false))
    const interval = setInterval(fetchData, 10000)
    return () => clearInterval(interval)
  }, [fetchData, setLoading])

  const handleRefresh = useCallback(async () => {
    setRefreshing(true)
    await fetchData()
    setRefreshing(false)
  }, [fetchData])

  /* ── Derived data ───────────────────────────────────────────── */

  const severityChartData = useMemo(() => [
    { name: 'Critical', value: stats?.vulnerabilities.critical || 0, color: SEVERITY_CHART_COLORS.critical },
    { name: 'High', value: stats?.vulnerabilities.high || 0, color: SEVERITY_CHART_COLORS.high },
    { name: 'Medium', value: stats?.vulnerabilities.medium || 0, color: SEVERITY_CHART_COLORS.medium },
    { name: 'Low', value: stats?.vulnerabilities.low || 0, color: SEVERITY_CHART_COLORS.low },
    { name: 'Info', value: stats?.vulnerabilities.info || 0, color: SEVERITY_CHART_COLORS.info },
  ], [stats])

  const scanChartData = useMemo(() => [
    { name: 'Running', value: stats?.scans.running || 0, color: STATUS_CHART_COLORS.running },
    { name: 'Completed', value: stats?.scans.completed || 0, color: STATUS_CHART_COLORS.completed },
    { name: 'Stopped', value: stats?.scans.stopped || 0, color: STATUS_CHART_COLORS.stopped },
    { name: 'Failed', value: stats?.scans.failed || 0, color: STATUS_CHART_COLORS.failed },
    { name: 'Pending', value: stats?.scans.pending || 0, color: STATUS_CHART_COLORS.pending },
  ], [stats])

  const filteredActivity = useMemo(() => {
    if (activityFilter === 'all') return activityFeed
    return activityFeed.filter(a => a.type === activityFilter)
  }, [activityFeed, activityFilter])

  const statCards = useMemo(() => [
    { label: 'Total Scans', value: stats?.scans.total || 0, icon: Activity, color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
    { label: 'Running', value: stats?.scans.running || 0, icon: Play, color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/20' },
    { label: 'Completed', value: stats?.scans.completed || 0, icon: CheckCircle, color: 'text-indigo-400', bg: 'bg-indigo-500/10', border: 'border-indigo-500/20' },
    { label: 'Total Vulns', value: stats?.vulnerabilities.total || 0, icon: Bug, color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
    { label: 'Critical', value: stats?.vulnerabilities.critical || 0, icon: AlertTriangle, color: 'text-red-500', bg: 'bg-red-600/10', border: 'border-red-600/20' },
    { label: 'High', value: stats?.vulnerabilities.high || 0, icon: Shield, color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
  ], [stats])

  /* ── Render ─────────────────────────────────────────────────── */

  return (
    <div className="space-y-6">
      {/* Animations */}
      <style>{`
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(-8px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes countUp {
          from { opacity: 0; transform: translateY(6px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Connection Lost Banner */}
      {connectionLost && (
        <div
          className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg px-4 py-2.5 flex items-center gap-3"
          style={{ animation: 'fadeSlideIn 0.3s ease-out' }}
        >
          <WifiOff className="w-4 h-4 text-yellow-400 flex-shrink-0" />
          <span className="text-sm text-yellow-300">Connection issues detected. Retrying...</span>
        </div>
      )}

      {/* ── Header ────────────────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Zap className="w-6 h-6 text-primary-500" />
            NeuroSploit Dashboard
          </h2>
          <p className="text-dark-400 mt-1">AI-Powered Penetration Testing Platform</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            className="p-2 rounded-lg bg-dark-800 border border-dark-700 hover:border-dark-600 text-dark-400 hover:text-white transition-all"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
          <Link to="/scan/new">
            <Button size="lg">
              <Plus className="w-5 h-5 mr-2" />
              New Scan
            </Button>
          </Link>
        </div>
      </div>

      {/* ── Quick Actions ─────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {([
          { label: 'Auto Pentest', icon: Zap, to: '/auto', color: 'text-green-400', bg: 'bg-green-500/10 hover:bg-green-500/20', border: 'border-green-500/20 hover:border-green-500/40', desc: '109 agents + 100 vulns' },
          { label: 'AI Agent', icon: Shield, to: '/scan/new', color: 'text-red-400', bg: 'bg-red-500/10 hover:bg-red-500/20', border: 'border-red-500/20 hover:border-red-500/40', desc: 'Custom AI scan' },
          { label: 'Vuln Lab', icon: FlaskConical, to: '/vuln-lab', color: 'text-purple-400', bg: 'bg-purple-500/10 hover:bg-purple-500/20', border: 'border-purple-500/20 hover:border-purple-500/40', desc: 'Per-type challenges' },
          { label: 'Terminal', icon: Terminal, to: '/terminal', color: 'text-cyan-400', bg: 'bg-cyan-500/10 hover:bg-cyan-500/20', border: 'border-cyan-500/20 hover:border-cyan-500/40', desc: 'AI chat + commands' },
        ] as const).map(action => (
          <Link
            key={action.to}
            to={action.to}
            className={`p-4 rounded-xl border ${action.border} ${action.bg} transition-all group`}
          >
            <action.icon className={`w-6 h-6 ${action.color} mb-2`} />
            <p className="font-semibold text-white text-sm group-hover:translate-x-0.5 transition-transform">
              {action.label}
            </p>
            <p className="text-xs text-dark-400 mt-0.5">{action.desc}</p>
          </Link>
        ))}
      </div>

      {/* ── Stats Grid ────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {statCards.map((stat, idx) => (
          <div
            key={stat.label}
            className={`bg-dark-800 rounded-xl border ${stat.border} p-4 hover:scale-[1.02] transition-all cursor-default`}
            style={{ animation: `fadeSlideIn 0.3s ease-out ${idx * 0.05}s both` }}
          >
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${stat.bg}`}>
                <stat.icon className={`w-5 h-5 ${stat.color}`} />
              </div>
              <div>
                <p
                  className="text-xl font-bold text-white tabular-nums"
                  style={{ animation: 'countUp 0.5s ease-out' }}
                >
                  {stat.value}
                </p>
                <p className="text-[11px] text-dark-400 whitespace-nowrap">{stat.label}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Live Agents ───────────────────────────────────────── */}
      {activeAgents.length > 0 && (
        <Card
          title={
            <span className="flex items-center gap-2">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500" />
              </span>
              Live Agents ({activeAgents.length}/{maxConcurrent})
            </span>
          }
          action={
            <Link to="/auto" className="text-sm text-primary-500 hover:text-primary-400 flex items-center gap-1">
              Manage <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          }
        >
          <div className="space-y-2">
            {activeAgents.map(agent => (
              <ActiveAgentCard key={agent.agent_id} agent={agent} />
            ))}
          </div>
        </Card>
      )}

      {/* ── Charts Row ────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Vulnerability Severity">
          <DonutChart data={severityChartData} />
        </Card>
        <Card title="Scan Status">
          <DonutChart data={scanChartData} />
        </Card>
      </div>

      {/* ── Recent Scans + Findings ───────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <Card
          title="Recent Scans"
          action={
            <Link to="/reports" className="text-sm text-primary-500 hover:text-primary-400 flex items-center gap-1">
              View All <ArrowRight className="w-4 h-4" />
            </Link>
          }
        >
          <div className="space-y-2">
            {recentScans.length === 0 ? (
              <div className="text-center py-8">
                <Globe className="w-10 h-10 text-dark-600 mx-auto mb-2" />
                <p className="text-dark-400 text-sm">No scans yet</p>
                <Link to="/scan/new" className="text-primary-500 text-sm hover:underline mt-1 inline-block">
                  Start your first scan
                </Link>
              </div>
            ) : (
              recentScans.map(scan => (
                <Link
                  key={scan.id}
                  to={`/scan/${scan.id}`}
                  className="flex items-center justify-between p-3 bg-dark-900/50 rounded-lg hover:bg-dark-900 transition-colors group"
                >
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-white truncate group-hover:text-primary-400 transition-colors">
                      {scan.name || 'Unnamed Scan'}
                    </p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-xs text-dark-500">{relativeTime(scan.created_at)}</span>
                      {scan.status === 'running' && (
                        <div className="flex items-center gap-1.5">
                          <div className="w-16 h-1 bg-dark-700 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-green-500 rounded-full transition-all"
                              style={{ width: `${scan.progress}%` }}
                            />
                          </div>
                          <span className="text-[10px] text-green-400 tabular-nums">{scan.progress}%</span>
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 ml-2">
                    <SeverityBadge severity={scan.status} />
                    {scan.total_vulnerabilities > 0 && (
                      <span className="text-xs text-dark-400 tabular-nums">
                        {scan.total_vulnerabilities} vulns
                      </span>
                    )}
                  </div>
                </Link>
              ))
            )}
          </div>
        </Card>

        {/* Recent Findings */}
        <Card
          title="Recent Findings"
          action={
            <Link to="/reports" className="text-sm text-primary-500 hover:text-primary-400 flex items-center gap-1">
              View All <ArrowRight className="w-4 h-4" />
            </Link>
          }
        >
          <div className="space-y-2">
            {recentVulnerabilities.length === 0 ? (
              <div className="text-center py-8">
                <Shield className="w-10 h-10 text-dark-600 mx-auto mb-2" />
                <p className="text-dark-400 text-sm">No vulnerabilities found yet</p>
              </div>
            ) : (
              recentVulnerabilities.slice(0, 5).map(vuln => (
                <div
                  key={vuln.id}
                  className={`flex items-center justify-between p-3 bg-dark-900/50 rounded-lg transition-colors hover:bg-dark-900 ${
                    vuln.validation_status === 'ai_rejected' ? 'opacity-60 border-l-2 border-orange-500/40' :
                    vuln.validation_status === 'false_positive' ? 'opacity-40' : ''
                  }`}
                >
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-white truncate">{vuln.title}</p>
                    <p className="text-xs text-dark-400 truncate mt-0.5">{vuln.affected_endpoint}</p>
                  </div>
                  <div className="flex items-center gap-1.5 ml-2">
                    {vuln.confidence_score != null && (
                      <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-bold tabular-nums ${
                        vuln.confidence_score >= 90 ? 'bg-green-500/20 text-green-400' :
                        vuln.confidence_score >= 60 ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-red-500/20 text-red-400'
                      }`}>
                        {vuln.confidence_score}
                      </span>
                    )}
                    {vuln.validation_status === 'ai_rejected' && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-orange-500/20 text-orange-400">
                        Rejected
                      </span>
                    )}
                    {vuln.validation_status === 'validated' && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/20 text-green-400">
                        Validated
                      </span>
                    )}
                    {vuln.validation_status === 'false_positive' && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-dark-600 text-dark-400">
                        FP
                      </span>
                    )}
                    <SeverityBadge severity={vuln.severity} />
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>

      {/* ── Activity Feed ─────────────────────────────────────── */}
      <Card
        title="Activity Feed"
        action={
          <div className="flex items-center gap-1 flex-wrap">
            {(['all', 'scan', 'vulnerability', 'agent_task', 'report'] as const).map(f => (
              <button
                key={f}
                onClick={() => setActivityFilter(f)}
                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                  activityFilter === f
                    ? 'bg-primary-500/20 text-primary-400'
                    : 'text-dark-400 hover:text-dark-200 hover:bg-dark-700'
                }`}
              >
                {f === 'all' ? 'All'
                  : f === 'agent_task' ? 'Tasks'
                  : f === 'vulnerability' ? 'Vulns'
                  : f.charAt(0).toUpperCase() + f.slice(1) + 's'}
              </button>
            ))}
          </div>
        }
      >
        <div className="space-y-1.5 max-h-[400px] overflow-auto">
          {filteredActivity.length === 0 ? (
            <p className="text-dark-400 text-center py-8 text-sm">No recent activity</p>
          ) : (
            filteredActivity.map((activity, idx) => (
              <Link
                key={`${activity.type}-${activity.timestamp}-${idx}`}
                to={activity.link}
                className="flex items-start gap-3 p-3 bg-dark-900/50 rounded-lg hover:bg-dark-900 transition-colors group"
                style={{ animation: `fadeSlideIn 0.2s ease-out ${Math.min(idx * 0.03, 0.3)}s both` }}
              >
                {/* Icon */}
                <div className={`mt-0.5 p-1.5 rounded-lg flex-shrink-0 ${
                  activity.type === 'scan' ? 'bg-blue-500/20 text-blue-400' :
                  activity.type === 'vulnerability' ? 'bg-red-500/20 text-red-400' :
                  activity.type === 'agent_task' ? 'bg-purple-500/20 text-purple-400' :
                  'bg-green-500/20 text-green-400'
                }`}>
                  {activity.type === 'scan' ? <Shield className="w-3.5 h-3.5" /> :
                   activity.type === 'vulnerability' ? <AlertTriangle className="w-3.5 h-3.5" /> :
                   activity.type === 'agent_task' ? <Cpu className="w-3.5 h-3.5" /> :
                   <FileText className="w-3.5 h-3.5" />}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-dark-500 uppercase font-medium">
                      {activity.type.replace('_', ' ')}
                    </span>
                    <span className="text-[10px] text-dark-600">{activity.action}</span>
                  </div>
                  <p className="font-medium text-white text-sm truncate group-hover:text-primary-400 transition-colors">
                    {activity.title}
                  </p>
                  {activity.description && (
                    <p className="text-xs text-dark-400 truncate">{activity.description}</p>
                  )}
                </div>

                {/* Meta */}
                <div className="flex flex-col items-end gap-1 flex-shrink-0">
                  {activity.severity && <SeverityBadge severity={activity.severity} />}
                  {activity.status && !activity.severity && (
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                      activity.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                      activity.status === 'running' ? 'bg-blue-500/20 text-blue-400' :
                      activity.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                      activity.status === 'stopped' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-dark-700 text-dark-300'
                    }`}>
                      {activity.status}
                    </span>
                  )}
                  <span className="text-[10px] text-dark-500">{relativeTime(activity.timestamp)}</span>
                </div>
              </Link>
            ))
          )}
        </div>
      </Card>
    </div>
  )
}
