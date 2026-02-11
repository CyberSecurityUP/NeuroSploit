import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
  Box, RefreshCw, Trash2, Heart, Clock, Cpu,
  HardDrive, Timer, AlertTriangle, CheckCircle2,
  XCircle, Wrench, Container
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { sandboxApi } from '../services/api'
import type { SandboxPoolStatus, SandboxContainer } from '../types'

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}s`
  if (seconds < 3600) {
    const m = Math.floor(seconds / 60)
    const s = Math.floor(seconds % 60)
    return `${m}m ${s}s`
  }
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return `${h}h ${m}m`
}

function timeAgo(isoDate: string | null): string {
  if (!isoDate) return 'Unknown'
  const diff = (Date.now() - new Date(isoDate).getTime()) / 1000
  if (diff < 60) return 'Just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export default function SandboxDashboardPage() {
  const [data, setData] = useState<SandboxPoolStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [destroyConfirm, setDestroyConfirm] = useState<string | null>(null)
  const [healthResults, setHealthResults] = useState<Record<string, { status: string; tools: string[] } | null>>({})
  const [healthLoading, setHealthLoading] = useState<Record<string, boolean>>({})
  const [actionLoading, setActionLoading] = useState(false)

  const fetchData = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true)
    try {
      const result = await sandboxApi.list()
      setData(result)
    } catch (error) {
      console.error('Failed to fetch sandbox data:', error)
      if (!data) {
        setData({
          pool: { active: 0, max_concurrent: 0, image: 'N/A', container_ttl_minutes: 0, docker_available: false },
          containers: [],
          error: 'Failed to connect to backend',
        })
      }
    } finally {
      setLoading(false)
    }
  }, [])

  // Initial fetch + 5-second polling
  useEffect(() => {
    fetchData(true)
    const interval = setInterval(() => fetchData(false), 5000)
    return () => clearInterval(interval)
  }, [fetchData])

  // Auto-dismiss messages
  useEffect(() => {
    if (message) {
      const timer = setTimeout(() => setMessage(null), 4000)
      return () => clearTimeout(timer)
    }
  }, [message])

  const handleDestroy = async (scanId: string) => {
    if (destroyConfirm !== scanId) {
      setDestroyConfirm(scanId)
      setTimeout(() => setDestroyConfirm(null), 5000)
      return
    }
    setDestroyConfirm(null)
    setActionLoading(true)
    try {
      await sandboxApi.destroy(scanId)
      setMessage({ type: 'success', text: `Container for scan ${scanId.slice(0, 8)}... destroyed` })
      fetchData(false)
    } catch (error: any) {
      setMessage({ type: 'error', text: error?.response?.data?.detail || 'Failed to destroy container' })
    } finally {
      setActionLoading(false)
    }
  }

  const handleHealthCheck = async (scanId: string) => {
    setHealthLoading(prev => ({ ...prev, [scanId]: true }))
    try {
      const result = await sandboxApi.healthCheck(scanId)
      setHealthResults(prev => ({ ...prev, [scanId]: result }))
      setTimeout(() => {
        setHealthResults(prev => ({ ...prev, [scanId]: null }))
      }, 8000)
    } catch {
      setHealthResults(prev => ({ ...prev, [scanId]: { status: 'error', tools: [] } }))
    } finally {
      setHealthLoading(prev => ({ ...prev, [scanId]: false }))
    }
  }

  const handleCleanup = async (type: 'expired' | 'orphans') => {
    setActionLoading(true)
    try {
      if (type === 'expired') {
        await sandboxApi.cleanup()
      } else {
        await sandboxApi.cleanupOrphans()
      }
      setMessage({ type: 'success', text: `${type === 'expired' ? 'Expired' : 'Orphan'} containers cleaned up` })
      fetchData(false)
    } catch (error: any) {
      setMessage({ type: 'error', text: error?.response?.data?.detail || `Cleanup failed` })
    } finally {
      setActionLoading(false)
    }
  }

  if (loading && !data) {
    return (
      <div className="animate-pulse space-y-6">
        <div className="h-8 bg-dark-800 rounded w-64" />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="h-24 bg-dark-800 rounded-lg" />
          ))}
        </div>
        <div className="space-y-4">
          {[1, 2].map(i => (
            <div key={i} className="h-40 bg-dark-800 rounded-lg" />
          ))}
        </div>
      </div>
    )
  }

  const pool = data?.pool
  const containers = data?.containers || []
  const utilizationPct = pool ? (pool.active / pool.max_concurrent) * 100 : 0

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
              <Container className="w-6 h-6 text-blue-400" />
            </div>
            Sandbox Containers
          </h1>
          <p className="text-dark-400 mt-1">Real-time monitoring of per-scan Kali Linux containers</p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleCleanup('expired')}
            isLoading={actionLoading}
          >
            <Timer className="w-4 h-4 mr-1" />
            Cleanup Expired
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleCleanup('orphans')}
            isLoading={actionLoading}
          >
            <Trash2 className="w-4 h-4 mr-1" />
            Cleanup Orphans
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => fetchData(false)}
          >
            <RefreshCw className="w-4 h-4 mr-1" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Status message */}
      {message && (
        <div className={`flex items-center gap-2 px-4 py-3 rounded-lg text-sm animate-fadeIn ${
          message.type === 'success'
            ? 'bg-green-500/10 border border-green-500/30 text-green-400'
            : 'bg-red-500/10 border border-red-500/30 text-red-400'
        }`}>
          {message.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          )}
          {message.text}
        </div>
      )}

      {/* Pool Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Active Containers */}
        <Card>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
              utilizationPct >= 100 ? 'bg-red-500/20' :
              utilizationPct >= 80 ? 'bg-yellow-500/20' :
              'bg-green-500/20'
            }`}>
              <Box className={`w-5 h-5 ${
                utilizationPct >= 100 ? 'text-red-400' :
                utilizationPct >= 80 ? 'text-yellow-400' :
                'text-green-400'
              }`} />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">
                {pool?.active || 0}<span className="text-dark-400 text-lg">/{pool?.max_concurrent || 0}</span>
              </p>
              <p className="text-xs text-dark-400">Active Containers</p>
            </div>
          </div>
        </Card>

        {/* Docker Status */}
        <Card>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
              pool?.docker_available ? 'bg-green-500/20' : 'bg-red-500/20'
            }`}>
              <HardDrive className={`w-5 h-5 ${
                pool?.docker_available ? 'text-green-400' : 'text-red-400'
              }`} />
            </div>
            <div>
              <p className="text-lg font-bold text-white">
                {pool?.docker_available ? 'Online' : 'Offline'}
              </p>
              <p className="text-xs text-dark-400">Docker Engine</p>
            </div>
          </div>
        </Card>

        {/* Container Image */}
        <Card>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
              <Cpu className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-sm font-bold text-white truncate max-w-[140px]" title={pool?.image}>
                {pool?.image?.split(':')[0]?.split('/').pop() || 'N/A'}
              </p>
              <p className="text-xs text-dark-400">
                {pool?.image?.includes(':') ? pool.image.split(':')[1] : 'latest'}
              </p>
            </div>
          </div>
        </Card>

        {/* TTL */}
        <Card>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-orange-500/20 rounded-lg flex items-center justify-center">
              <Clock className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">
                {pool?.container_ttl_minutes || 0}<span className="text-dark-400 text-lg"> min</span>
              </p>
              <p className="text-xs text-dark-400">Container TTL</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Capacity Bar */}
      {pool && pool.max_concurrent > 0 && (
        <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-dark-300">Pool Capacity</span>
            <span className={`text-sm font-medium ${
              utilizationPct >= 100 ? 'text-red-400' :
              utilizationPct >= 80 ? 'text-yellow-400' :
              'text-green-400'
            }`}>
              {Math.round(utilizationPct)}%
            </span>
          </div>
          <div className="w-full bg-dark-900 rounded-full h-2.5">
            <div
              className={`h-2.5 rounded-full transition-all duration-500 ${
                utilizationPct >= 100 ? 'bg-red-500' :
                utilizationPct >= 80 ? 'bg-yellow-500' :
                'bg-green-500'
              }`}
              style={{ width: `${Math.min(utilizationPct, 100)}%` }}
            />
          </div>
        </div>
      )}

      {/* Container List */}
      {containers.length === 0 ? (
        <div className="bg-dark-800 rounded-lg border border-dark-700 p-12 text-center">
          <Box className="w-16 h-16 text-dark-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-dark-300 mb-2">No Sandbox Containers Running</h3>
          <p className="text-dark-400 text-sm max-w-md mx-auto">
            Containers are automatically created when scans start and destroyed when they complete.
            Start a scan to see containers here.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          <h2 className="text-lg font-semibold text-white">
            Running Containers ({containers.length})
          </h2>

          {containers.map((container: SandboxContainer) => {
            const health = healthResults[container.scan_id]
            const isHealthLoading = healthLoading[container.scan_id]
            const isConfirming = destroyConfirm === container.scan_id

            return (
              <div
                key={container.scan_id}
                className="bg-dark-800 rounded-lg border border-dark-700 p-5 hover:border-dark-600 transition-colors"
              >
                {/* Container Header */}
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className={`w-3 h-3 rounded-full ${
                      container.available ? 'bg-green-500 animate-pulse' : 'bg-red-500'
                    }`} />
                    <div>
                      <h3 className="text-white font-medium font-mono text-sm">
                        {container.container_name}
                      </h3>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-xs text-dark-400">Scan:</span>
                        <Link
                          to={`/scan/${container.scan_id}`}
                          className="text-xs text-primary-400 hover:text-primary-300 font-mono"
                        >
                          {container.scan_id.slice(0, 12)}...
                        </Link>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {/* Status badge */}
                    <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium ${
                      container.available
                        ? 'bg-green-500/10 text-green-400 border border-green-500/30'
                        : 'bg-red-500/10 text-red-400 border border-red-500/30'
                    }`}>
                      {container.available ? (
                        <><CheckCircle2 className="w-3 h-3" /> Running</>
                      ) : (
                        <><XCircle className="w-3 h-3" /> Stopped</>
                      )}
                    </span>
                  </div>
                </div>

                {/* Container Info Grid */}
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-4">
                  {/* Uptime */}
                  <div>
                    <p className="text-xs text-dark-400 mb-1">Uptime</p>
                    <p className="text-sm text-white font-medium">
                      {formatUptime(container.uptime_seconds)}
                    </p>
                  </div>

                  {/* Created */}
                  <div>
                    <p className="text-xs text-dark-400 mb-1">Created</p>
                    <p className="text-sm text-dark-300">
                      {timeAgo(container.created_at)}
                    </p>
                  </div>

                  {/* Tools count */}
                  <div>
                    <p className="text-xs text-dark-400 mb-1">Installed Tools</p>
                    <p className="text-sm text-white font-medium">
                      {container.installed_tools.length}
                    </p>
                  </div>
                </div>

                {/* Installed Tools */}
                {container.installed_tools.length > 0 && (
                  <div className="mb-4">
                    <p className="text-xs text-dark-400 mb-2">Tools</p>
                    <div className="flex flex-wrap gap-1.5">
                      {container.installed_tools.map(tool => (
                        <span
                          key={tool}
                          className="inline-flex items-center gap-1 px-2 py-0.5 bg-dark-900 border border-dark-600 rounded text-xs text-dark-300"
                        >
                          <Wrench className="w-3 h-3 text-dark-500" />
                          {tool}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Health Check Result */}
                {health && (
                  <div className={`mb-4 px-3 py-2 rounded-lg text-xs animate-fadeIn ${
                    health.status === 'healthy'
                      ? 'bg-green-500/10 border border-green-500/20 text-green-400'
                      : health.status === 'degraded'
                      ? 'bg-yellow-500/10 border border-yellow-500/20 text-yellow-400'
                      : 'bg-red-500/10 border border-red-500/20 text-red-400'
                  }`}>
                    <span className="font-medium">Health: {health.status}</span>
                    {health.tools.length > 0 && (
                      <span className="ml-2">
                        — Verified: {health.tools.join(', ')}
                      </span>
                    )}
                  </div>
                )}

                {/* Actions */}
                <div className="flex items-center gap-2 pt-3 border-t border-dark-700">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleHealthCheck(container.scan_id)}
                    isLoading={isHealthLoading}
                  >
                    <Heart className="w-4 h-4 mr-1" />
                    Health Check
                  </Button>

                  <Button
                    variant={isConfirming ? 'danger' : 'ghost'}
                    size="sm"
                    onClick={() => handleDestroy(container.scan_id)}
                    isLoading={actionLoading}
                  >
                    <Trash2 className="w-4 h-4 mr-1" />
                    {isConfirming ? 'Confirm Destroy' : 'Destroy'}
                  </Button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Auto-refresh indicator */}
      <div className="text-center text-xs text-dark-500">
        Auto-refreshing every 5 seconds
      </div>
    </div>
  )
}
