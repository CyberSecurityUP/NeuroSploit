import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { Scan, Vulnerability, Endpoint, DashboardStats, ScanAgentTask } from '../types'

interface LogEntry {
  level: string
  message: string
  time: string
}

interface ScanDataCache {
  endpoints: Endpoint[]
  vulnerabilities: Vulnerability[]
  logs: LogEntry[]
  agentTasks: ScanAgentTask[]
}

interface ScanState {
  currentScan: Scan | null
  scans: Scan[]
  endpoints: Endpoint[]
  vulnerabilities: Vulnerability[]
  logs: LogEntry[]
  agentTasks: ScanAgentTask[]
  scanDataCache: Record<string, ScanDataCache>
  isLoading: boolean
  error: string | null

  setCurrentScan: (scan: Scan | null) => void
  setScans: (scans: Scan[]) => void
  updateScan: (scanId: string, updates: Partial<Scan>) => void
  addEndpoint: (endpoint: Endpoint) => void
  addVulnerability: (vulnerability: Vulnerability) => void
  setEndpoints: (endpoints: Endpoint[]) => void
  setVulnerabilities: (vulnerabilities: Vulnerability[]) => void
  addLog: (level: string, message: string) => void
  setLogs: (logs: LogEntry[]) => void
  addAgentTask: (task: ScanAgentTask) => void
  updateAgentTask: (taskId: string, updates: Partial<ScanAgentTask>) => void
  setAgentTasks: (tasks: ScanAgentTask[]) => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
  loadScanData: (scanId: string) => void
  saveScanData: (scanId: string) => void
  reset: () => void
  resetCurrentScan: () => void

  getVulnCounts: () => { critical: number; high: number; medium: number; low: number; info: number }
}

export const useScanStore = create<ScanState>()(
  persist(
    (set, get) => ({
      currentScan: null,
      scans: [],
      endpoints: [],
      vulnerabilities: [],
      logs: [],
      agentTasks: [],
      scanDataCache: {},
      isLoading: false,
      error: null,

      setCurrentScan: (scan) => set({ currentScan: scan }),
      setScans: (scans) => set({ scans }),
      updateScan: (scanId, updates) =>
        set((state) => ({
          currentScan:
            state.currentScan?.id === scanId
              ? { ...state.currentScan, ...updates }
              : state.currentScan,
          scans: state.scans.map((s) => (s.id === scanId ? { ...s, ...updates } : s)),
        })),
      addEndpoint: (endpoint) =>
        set((state) => {
          const exists = state.endpoints.some(e => e.id === endpoint.id || (e.url === endpoint.url && e.method === endpoint.method))
          if (exists) return state
          return { endpoints: [...state.endpoints, endpoint] }
        }),
      addVulnerability: (vulnerability) =>
        set((state) => {
          const exists = state.vulnerabilities.some(v => v.id === vulnerability.id)
          if (exists) return state
          return { vulnerabilities: [...state.vulnerabilities, vulnerability] }
        }),
      setEndpoints: (endpoints) => set({ endpoints }),
      setVulnerabilities: (vulnerabilities) => set({ vulnerabilities }),
      addLog: (level, message) =>
        set((state) => ({
          logs: [...state.logs, { level, message, time: new Date().toISOString() }].slice(-200)
        })),
      setLogs: (logs) => set({ logs }),

      // Agent Tasks
      addAgentTask: (task) =>
        set((state) => {
          const exists = state.agentTasks.some(t => t.id === task.id)
          if (exists) {
            // Update existing task
            return {
              agentTasks: state.agentTasks.map(t => t.id === task.id ? task : t)
            }
          }
          return { agentTasks: [...state.agentTasks, task] }
        }),
      updateAgentTask: (taskId, updates) =>
        set((state) => ({
          agentTasks: state.agentTasks.map(t =>
            t.id === taskId ? { ...t, ...updates } : t
          )
        })),
      setAgentTasks: (agentTasks) => set({ agentTasks }),

      setLoading: (isLoading) => set({ isLoading }),
      setError: (error) => set({ error }),

      loadScanData: (scanId) => {
        const state = get()
        const cached = state.scanDataCache[scanId]
        if (cached) {
          set({
            endpoints: cached.endpoints,
            vulnerabilities: cached.vulnerabilities,
            logs: cached.logs,
            agentTasks: cached.agentTasks || []
          })
        }
      },

      saveScanData: (scanId) => {
        const state = get()
        set({
          scanDataCache: {
            ...state.scanDataCache,
            [scanId]: {
              endpoints: state.endpoints,
              vulnerabilities: state.vulnerabilities,
              logs: state.logs,
              agentTasks: state.agentTasks
            }
          }
        })
      },

      reset: () =>
        set({
          currentScan: null,
          scans: [],
          endpoints: [],
          vulnerabilities: [],
          logs: [],
          agentTasks: [],
          scanDataCache: {},
          isLoading: false,
          error: null,
        }),

      resetCurrentScan: () =>
        set({
          endpoints: [],
          vulnerabilities: [],
          logs: [],
          agentTasks: [],
        }),

      getVulnCounts: () => {
        const vulns = get().vulnerabilities
        return {
          critical: vulns.filter(v => v.severity === 'critical').length,
          high: vulns.filter(v => v.severity === 'high').length,
          medium: vulns.filter(v => v.severity === 'medium').length,
          low: vulns.filter(v => v.severity === 'low').length,
          info: vulns.filter(v => v.severity === 'info').length,
        }
      }
    }),
    {
      name: 'neurosploit-scan-store',
      partialize: (state) => ({
        scanDataCache: state.scanDataCache,
        scans: state.scans
      })
    }
  )
)

interface DashboardState {
  stats: DashboardStats | null
  recentScans: Scan[]
  recentVulnerabilities: Vulnerability[]
  isLoading: boolean

  setStats: (stats: DashboardStats) => void
  setRecentScans: (scans: Scan[]) => void
  setRecentVulnerabilities: (vulns: Vulnerability[]) => void
  setLoading: (loading: boolean) => void
}

export const useDashboardStore = create<DashboardState>((set) => ({
  stats: null,
  recentScans: [],
  recentVulnerabilities: [],
  isLoading: false,

  setStats: (stats) => set({ stats }),
  setRecentScans: (recentScans) => set({ recentScans }),
  setRecentVulnerabilities: (recentVulnerabilities) => set({ recentVulnerabilities }),
  setLoading: (isLoading) => set({ isLoading }),
}))
