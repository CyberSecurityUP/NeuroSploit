import { useState, useEffect, useCallback } from 'react'
import { Plus, Trash2, Play, Pause, Clock, RefreshCw, Target, Calendar, ChevronDown, Shield, Zap, Search, Settings2, AlertTriangle, CheckCircle2 } from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import Input from '../components/common/Input'
import { schedulerApi } from '../services/api'
import type { ScheduleJob, AgentRole } from '../types'

// Cron presets for quick selection
const CRON_PRESETS = [
  { label: 'Every Hour', value: '0 * * * *', desc: 'Runs at the start of every hour' },
  { label: 'Every 6 Hours', value: '0 */6 * * *', desc: 'Runs every 6 hours' },
  { label: 'Daily at 2 AM', value: '0 2 * * *', desc: 'Runs once a day at 2:00 AM' },
  { label: 'Daily at Midnight', value: '0 0 * * *', desc: 'Runs once a day at midnight' },
  { label: 'Weekdays at 9 AM', value: '0 9 * * 1-5', desc: 'Monday to Friday at 9:00 AM' },
  { label: 'Weekly (Monday)', value: '0 0 * * 1', desc: 'Every Monday at midnight' },
  { label: 'Weekly (Friday)', value: '0 18 * * 5', desc: 'Every Friday at 6:00 PM' },
  { label: 'Monthly (1st)', value: '0 0 1 * *', desc: 'First day of each month' },
  { label: 'Custom', value: 'custom', desc: 'Enter a custom cron expression' },
]

const SCAN_TYPES = [
  { id: 'quick', label: 'Quick', icon: Zap, desc: 'Fast surface scan' },
  { id: 'full', label: 'Full', icon: Search, desc: 'Comprehensive analysis' },
  { id: 'custom', label: 'Custom', icon: Settings2, desc: 'Custom configuration' },
]

const DAYS_OF_WEEK = [
  { id: 0, short: 'Sun', full: 'Sunday' },
  { id: 1, short: 'Mon', full: 'Monday' },
  { id: 2, short: 'Tue', full: 'Tuesday' },
  { id: 3, short: 'Wed', full: 'Wednesday' },
  { id: 4, short: 'Thu', full: 'Thursday' },
  { id: 5, short: 'Fri', full: 'Friday' },
  { id: 6, short: 'Sat', full: 'Saturday' },
]

export default function SchedulerPage() {
  const [jobs, setJobs] = useState<ScheduleJob[]>([])
  const [agentRoles, setAgentRoles] = useState<AgentRole[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  // Form state
  const [jobId, setJobId] = useState('')
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('quick')
  const [scheduleMode, setScheduleMode] = useState<'interval' | 'preset' | 'days'>('preset')
  const [cronPreset, setCronPreset] = useState('0 2 * * *')
  const [customCron, setCustomCron] = useState('')
  const [intervalMinutes, setIntervalMinutes] = useState('60')
  const [selectedDays, setSelectedDays] = useState<number[]>([1, 2, 3, 4, 5])
  const [executionHour, setExecutionHour] = useState('02')
  const [executionMinute, setExecutionMinute] = useState('00')
  const [agentRole, setAgentRole] = useState('')
  const [showRoleDropdown, setShowRoleDropdown] = useState(false)
  const [isCreating, setIsCreating] = useState(false)

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const [jobsData, rolesData] = await Promise.all([
        schedulerApi.list(),
        schedulerApi.getAgentRoles(),
      ])
      setJobs(jobsData)
      setAgentRoles(rolesData)
    } catch (error) {
      console.error('Failed to fetch scheduler data:', error)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  // Auto-dismiss messages after 4 seconds
  useEffect(() => {
    if (message) {
      const timer = setTimeout(() => setMessage(null), 4000)
      return () => clearTimeout(timer)
    }
  }, [message])

  const buildCronExpression = (): string | undefined => {
    if (scheduleMode === 'interval') return undefined
    if (scheduleMode === 'preset') {
      return cronPreset === 'custom' ? customCron : cronPreset
    }
    // days mode: build cron from selected days + time
    if (selectedDays.length === 0) return undefined
    const daysStr = selectedDays.sort((a, b) => a - b).join(',')
    return `${executionMinute} ${executionHour} * * ${daysStr}`
  }

  const getIntervalMinutes = (): number | undefined => {
    if (scheduleMode !== 'interval') return undefined
    return parseInt(intervalMinutes) || 60
  }

  const handleCreate = async () => {
    if (!jobId.trim()) {
      setMessage({ type: 'error', text: 'Job ID is required' })
      return
    }
    if (!target.trim()) {
      setMessage({ type: 'error', text: 'Target URL is required' })
      return
    }

    const cron = buildCronExpression()
    const interval = getIntervalMinutes()

    if (!cron && !interval) {
      setMessage({ type: 'error', text: 'Please configure a schedule (select days or set interval)' })
      return
    }

    setIsCreating(true)
    setMessage(null)

    try {
      await schedulerApi.create({
        job_id: jobId.trim(),
        target: target.trim(),
        scan_type: scanType,
        cron_expression: cron,
        interval_minutes: interval,
        agent_role: agentRole || undefined,
      })
      setMessage({ type: 'success', text: `Schedule "${jobId}" created successfully` })
      setShowForm(false)
      resetForm()
      fetchData()
    } catch (error: any) {
      const detail = error?.response?.data?.detail || 'Failed to create schedule'
      setMessage({ type: 'error', text: detail })
    } finally {
      setIsCreating(false)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await schedulerApi.delete(id)
      setMessage({ type: 'success', text: `Schedule "${id}" deleted` })
      setDeleteConfirm(null)
      fetchData()
    } catch (error) {
      setMessage({ type: 'error', text: `Failed to delete "${id}"` })
    }
  }

  const handlePause = async (id: string) => {
    try {
      await schedulerApi.pause(id)
      fetchData()
    } catch (error) {
      setMessage({ type: 'error', text: `Failed to pause "${id}"` })
    }
  }

  const handleResume = async (id: string) => {
    try {
      await schedulerApi.resume(id)
      fetchData()
    } catch (error) {
      setMessage({ type: 'error', text: `Failed to resume "${id}"` })
    }
  }

  const toggleDay = (dayId: number) => {
    setSelectedDays(prev =>
      prev.includes(dayId) ? prev.filter(d => d !== dayId) : [...prev, dayId]
    )
  }

  const resetForm = () => {
    setJobId('')
    setTarget('')
    setScanType('quick')
    setScheduleMode('preset')
    setCronPreset('0 2 * * *')
    setCustomCron('')
    setIntervalMinutes('60')
    setSelectedDays([1, 2, 3, 4, 5])
    setExecutionHour('02')
    setExecutionMinute('00')
    setAgentRole('')
    setShowRoleDropdown(false)
  }

  const selectedRole = agentRoles.find(r => r.id === agentRole)

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="p-2 bg-brand-500/20 rounded-lg">
              <Calendar className="w-6 h-6 text-brand-400" />
            </div>
            Scan Scheduler
          </h2>
          <p className="text-dark-400 mt-1 ml-14">Schedule automated recurring scans with agent specialization</p>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" onClick={fetchData}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button onClick={() => { setShowForm(!showForm); if (showForm) resetForm() }}>
            <Plus className="w-4 h-4 mr-2" />
            New Schedule
          </Button>
        </div>
      </div>

      {/* Status Message */}
      {message && (
        <div className={`flex items-center gap-3 p-4 rounded-lg border transition-all ${
          message.type === 'success'
            ? 'bg-green-500/10 border-green-500/30 text-green-400'
            : 'bg-red-500/10 border-red-500/30 text-red-400'
        }`}>
          {message.type === 'success'
            ? <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
            : <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          }
          <span>{message.text}</span>
        </div>
      )}

      {/* Create Form */}
      {showForm && (
        <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
          <div className="p-5 border-b border-dark-700">
            <h3 className="text-lg font-semibold text-white">Create New Schedule</h3>
            <p className="text-dark-400 text-sm mt-1">Configure a recurring scan with specialized agent roles</p>
          </div>

          <div className="p-5 space-y-6">
            {/* Row 1: Job ID + Target */}
            <div className="grid grid-cols-2 gap-4">
              <Input
                label="Job ID"
                placeholder="daily-scan-prod"
                value={jobId}
                onChange={(e) => setJobId(e.target.value)}
                helperText="Unique identifier for this schedule"
              />
              <Input
                label="Target URL"
                placeholder="https://example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                helperText="URL to scan on each execution"
              />
            </div>

            {/* Row 2: Scan Type */}
            <div>
              <label className="block text-sm font-medium text-dark-200 mb-3">Scan Type</label>
              <div className="grid grid-cols-3 gap-3">
                {SCAN_TYPES.map(({ id, label, icon: Icon, desc }) => (
                  <button
                    key={id}
                    onClick={() => setScanType(id)}
                    className={`p-4 rounded-lg border-2 text-left transition-all ${
                      scanType === id
                        ? 'border-brand-500 bg-brand-500/10'
                        : 'border-dark-600 bg-dark-900/50 hover:border-dark-500'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Icon className={`w-4 h-4 ${scanType === id ? 'text-brand-400' : 'text-dark-400'}`} />
                      <span className={`font-medium ${scanType === id ? 'text-white' : 'text-dark-300'}`}>{label}</span>
                    </div>
                    <p className="text-xs text-dark-500">{desc}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* Row 3: Agent Role Dropdown */}
            <div>
              <label className="block text-sm font-medium text-dark-200 mb-3">
                <Shield className="w-4 h-4 inline mr-1 -mt-0.5" />
                Agent Role
              </label>
              <div className="relative">
                <button
                  onClick={() => setShowRoleDropdown(!showRoleDropdown)}
                  className="w-full flex items-center justify-between p-3 rounded-lg border border-dark-600 bg-dark-900/50 hover:border-dark-500 transition-colors text-left"
                >
                  <div>
                    {selectedRole ? (
                      <>
                        <span className="text-white font-medium">{selectedRole.name}</span>
                        <span className="text-dark-500 text-sm ml-2">- {selectedRole.description}</span>
                      </>
                    ) : (
                      <span className="text-dark-500">Select an agent role (optional)</span>
                    )}
                  </div>
                  <ChevronDown className={`w-4 h-4 text-dark-400 transition-transform ${showRoleDropdown ? 'rotate-180' : ''}`} />
                </button>

                {showRoleDropdown && (
                  <div className="absolute z-20 w-full mt-1 bg-dark-800 border border-dark-600 rounded-lg shadow-xl max-h-72 overflow-y-auto">
                    {/* None option */}
                    <button
                      onClick={() => { setAgentRole(''); setShowRoleDropdown(false) }}
                      className={`w-full flex items-start gap-3 p-3 text-left hover:bg-dark-700/50 transition-colors border-b border-dark-700/50 ${
                        !agentRole ? 'bg-dark-700/30' : ''
                      }`}
                    >
                      <div className="w-8 h-8 rounded-lg bg-dark-600 flex items-center justify-center flex-shrink-0 mt-0.5">
                        <Target className="w-4 h-4 text-dark-400" />
                      </div>
                      <div>
                        <p className="text-dark-300 font-medium">Default Agent</p>
                        <p className="text-dark-500 text-xs">No specialization - uses general pentest agent</p>
                      </div>
                    </button>

                    {agentRoles.map((role) => (
                      <button
                        key={role.id}
                        onClick={() => { setAgentRole(role.id); setShowRoleDropdown(false) }}
                        className={`w-full flex items-start gap-3 p-3 text-left hover:bg-dark-700/50 transition-colors ${
                          agentRole === role.id ? 'bg-brand-500/10 border-l-2 border-brand-500' : ''
                        }`}
                      >
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 ${
                          agentRole === role.id ? 'bg-brand-500/20' : 'bg-dark-600'
                        }`}>
                          <Shield className={`w-4 h-4 ${agentRole === role.id ? 'text-brand-400' : 'text-dark-400'}`} />
                        </div>
                        <div className="min-w-0">
                          <p className={`font-medium ${agentRole === role.id ? 'text-brand-400' : 'text-white'}`}>
                            {role.name}
                          </p>
                          <p className="text-dark-500 text-xs mt-0.5">{role.description}</p>
                          {role.tools.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1.5">
                              {role.tools.slice(0, 4).map(tool => (
                                <span key={tool} className="px-1.5 py-0.5 text-[10px] bg-dark-600 text-dark-300 rounded">
                                  {tool}
                                </span>
                              ))}
                              {role.tools.length > 4 && (
                                <span className="px-1.5 py-0.5 text-[10px] bg-dark-600 text-dark-400 rounded">
                                  +{role.tools.length - 4}
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Row 4: Schedule Configuration */}
            <div>
              <label className="block text-sm font-medium text-dark-200 mb-3">
                <Clock className="w-4 h-4 inline mr-1 -mt-0.5" />
                Schedule
              </label>

              {/* Schedule mode tabs */}
              <div className="flex gap-1 p-1 bg-dark-900/50 rounded-lg mb-4">
                {[
                  { id: 'preset' as const, label: 'Presets' },
                  { id: 'days' as const, label: 'Days & Time' },
                  { id: 'interval' as const, label: 'Interval' },
                ].map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setScheduleMode(tab.id)}
                    className={`flex-1 py-2 px-3 rounded-md text-sm font-medium transition-all ${
                      scheduleMode === tab.id
                        ? 'bg-brand-500 text-white shadow-sm'
                        : 'text-dark-400 hover:text-dark-200'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Preset mode */}
              {scheduleMode === 'preset' && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-2">
                    {CRON_PRESETS.map(preset => (
                      <button
                        key={preset.value}
                        onClick={() => setCronPreset(preset.value)}
                        className={`p-3 rounded-lg border text-left transition-all ${
                          cronPreset === preset.value
                            ? 'border-brand-500 bg-brand-500/10'
                            : 'border-dark-600 bg-dark-900/30 hover:border-dark-500'
                        }`}
                      >
                        <p className={`text-sm font-medium ${cronPreset === preset.value ? 'text-brand-400' : 'text-dark-200'}`}>
                          {preset.label}
                        </p>
                        <p className="text-xs text-dark-500 mt-0.5">{preset.desc}</p>
                      </button>
                    ))}
                  </div>
                  {cronPreset === 'custom' && (
                    <Input
                      label="Custom Cron Expression"
                      placeholder="*/30 * * * *"
                      value={customCron}
                      onChange={(e) => setCustomCron(e.target.value)}
                      helperText="Format: minute hour day-of-month month day-of-week"
                    />
                  )}
                </div>
              )}

              {/* Days & Time mode */}
              {scheduleMode === 'days' && (
                <div className="space-y-4">
                  <div>
                    <p className="text-sm text-dark-400 mb-2">Select days of the week</p>
                    <div className="flex gap-2">
                      {DAYS_OF_WEEK.map(day => (
                        <button
                          key={day.id}
                          onClick={() => toggleDay(day.id)}
                          className={`flex-1 py-3 rounded-lg border-2 text-center text-sm font-medium transition-all ${
                            selectedDays.includes(day.id)
                              ? 'border-brand-500 bg-brand-500/15 text-brand-400'
                              : 'border-dark-600 bg-dark-900/30 text-dark-400 hover:border-dark-500'
                          }`}
                          title={day.full}
                        >
                          {day.short}
                        </button>
                      ))}
                    </div>
                    <div className="flex gap-2 mt-2">
                      <button
                        onClick={() => setSelectedDays([1, 2, 3, 4, 5])}
                        className="text-xs text-brand-400 hover:text-brand-300 transition-colors"
                      >
                        Weekdays
                      </button>
                      <span className="text-dark-600">|</span>
                      <button
                        onClick={() => setSelectedDays([0, 6])}
                        className="text-xs text-brand-400 hover:text-brand-300 transition-colors"
                      >
                        Weekends
                      </button>
                      <span className="text-dark-600">|</span>
                      <button
                        onClick={() => setSelectedDays([0, 1, 2, 3, 4, 5, 6])}
                        className="text-xs text-brand-400 hover:text-brand-300 transition-colors"
                      >
                        Every Day
                      </button>
                    </div>
                  </div>

                  <div>
                    <p className="text-sm text-dark-400 mb-2">Execution Time</p>
                    <div className="flex items-center gap-2">
                      <select
                        value={executionHour}
                        onChange={(e) => setExecutionHour(e.target.value)}
                        className="bg-dark-900 border border-dark-600 rounded-lg px-3 py-2.5 text-white text-sm focus:border-brand-500 focus:outline-none"
                      >
                        {Array.from({ length: 24 }, (_, i) => (
                          <option key={i} value={String(i).padStart(2, '0')}>
                            {String(i).padStart(2, '0')}
                          </option>
                        ))}
                      </select>
                      <span className="text-dark-400 text-lg font-bold">:</span>
                      <select
                        value={executionMinute}
                        onChange={(e) => setExecutionMinute(e.target.value)}
                        className="bg-dark-900 border border-dark-600 rounded-lg px-3 py-2.5 text-white text-sm focus:border-brand-500 focus:outline-none"
                      >
                        {['00', '15', '30', '45'].map(m => (
                          <option key={m} value={m}>{m}</option>
                        ))}
                      </select>
                      <span className="text-dark-500 text-sm ml-2">UTC</span>
                    </div>
                  </div>

                  {selectedDays.length > 0 && (
                    <div className="p-3 bg-dark-900/50 rounded-lg border border-dark-700/50">
                      <p className="text-xs text-dark-400">
                        Cron: <code className="text-brand-400 bg-dark-700 px-1.5 py-0.5 rounded">
                          {`${executionMinute} ${executionHour} * * ${selectedDays.sort((a, b) => a - b).join(',')}`}
                        </code>
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Interval mode */}
              {scheduleMode === 'interval' && (
                <div className="space-y-3">
                  <div className="grid grid-cols-4 gap-2">
                    {[
                      { label: '15 min', value: '15' },
                      { label: '30 min', value: '30' },
                      { label: '1 hour', value: '60' },
                      { label: '2 hours', value: '120' },
                      { label: '4 hours', value: '240' },
                      { label: '6 hours', value: '360' },
                      { label: '12 hours', value: '720' },
                      { label: '24 hours', value: '1440' },
                    ].map(opt => (
                      <button
                        key={opt.value}
                        onClick={() => setIntervalMinutes(opt.value)}
                        className={`py-2.5 px-3 rounded-lg border text-sm font-medium transition-all ${
                          intervalMinutes === opt.value
                            ? 'border-brand-500 bg-brand-500/10 text-brand-400'
                            : 'border-dark-600 bg-dark-900/30 text-dark-400 hover:border-dark-500'
                        }`}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                  <Input
                    label="Custom interval (minutes)"
                    type="number"
                    min="1"
                    value={intervalMinutes}
                    onChange={(e) => setIntervalMinutes(e.target.value)}
                    helperText={`Scan runs every ${parseInt(intervalMinutes) >= 60 ? `${Math.floor(parseInt(intervalMinutes) / 60)}h ${parseInt(intervalMinutes) % 60}m` : `${intervalMinutes} minutes`}`}
                  />
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="flex items-center justify-between pt-2 border-t border-dark-700">
              <p className="text-xs text-dark-500">
                {scheduleMode === 'interval'
                  ? `Runs every ${parseInt(intervalMinutes) >= 60 ? `${Math.floor(parseInt(intervalMinutes) / 60)} hour(s)` : `${intervalMinutes} min`}`
                  : scheduleMode === 'days' && selectedDays.length > 0
                    ? `Runs on ${selectedDays.sort((a,b)=>a-b).map(d => DAYS_OF_WEEK[d].short).join(', ')} at ${executionHour}:${executionMinute}`
                    : scheduleMode === 'preset' && cronPreset !== 'custom'
                      ? CRON_PRESETS.find(p => p.value === cronPreset)?.desc || ''
                      : ''
                }
              </p>
              <div className="flex gap-3">
                <Button variant="secondary" onClick={() => { setShowForm(false); resetForm() }}>
                  Cancel
                </Button>
                <Button onClick={handleCreate} isLoading={isCreating}>
                  <Plus className="w-4 h-4 mr-2" />
                  Create Schedule
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Summary Stats */}
      {jobs.length > 0 && (
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
            <p className="text-dark-400 text-sm">Total Schedules</p>
            <p className="text-2xl font-bold text-white mt-1">{jobs.length}</p>
          </div>
          <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
            <p className="text-dark-400 text-sm">Active</p>
            <p className="text-2xl font-bold text-green-400 mt-1">{jobs.filter(j => j.status === 'active').length}</p>
          </div>
          <div className="bg-dark-800/50 border border-dark-700/50 rounded-lg p-4">
            <p className="text-dark-400 text-sm">Total Runs</p>
            <p className="text-2xl font-bold text-brand-400 mt-1">{jobs.reduce((sum, j) => sum + j.run_count, 0)}</p>
          </div>
        </div>
      )}

      {/* Jobs List */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">
            Scheduled Jobs
            <span className="text-dark-500 text-sm font-normal ml-2">
              {jobs.length} job{jobs.length !== 1 ? 's' : ''}
            </span>
          </h3>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-16">
            <RefreshCw className="w-6 h-6 text-dark-400 animate-spin" />
          </div>
        ) : jobs.length === 0 ? (
          <Card>
            <div className="text-center py-16">
              <div className="w-16 h-16 bg-dark-700/50 rounded-full flex items-center justify-center mx-auto mb-4">
                <Calendar className="w-8 h-8 text-dark-500" />
              </div>
              <p className="text-dark-300 font-medium">No scheduled jobs yet</p>
              <p className="text-dark-500 text-sm mt-1 mb-4">Create a schedule to run automated recurring scans</p>
              <Button onClick={() => setShowForm(true)}>
                <Plus className="w-4 h-4 mr-2" />
                Create First Schedule
              </Button>
            </div>
          </Card>
        ) : (
          <div className="space-y-3">
            {jobs.map((job) => (
              <div
                key={job.id}
                className="bg-dark-800 border border-dark-700/50 rounded-xl p-5 hover:border-dark-600 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-4">
                    {/* Status indicator */}
                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${
                      job.status === 'active' ? 'bg-green-500/15' : 'bg-yellow-500/15'
                    }`}>
                      {job.status === 'active'
                        ? <Play className="w-5 h-5 text-green-400" />
                        : <Pause className="w-5 h-5 text-yellow-400" />
                      }
                    </div>

                    <div>
                      <div className="flex items-center gap-3">
                        <p className="font-semibold text-white text-lg">{job.id}</p>
                        <span className={`px-2.5 py-0.5 text-xs rounded-full font-medium ${
                          job.status === 'active'
                            ? 'bg-green-500/15 text-green-400 border border-green-500/30'
                            : 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30'
                        }`}>
                          {job.status}
                        </span>
                        <span className="px-2 py-0.5 text-xs rounded bg-dark-700 text-dark-300">
                          {job.scan_type}
                        </span>
                        {job.agent_role && (
                          <span className="px-2 py-0.5 text-xs rounded bg-brand-500/15 text-brand-400 border border-brand-500/30">
                            {job.agent_role.replace(/_/g, ' ')}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-4 mt-2 text-sm text-dark-400">
                        <span className="flex items-center gap-1.5">
                          <Target className="w-3.5 h-3.5" />
                          {job.target}
                        </span>
                        <span className="flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5" />
                          {job.schedule}
                        </span>
                        {job.run_count > 0 && (
                          <span className="flex items-center gap-1.5">
                            <RefreshCw className="w-3.5 h-3.5" />
                            {job.run_count} run{job.run_count !== 1 ? 's' : ''}
                          </span>
                        )}
                      </div>

                      {(job.next_run || job.last_run) && (
                        <div className="flex items-center gap-4 mt-1.5 text-xs text-dark-500">
                          {job.next_run && (
                            <span>Next: {new Date(job.next_run).toLocaleString()}</span>
                          )}
                          {job.last_run && (
                            <span>Last: {new Date(job.last_run).toLocaleString()}</span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1">
                    {job.status === 'active' ? (
                      <Button variant="ghost" size="sm" onClick={() => handlePause(job.id)} title="Pause schedule">
                        <Pause className="w-4 h-4 text-yellow-400" />
                      </Button>
                    ) : (
                      <Button variant="ghost" size="sm" onClick={() => handleResume(job.id)} title="Resume schedule">
                        <Play className="w-4 h-4 text-green-400" />
                      </Button>
                    )}

                    {deleteConfirm === job.id ? (
                      <div className="flex items-center gap-1 ml-2">
                        <Button variant="ghost" size="sm" onClick={() => handleDelete(job.id)}>
                          <span className="text-red-400 text-xs font-medium">Confirm</span>
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => setDeleteConfirm(null)}>
                          <span className="text-dark-400 text-xs">Cancel</span>
                        </Button>
                      </div>
                    ) : (
                      <Button variant="ghost" size="sm" onClick={() => setDeleteConfirm(job.id)} title="Delete schedule">
                        <Trash2 className="w-4 h-4 text-red-400" />
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
