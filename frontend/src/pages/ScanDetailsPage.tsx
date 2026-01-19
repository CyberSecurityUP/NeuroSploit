import { useEffect, useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Globe, FileText, StopCircle, RefreshCw, ChevronDown, ChevronRight,
  ExternalLink, Copy, Shield, AlertTriangle
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { SeverityBadge } from '../components/common/Badge'
import { scansApi, reportsApi } from '../services/api'
import { wsService } from '../services/websocket'
import { useScanStore } from '../store'
import type { Endpoint, Vulnerability, WSMessage } from '../types'

export default function ScanDetailsPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const {
    currentScan, endpoints, vulnerabilities, logs,
    setCurrentScan, setEndpoints, setVulnerabilities,
    addEndpoint, addVulnerability, addLog, updateScan,
    loadScanData, saveScanData, getVulnCounts
  } = useScanStore()

  const [isGeneratingReport, setIsGeneratingReport] = useState(false)
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set())
  const [activeTab, setActiveTab] = useState<'endpoints' | 'vulns'>('vulns')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Calculate vulnerability counts from actual data
  const vulnCounts = useMemo(() => getVulnCounts(), [vulnerabilities])

  useEffect(() => {
    if (!scanId) return

    // Try to load cached data first
    loadScanData(scanId)

    // Fetch initial data from API
    const fetchData = async () => {
      setIsLoading(true)
      setError(null)
      try {
        const scan = await scansApi.get(scanId)
        setCurrentScan(scan)

        const [endpointsData, vulnsData] = await Promise.all([
          scansApi.getEndpoints(scanId),
          scansApi.getVulnerabilities(scanId)
        ])

        // Only set if we have data from API
        if (endpointsData.endpoints?.length > 0) {
          setEndpoints(endpointsData.endpoints)
        }
        if (vulnsData.vulnerabilities?.length > 0) {
          setVulnerabilities(vulnsData.vulnerabilities)
        }
      } catch (err: any) {
        console.error('Failed to fetch scan:', err)
        setError(err?.response?.data?.detail || 'Failed to load scan')
      } finally {
        setIsLoading(false)
      }
    }
    fetchData()

    // Poll for updates while scan is running
    const pollInterval = setInterval(async () => {
      if (currentScan?.status === 'running' || !currentScan) {
        try {
          const scan = await scansApi.get(scanId)
          setCurrentScan(scan)

          const [endpointsData, vulnsData] = await Promise.all([
            scansApi.getEndpoints(scanId),
            scansApi.getVulnerabilities(scanId)
          ])

          if (endpointsData.endpoints?.length > 0) {
            setEndpoints(endpointsData.endpoints)
          }
          if (vulnsData.vulnerabilities?.length > 0) {
            setVulnerabilities(vulnsData.vulnerabilities)
          }
        } catch (err) {
          console.error('Poll error:', err)
        }
      }
    }, 3000)

    // Connect WebSocket for running scans
    wsService.connect(scanId)

    // Subscribe to events
    const unsubscribe = wsService.subscribe('*', (message: WSMessage) => {
      switch (message.type) {
        case 'progress_update':
          updateScan(scanId, {
            progress: message.progress as number,
            current_phase: message.message as string
          })
          break
        case 'phase_change':
          updateScan(scanId, { current_phase: message.phase as string })
          addLog('info', `Phase: ${message.phase}`)
          break
        case 'endpoint_found':
          addEndpoint(message.endpoint as Endpoint)
          break
        case 'vuln_found':
          addVulnerability(message.vulnerability as Vulnerability)
          addLog('warning', `Found: ${(message.vulnerability as Vulnerability).title}`)
          break
        case 'log_message':
          addLog(message.level as string, message.message as string)
          break
        case 'scan_completed':
          updateScan(scanId, { status: 'completed', progress: 100 })
          addLog('info', 'Scan completed')
          // Save data when scan completes
          saveScanData(scanId)
          break
        case 'error':
          addLog('error', message.error as string)
          break
      }
    })

    return () => {
      // Save data before unmounting
      saveScanData(scanId)
      unsubscribe()
      wsService.disconnect()
      clearInterval(pollInterval)
    }
  }, [scanId])

  const handleStopScan = async () => {
    if (!scanId) return
    try {
      await scansApi.stop(scanId)
      updateScan(scanId, { status: 'stopped' })
      saveScanData(scanId)
    } catch (error) {
      console.error('Failed to stop scan:', error)
    }
  }

  const handleGenerateReport = async () => {
    if (!scanId) return
    setIsGeneratingReport(true)
    try {
      const report = await reportsApi.generate({
        scan_id: scanId,
        format: 'html',
        include_poc: true,
        include_remediation: true
      })
      window.open(reportsApi.getViewUrl(report.id), '_blank')
    } catch (error) {
      console.error('Failed to generate report:', error)
    } finally {
      setIsGeneratingReport(false)
    }
  }

  const toggleVuln = (id: string) => {
    const newExpanded = new Set(expandedVulns)
    if (newExpanded.has(id)) {
      newExpanded.delete(id)
    } else {
      newExpanded.add(id)
    }
    setExpandedVulns(newExpanded)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-primary-500" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-64">
        <AlertTriangle className="w-12 h-12 text-red-500 mb-4" />
        <p className="text-xl text-white mb-2">Failed to load scan</p>
        <p className="text-dark-400 mb-4">{error}</p>
        <Button onClick={() => navigate('/')}>Go to Dashboard</Button>
      </div>
    )
  }

  if (!currentScan) {
    return (
      <div className="flex flex-col items-center justify-center h-64">
        <AlertTriangle className="w-12 h-12 text-yellow-500 mb-4" />
        <p className="text-xl text-white mb-2">Scan not found</p>
        <p className="text-dark-400 mb-4">The scan may still be initializing or does not exist.</p>
        <div className="flex gap-2">
          <Button onClick={() => window.location.reload()}>Refresh</Button>
          <Button variant="secondary" onClick={() => navigate('/')}>Go to Dashboard</Button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-primary-500" />
            {currentScan.name || 'Unnamed Scan'}
          </h2>
          <div className="flex items-center gap-3 mt-2">
            <SeverityBadge severity={currentScan.status} />
            <span className="text-dark-400">
              Started {new Date(currentScan.created_at).toLocaleString()}
            </span>
          </div>
        </div>
        <div className="flex gap-2">
          {currentScan.status === 'running' && (
            <Button variant="danger" onClick={handleStopScan}>
              <StopCircle className="w-4 h-4 mr-2" />
              Stop Scan
            </Button>
          )}
          {currentScan.status === 'completed' && (
            <Button onClick={handleGenerateReport} isLoading={isGeneratingReport}>
              <FileText className="w-4 h-4 mr-2" />
              Generate Report
            </Button>
          )}
        </div>
      </div>

      {/* Progress */}
      {currentScan.status === 'running' && (
        <Card>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-dark-300">{currentScan.current_phase || 'Initializing...'}</span>
              <span className="text-white font-medium">{currentScan.progress}%</span>
            </div>
            <div className="h-2 bg-dark-900 rounded-full overflow-hidden">
              <div
                className="h-full bg-primary-500 rounded-full transition-all duration-300"
                style={{ width: `${currentScan.progress}%` }}
              />
            </div>
          </div>
        </Card>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <Card>
          <div className="text-center">
            <p className="text-2xl font-bold text-white">{endpoints.length}</p>
            <p className="text-sm text-dark-400">Endpoints</p>
          </div>
        </Card>
        <Card>
          <div className="text-center">
            <p className="text-2xl font-bold text-white">{vulnerabilities.length}</p>
            <p className="text-sm text-dark-400">Total Vulns</p>
          </div>
        </Card>
        <Card>
          <div className="text-center">
            <p className="text-2xl font-bold text-red-500">{vulnCounts.critical}</p>
            <p className="text-sm text-dark-400">Critical</p>
          </div>
        </Card>
        <Card>
          <div className="text-center">
            <p className="text-2xl font-bold text-orange-500">{vulnCounts.high}</p>
            <p className="text-sm text-dark-400">High</p>
          </div>
        </Card>
        <Card>
          <div className="text-center">
            <p className="text-2xl font-bold text-yellow-500">{vulnCounts.medium}</p>
            <p className="text-sm text-dark-400">Medium</p>
          </div>
        </Card>
        <Card>
          <div className="text-center">
            <p className="text-2xl font-bold text-blue-500">{vulnCounts.low}</p>
            <p className="text-sm text-dark-400">Low</p>
          </div>
        </Card>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-dark-700 pb-2">
        <Button
          variant={activeTab === 'vulns' ? 'primary' : 'ghost'}
          onClick={() => setActiveTab('vulns')}
        >
          <AlertTriangle className="w-4 h-4 mr-2" />
          Vulnerabilities ({vulnerabilities.length})
        </Button>
        <Button
          variant={activeTab === 'endpoints' ? 'primary' : 'ghost'}
          onClick={() => setActiveTab('endpoints')}
        >
          <Globe className="w-4 h-4 mr-2" />
          Endpoints ({endpoints.length})
        </Button>
      </div>

      {/* Vulnerabilities Tab */}
      {activeTab === 'vulns' && (
        <div className="space-y-3">
          {vulnerabilities.length === 0 ? (
            <Card>
              <p className="text-dark-400 text-center py-8">
                {currentScan.status === 'running' ? 'Scanning for vulnerabilities...' : 'No vulnerabilities found'}
              </p>
            </Card>
          ) : (
            vulnerabilities.map((vuln, idx) => (
              <div
                key={vuln.id || `vuln-${idx}`}
                className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden"
              >
                {/* Vulnerability Header */}
                <div
                  className="p-4 cursor-pointer hover:bg-dark-750 transition-colors"
                  onClick={() => toggleVuln(vuln.id || `vuln-${idx}`)}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-2 flex-1">
                      {expandedVulns.has(vuln.id || `vuln-${idx}`) ? (
                        <ChevronDown className="w-4 h-4 mt-1 text-dark-400" />
                      ) : (
                        <ChevronRight className="w-4 h-4 mt-1 text-dark-400" />
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-white">{vuln.title}</p>
                        <p className="text-sm text-dark-400 truncate mt-1">{vuln.affected_endpoint}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {vuln.cvss_score && (
                        <span className={`text-sm font-bold px-2 py-0.5 rounded ${
                          vuln.cvss_score >= 9 ? 'bg-red-500/20 text-red-400' :
                          vuln.cvss_score >= 7 ? 'bg-orange-500/20 text-orange-400' :
                          vuln.cvss_score >= 4 ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-blue-500/20 text-blue-400'
                        }`}>
                          CVSS {vuln.cvss_score.toFixed(1)}
                        </span>
                      )}
                      <SeverityBadge severity={vuln.severity} />
                    </div>
                  </div>
                </div>

                {/* Vulnerability Details */}
                {expandedVulns.has(vuln.id || `vuln-${idx}`) && (
                  <div className="p-4 pt-0 space-y-4 border-t border-dark-700">
                    {/* Meta Info */}
                    <div className="flex flex-wrap items-center gap-4 text-sm">
                      {vuln.vulnerability_type && (
                        <span className="text-dark-400">
                          Type: <span className="text-white">{vuln.vulnerability_type}</span>
                        </span>
                      )}
                      {vuln.cwe_id && (
                        <a
                          href={`https://cwe.mitre.org/data/definitions/${vuln.cwe_id.replace('CWE-', '')}.html`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary-400 hover:underline flex items-center gap-1"
                        >
                          {vuln.cwe_id}
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                      {vuln.cvss_vector && (
                        <span className="text-xs bg-dark-700 px-2 py-1 rounded font-mono text-dark-300">
                          {vuln.cvss_vector}
                        </span>
                      )}
                    </div>

                    {/* Description */}
                    {vuln.description && (
                      <div>
                        <p className="text-sm font-medium text-dark-300 mb-1">Description</p>
                        <p className="text-sm text-dark-400">{vuln.description}</p>
                      </div>
                    )}

                    {/* Impact */}
                    {vuln.impact && (
                      <div>
                        <p className="text-sm font-medium text-dark-300 mb-1">Impact</p>
                        <p className="text-sm text-dark-400">{vuln.impact}</p>
                      </div>
                    )}

                    {/* Proof of Concept */}
                    {(vuln.poc_request || vuln.poc_payload) && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <p className="text-sm font-medium text-dark-300">Proof of Concept</p>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(vuln.poc_request || vuln.poc_payload || '')}
                          >
                            <Copy className="w-3 h-3 mr-1" />
                            Copy
                          </Button>
                        </div>
                        {vuln.poc_payload && (
                          <div className="mb-2">
                            <p className="text-xs text-dark-500 mb-1">Payload:</p>
                            <pre className="text-xs bg-dark-900 p-3 rounded overflow-x-auto text-yellow-400 font-mono">
                              {vuln.poc_payload}
                            </pre>
                          </div>
                        )}
                        {vuln.poc_request && (
                          <div>
                            <p className="text-xs text-dark-500 mb-1">Request:</p>
                            <pre className="text-xs bg-dark-900 p-3 rounded overflow-x-auto text-dark-300 font-mono">
                              {vuln.poc_request}
                            </pre>
                          </div>
                        )}
                        {vuln.poc_response && (
                          <div className="mt-2">
                            <p className="text-xs text-dark-500 mb-1">Response:</p>
                            <pre className="text-xs bg-dark-900 p-3 rounded overflow-x-auto text-dark-300 font-mono max-h-40">
                              {vuln.poc_response}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Remediation */}
                    {vuln.remediation && (
                      <div>
                        <p className="text-sm font-medium text-green-400 mb-1">Remediation</p>
                        <p className="text-sm text-dark-400">{vuln.remediation}</p>
                      </div>
                    )}

                    {/* AI Analysis */}
                    {vuln.ai_analysis && (
                      <div>
                        <p className="text-sm font-medium text-purple-400 mb-1">AI Analysis</p>
                        <p className="text-sm text-dark-400 whitespace-pre-wrap">{vuln.ai_analysis}</p>
                      </div>
                    )}

                    {/* References */}
                    {vuln.references?.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-dark-300 mb-1">References</p>
                        <div className="flex flex-wrap gap-2">
                          {vuln.references.map((ref, i) => (
                            <a
                              key={i}
                              href={ref}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs text-primary-400 hover:underline flex items-center gap-1"
                            >
                              {(() => {
                                try {
                                  return new URL(ref).hostname
                                } catch {
                                  return ref
                                }
                              })()}
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* Endpoints Tab */}
      {activeTab === 'endpoints' && (
        <Card title="Discovered Endpoints" subtitle={`${endpoints.length} endpoints found`}>
          <div className="space-y-2 max-h-[500px] overflow-auto">
            {endpoints.length === 0 ? (
              <p className="text-dark-400 text-center py-8">No endpoints discovered yet</p>
            ) : (
              endpoints.map((endpoint, idx) => (
                <div
                  key={endpoint.id || `endpoint-${idx}`}
                  className="flex items-center gap-3 p-3 bg-dark-900/50 rounded-lg hover:bg-dark-900 transition-colors"
                >
                  <Globe className="w-4 h-4 text-dark-400 flex-shrink-0" />
                  <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                    endpoint.method === 'GET' ? 'bg-green-500/20 text-green-400' :
                    endpoint.method === 'POST' ? 'bg-blue-500/20 text-blue-400' :
                    endpoint.method === 'PUT' ? 'bg-yellow-500/20 text-yellow-400' :
                    endpoint.method === 'DELETE' ? 'bg-red-500/20 text-red-400' :
                    'bg-dark-700 text-dark-300'
                  }`}>
                    {endpoint.method}
                  </span>
                  <span className="text-sm text-dark-200 truncate flex-1 font-mono">
                    {endpoint.path || endpoint.url}
                  </span>
                  {endpoint.parameters?.length > 0 && (
                    <span className="text-xs text-dark-500">
                      {endpoint.parameters.length} params
                    </span>
                  )}
                  {endpoint.content_type && (
                    <span className="text-xs text-dark-500">{endpoint.content_type}</span>
                  )}
                  {endpoint.response_status && (
                    <span className={`text-xs font-medium ${
                      endpoint.response_status < 300 ? 'text-green-400' :
                      endpoint.response_status < 400 ? 'text-yellow-400' :
                      'text-red-400'
                    }`}>
                      {endpoint.response_status}
                    </span>
                  )}
                </div>
              ))
            )}
          </div>
        </Card>
      )}

      {/* Activity Log */}
      <Card title="Activity Log">
        <div className="space-y-1 max-h-60 overflow-auto font-mono text-xs">
          {logs.length === 0 ? (
            <p className="text-dark-400 text-center py-4">Waiting for activity...</p>
          ) : (
            logs.map((log, i) => (
              <div key={i} className="flex gap-2">
                <span className="text-dark-500">{new Date(log.time).toLocaleTimeString()}</span>
                <span className={`${
                  log.level === 'error' ? 'text-red-400' :
                  log.level === 'warning' ? 'text-yellow-400' :
                  log.level === 'success' ? 'text-green-400' :
                  'text-dark-300'
                }`}>
                  {log.message}
                </span>
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  )
}
