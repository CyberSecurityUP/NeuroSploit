import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { FileText, Download, Eye, Trash2, Calendar } from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { reportsApi, scansApi } from '../services/api'
import type { Report, Scan } from '../types'

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([])
  const [scans, setScans] = useState<Map<string, Scan>>(new Map())
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [reportsData, scansData] = await Promise.all([
          reportsApi.list(),
          scansApi.list(1, 100)
        ])
        setReports(reportsData.reports)

        const scansMap = new Map<string, Scan>()
        scansData.scans.forEach((scan: Scan) => scansMap.set(scan.id, scan))
        setScans(scansMap)
      } catch (error) {
        console.error('Failed to fetch reports:', error)
      } finally {
        setIsLoading(false)
      }
    }
    fetchData()
  }, [])

  const handleDelete = async (reportId: string) => {
    if (!confirm('Are you sure you want to delete this report?')) return
    try {
      await reportsApi.delete(reportId)
      setReports(reports.filter((r) => r.id !== reportId))
    } catch (error) {
      console.error('Failed to delete report:', error)
    }
  }

  const handleDownload = (reportId: string, format: string) => {
    window.open(reportsApi.getDownloadUrl(reportId, format), '_blank')
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Reports</h2>
          <p className="text-dark-400 mt-1">View and download security assessment reports</p>
        </div>
      </div>

      {reports.length === 0 ? (
        <Card>
          <div className="text-center py-12">
            <FileText className="w-16 h-16 mx-auto text-dark-500 mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No Reports Yet</h3>
            <p className="text-dark-400 mb-4">
              Reports are generated after completing a security scan.
            </p>
            <Link to="/scan/new">
              <Button>Start a New Scan</Button>
            </Link>
          </div>
        </Card>
      ) : (
        <div className="grid gap-4">
          {reports.map((report) => {
            const scan = scans.get(report.scan_id)
            return (
              <Card key={report.id}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="p-3 bg-primary-500/10 rounded-lg">
                      <FileText className="w-6 h-6 text-primary-500" />
                    </div>
                    <div>
                      <h3 className="font-medium text-white">
                        {report.title || scan?.name || 'Security Report'}
                      </h3>
                      <div className="flex items-center gap-3 mt-1 text-sm text-dark-400">
                        <span className="flex items-center gap-1">
                          <Calendar className="w-4 h-4" />
                          {new Date(report.generated_at).toLocaleDateString()}
                        </span>
                        <span className="uppercase text-xs bg-dark-700 px-2 py-0.5 rounded">
                          {report.format}
                        </span>
                        {scan && (
                          <span>
                            {scan.total_vulnerabilities} vulnerabilities
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="ghost"
                      onClick={() => window.open(reportsApi.getViewUrl(report.id), '_blank')}
                    >
                      <Eye className="w-4 h-4 mr-2" />
                      View
                    </Button>
                    <Button
                      variant="secondary"
                      onClick={() => handleDownload(report.id, 'html')}
                    >
                      <Download className="w-4 h-4 mr-2" />
                      HTML
                    </Button>
                    <Button
                      variant="secondary"
                      onClick={() => handleDownload(report.id, 'json')}
                    >
                      <Download className="w-4 h-4 mr-2" />
                      JSON
                    </Button>
                    <Button
                      variant="ghost"
                      onClick={() => handleDelete(report.id)}
                      className="text-red-400 hover:text-red-300"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
