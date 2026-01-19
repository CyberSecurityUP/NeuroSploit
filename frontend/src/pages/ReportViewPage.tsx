import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Download, ExternalLink } from 'lucide-react'
import Button from '../components/common/Button'
import { reportsApi } from '../services/api'

export default function ReportViewPage() {
  const { reportId } = useParams<{ reportId: string }>()
  const navigate = useNavigate()
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    if (!reportId) {
      navigate('/reports')
      return
    }
    setIsLoading(false)
  }, [reportId])

  if (isLoading || !reportId) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <div className="space-y-4 animate-fadeIn">
      <div className="flex items-center justify-between">
        <Button variant="ghost" onClick={() => navigate('/reports')}>
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Reports
        </Button>
        <div className="flex gap-2">
          <Button
            variant="secondary"
            onClick={() => window.open(reportsApi.getDownloadUrl(reportId, 'html'), '_blank')}
          >
            <Download className="w-4 h-4 mr-2" />
            Download HTML
          </Button>
          <Button
            variant="secondary"
            onClick={() => window.open(reportsApi.getDownloadUrl(reportId, 'json'), '_blank')}
          >
            <Download className="w-4 h-4 mr-2" />
            Download JSON
          </Button>
          <Button
            onClick={() => window.open(reportsApi.getViewUrl(reportId), '_blank')}
          >
            <ExternalLink className="w-4 h-4 mr-2" />
            Open in New Tab
          </Button>
        </div>
      </div>

      <div className="bg-dark-800 rounded-xl overflow-hidden border border-dark-900/50">
        <iframe
          src={reportsApi.getViewUrl(reportId)}
          className="w-full h-[calc(100vh-200px)]"
          title="Report"
        />
      </div>
    </div>
  )
}
