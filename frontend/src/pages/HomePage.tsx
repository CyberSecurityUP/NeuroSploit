import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Activity, Shield, AlertTriangle, Plus, ArrowRight } from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { SeverityBadge } from '../components/common/Badge'
import { dashboardApi } from '../services/api'
import { useDashboardStore } from '../store'

export default function HomePage() {
  const { stats, recentScans, recentVulnerabilities, setStats, setRecentScans, setRecentVulnerabilities, setLoading } = useDashboardStore()

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true)
      try {
        const [statsData, recentData] = await Promise.all([
          dashboardApi.getStats(),
          dashboardApi.getRecent(5)
        ])
        setStats(statsData)
        setRecentScans(recentData.recent_scans)
        setRecentVulnerabilities(recentData.recent_vulnerabilities)
      } catch (error) {
        console.error('Failed to fetch dashboard data:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  const statCards = [
    {
      label: 'Total Scans',
      value: stats?.scans.total || 0,
      icon: Activity,
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10',
    },
    {
      label: 'Running Scans',
      value: stats?.scans.running || 0,
      icon: Shield,
      color: 'text-green-400',
      bgColor: 'bg-green-500/10',
    },
    {
      label: 'Vulnerabilities',
      value: stats?.vulnerabilities.total || 0,
      icon: AlertTriangle,
      color: 'text-red-400',
      bgColor: 'bg-red-500/10',
    },
    {
      label: 'Critical Issues',
      value: stats?.vulnerabilities.critical || 0,
      icon: AlertTriangle,
      color: 'text-red-500',
      bgColor: 'bg-red-600/10',
    },
  ]

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Quick Actions */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Welcome to NeuroSploit</h2>
          <p className="text-dark-400 mt-1">AI-Powered Penetration Testing Platform</p>
        </div>
        <Link to="/scan/new">
          <Button size="lg">
            <Plus className="w-5 h-5 mr-2" />
            New Scan
          </Button>
        </Link>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((stat) => (
          <Card key={stat.label} className="hover:border-dark-700 transition-colors">
            <div className="flex items-center gap-4">
              <div className={`p-3 rounded-lg ${stat.bgColor}`}>
                <stat.icon className={`w-6 h-6 ${stat.color}`} />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{stat.value}</p>
                <p className="text-sm text-dark-400">{stat.label}</p>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Severity Distribution */}
      {stats && stats.vulnerabilities.total > 0 && (
        <Card title="Vulnerability Distribution">
          <div className="flex h-8 rounded-lg overflow-hidden">
            {stats.vulnerabilities.critical > 0 && (
              <div
                className="bg-red-500 flex items-center justify-center text-white text-xs font-medium"
                style={{ width: `${(stats.vulnerabilities.critical / stats.vulnerabilities.total) * 100}%` }}
              >
                {stats.vulnerabilities.critical}
              </div>
            )}
            {stats.vulnerabilities.high > 0 && (
              <div
                className="bg-orange-500 flex items-center justify-center text-white text-xs font-medium"
                style={{ width: `${(stats.vulnerabilities.high / stats.vulnerabilities.total) * 100}%` }}
              >
                {stats.vulnerabilities.high}
              </div>
            )}
            {stats.vulnerabilities.medium > 0 && (
              <div
                className="bg-yellow-500 flex items-center justify-center text-white text-xs font-medium"
                style={{ width: `${(stats.vulnerabilities.medium / stats.vulnerabilities.total) * 100}%` }}
              >
                {stats.vulnerabilities.medium}
              </div>
            )}
            {stats.vulnerabilities.low > 0 && (
              <div
                className="bg-blue-500 flex items-center justify-center text-white text-xs font-medium"
                style={{ width: `${(stats.vulnerabilities.low / stats.vulnerabilities.total) * 100}%` }}
              >
                {stats.vulnerabilities.low}
              </div>
            )}
          </div>
          <div className="flex gap-4 mt-3 text-xs">
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-500" /> Critical</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-orange-500" /> High</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-yellow-500" /> Medium</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-blue-500" /> Low</span>
          </div>
        </Card>
      )}

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
          <div className="space-y-3">
            {recentScans.length === 0 ? (
              <p className="text-dark-400 text-center py-4">No scans yet. Start your first scan!</p>
            ) : (
              recentScans.map((scan) => (
                <Link
                  key={scan.id}
                  to={`/scan/${scan.id}`}
                  className="flex items-center justify-between p-3 bg-dark-900/50 rounded-lg hover:bg-dark-900 transition-colors"
                >
                  <div>
                    <p className="font-medium text-white">{scan.name || 'Unnamed Scan'}</p>
                    <p className="text-xs text-dark-400">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={scan.status} />
                    <span className="text-sm text-dark-400">{scan.total_vulnerabilities} vulns</span>
                  </div>
                </Link>
              ))
            )}
          </div>
        </Card>

        {/* Recent Vulnerabilities */}
        <Card
          title="Recent Findings"
          action={
            <Link to="/reports" className="text-sm text-primary-500 hover:text-primary-400 flex items-center gap-1">
              View All <ArrowRight className="w-4 h-4" />
            </Link>
          }
        >
          <div className="space-y-3">
            {recentVulnerabilities.length === 0 ? (
              <p className="text-dark-400 text-center py-4">No vulnerabilities found yet.</p>
            ) : (
              recentVulnerabilities.slice(0, 5).map((vuln) => (
                <div
                  key={vuln.id}
                  className="flex items-center justify-between p-3 bg-dark-900/50 rounded-lg"
                >
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-white truncate">{vuln.title}</p>
                    <p className="text-xs text-dark-400 truncate">{vuln.affected_endpoint}</p>
                  </div>
                  <SeverityBadge severity={vuln.severity} />
                </div>
              ))
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}
