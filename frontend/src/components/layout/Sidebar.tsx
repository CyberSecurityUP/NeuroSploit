import { Link, useLocation } from 'react-router-dom'
import {
  Home,
  Bot,
  BookOpen,
  FileText,
  Settings,
  Activity,
  Shield,
  Zap
} from 'lucide-react'

const navItems = [
  { path: '/', icon: Home, label: 'Dashboard' },
  { path: '/scan/new', icon: Bot, label: 'AI Agent' },
  { path: '/realtime', icon: Zap, label: 'Real-time Task' },
  { path: '/tasks', icon: BookOpen, label: 'Task Library' },
  { path: '/reports', icon: FileText, label: 'Reports' },
  { path: '/settings', icon: Settings, label: 'Settings' },
]

export default function Sidebar() {
  const location = useLocation()

  return (
    <aside className="w-64 bg-dark-800 border-r border-dark-900/50 flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-dark-900/50">
        <Link to="/" className="flex items-center gap-3">
          <div className="w-10 h-10 bg-primary-500 rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">NeuroSploit</h1>
            <p className="text-xs text-dark-400">v3.0 AI Pentest</p>
          </div>
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4">
        <ul className="space-y-2">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path
            const Icon = item.icon
            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                    isActive
                      ? 'bg-primary-500/20 text-primary-500'
                      : 'text-dark-300 hover:bg-dark-900/50 hover:text-white'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span>{item.label}</span>
                </Link>
              </li>
            )
          })}
        </ul>
      </nav>

      {/* Status */}
      <div className="p-4 border-t border-dark-900/50">
        <div className="flex items-center gap-2 text-sm">
          <Activity className="w-4 h-4 text-green-500" />
          <span className="text-dark-400">System Online</span>
        </div>
      </div>
    </aside>
  )
}
