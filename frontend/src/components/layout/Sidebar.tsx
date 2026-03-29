import { Link, useLocation } from 'react-router-dom'
import {
  Home,
  Bot,
  BookOpen,
  FileText,
  Settings,
  Activity,
  Shield,
  Zap,
  Clock,
  Rocket,
  FlaskConical,
  Terminal,
  Container,
  Brain,
  Cable,
  Plug,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { useUIStore } from '../../store'

const navGroups = [
  {
    label: 'Operations',
    items: [
      { path: '/', icon: Home, label: 'Dashboard' },
      { path: '/auto', icon: Rocket, label: 'Auto Pentest' },
      { path: '/scan/new', icon: Bot, label: 'AI Agent' },
      { path: '/realtime', icon: Zap, label: 'Real-time Task' },
    ],
  },
  {
    label: 'Tools',
    items: [
      { path: '/vuln-lab', icon: FlaskConical, label: 'Vuln Lab' },
      { path: '/terminal', icon: Terminal, label: 'Terminal Agent' },
      { path: '/sandboxes', icon: Container, label: 'Sandboxes' },
      { path: '/tasks', icon: BookOpen, label: 'Task Library' },
      { path: '/knowledge', icon: Brain, label: 'Knowledge' },
      { path: '/mcp', icon: Cable, label: 'MCP Servers' },
      { path: '/providers', icon: Plug, label: 'Providers' },
    ],
  },
  {
    label: 'Configuration',
    items: [
      { path: '/scheduler', icon: Clock, label: 'Scheduler' },
      { path: '/reports', icon: FileText, label: 'Reports' },
      { path: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
]

export default function Sidebar() {
  const location = useLocation()
  const { sidebarCollapsed, toggleSidebar } = useUIStore()

  return (
    <aside
      className={`${
        sidebarCollapsed ? 'w-16' : 'w-64'
      } bg-dark-800 border-r border-dark-900/50 flex flex-col transition-all duration-300 ease-in-out flex-shrink-0`}
    >
      {/* Logo */}
      <div className={`border-b border-dark-900/50 ${sidebarCollapsed ? 'p-3' : 'p-4'}`}>
        <div className="flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 min-w-0">
            <div className="w-10 h-10 bg-primary-500 rounded-lg flex items-center justify-center flex-shrink-0">
              <Shield className="w-6 h-6 text-white" />
            </div>
            {!sidebarCollapsed && (
              <div className="min-w-0">
                <h1 className="text-lg font-bold text-white truncate">NeuroSploit</h1>
                <p className="text-xs text-dark-400">v3.0 AI Pentest</p>
              </div>
            )}
          </Link>
          <button
            onClick={toggleSidebar}
            className="text-dark-400 hover:text-white transition-colors p-1 rounded hover:bg-dark-700 flex-shrink-0"
            title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {sidebarCollapsed ? (
              <ChevronRight className="w-4 h-4" />
            ) : (
              <ChevronLeft className="w-4 h-4" />
            )}
          </button>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-2 overflow-y-auto overflow-x-hidden">
        {navGroups.map((group) => (
          <div key={group.label} className="mb-3">
            {!sidebarCollapsed && (
              <p className="px-3 mb-1 text-[10px] font-semibold uppercase text-dark-500 tracking-wider">
                {group.label}
              </p>
            )}
            {sidebarCollapsed && <div className="border-t border-dark-700/50 mx-2 mb-2 mt-1" />}
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                const isActive = location.pathname === item.path
                const Icon = item.icon
                return (
                  <li key={item.path}>
                    <Link
                      to={item.path}
                      title={sidebarCollapsed ? item.label : undefined}
                      className={`flex items-center ${
                        sidebarCollapsed ? 'justify-center px-2' : 'gap-3 px-3'
                      } py-2.5 rounded-lg transition-colors ${
                        isActive
                          ? 'bg-primary-500/20 text-primary-500'
                          : 'text-dark-300 hover:bg-dark-900/50 hover:text-white'
                      }`}
                    >
                      <Icon className="w-5 h-5 flex-shrink-0" />
                      {!sidebarCollapsed && (
                        <span className="whitespace-nowrap text-sm">{item.label}</span>
                      )}
                    </Link>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Status */}
      <div className="p-3 border-t border-dark-900/50">
        <div className={`flex items-center ${sidebarCollapsed ? 'justify-center' : 'gap-2'} text-sm`}>
          <Activity className="w-4 h-4 text-green-500 flex-shrink-0" />
          {!sidebarCollapsed && <span className="text-dark-400">System Online</span>}
        </div>
      </div>
    </aside>
  )
}
