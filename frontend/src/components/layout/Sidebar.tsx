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
  Crosshair,
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
      { path: '/full-ia', icon: Crosshair, label: 'FULL AI TESTING' },
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
      } glass-panel border-r border-cyber-green/10 flex flex-col transition-all duration-300 ease-in-out flex-shrink-0 z-50`}
    >
      {/* Logo */}
      <div className={`border-b border-cyber-green/10 ${sidebarCollapsed ? 'p-3' : 'p-4'}`}>
        <div className="flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 min-w-0 group">
            <div className="w-10 h-10 bg-cyber-green/10 border border-cyber-green/30 rounded-lg flex items-center justify-center flex-shrink-0 group-hover:shadow-neon-green transition-all duration-300">
              <Shield className="w-6 h-6 text-cyber-green animate-pulse-glow" />
            </div>
            {!sidebarCollapsed && (
              <div className="min-w-0">
                <h1 className="text-lg font-bold text-white truncate tracking-tighter uppercase">
                  Neuro<span className="text-cyber-green">Sploit</span>
                </h1>
                <p className="text-[10px] text-cyber-green/50 font-mono tracking-widest uppercase">v3.0 AI PENTEST</p>
              </div>
            )}
          </Link>
          <button
            onClick={toggleSidebar}
            className="text-dark-400 hover:text-cyber-green transition-all p-1 rounded hover:bg-cyber-green/5 flex-shrink-0 border border-transparent hover:border-cyber-green/20"
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
      <nav className="flex-1 p-2 overflow-y-auto overflow-x-hidden space-y-4 pt-4">
        {navGroups.map((group) => (
          <div key={group.label}>
            {!sidebarCollapsed && (
              <p className="px-3 mb-2 text-[10px] font-bold uppercase text-dark-500 tracking-[0.2em] flex items-center gap-2">
                <span className="w-1 h-1 bg-cyber-green/30 rounded-full"></span>
                {group.label}
              </p>
            )}
            {sidebarCollapsed && <div className="border-t border-cyber-green/5 mx-2 mb-2 mt-1" />}
            <ul className="space-y-1">
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
                      } py-2.5 rounded transition-all duration-200 relative group overflow-hidden ${
                        isActive
                          ? 'bg-cyber-green/10 text-cyber-green border-l-2 border-cyber-green shadow-[inset_4px_0_10px_rgba(0,255,102,0.1)]'
                          : 'text-dark-300 hover:bg-cyber-green/5 hover:text-white border-l-2 border-transparent'
                      }`}
                    >
                      <Icon className={`w-5 h-5 flex-shrink-0 transition-transform duration-300 ${isActive ? 'scale-110' : 'group-hover:scale-110 group-hover:text-cyber-green'}`} />
                      {!sidebarCollapsed && (
                        <span className="whitespace-nowrap text-sm font-medium tracking-tight">{item.label}</span>
                      )}
                      
                      {/* Hover effect light */}
                      <div className="absolute inset-0 bg-gradient-to-r from-cyber-green/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
                    </Link>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Status */}
      <div className="p-4 border-t border-cyber-green/10 bg-cyber-green/[0.02]">
        <div className={`flex items-center ${sidebarCollapsed ? 'justify-center' : 'gap-3'} text-[11px] font-mono`}>
          <div className="relative">
            <Activity className="w-4 h-4 text-cyber-green" />
            <div className="absolute inset-0 bg-cyber-green rounded-full blur-[4px] animate-pulse opacity-50"></div>
          </div>
          {!sidebarCollapsed && (
            <div className="flex flex-col">
              <span className="text-white font-bold uppercase tracking-tighter">System Online</span>
              <span className="text-cyber-green/50 text-[9px] uppercase">Node: NS-2026-ALPHA</span>
            </div>
          )}
        </div>
      </div>
    </aside>
  )
}
