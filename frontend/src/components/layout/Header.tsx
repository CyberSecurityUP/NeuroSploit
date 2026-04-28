import { useLocation } from 'react-router-dom'

const pageTitles: Record<string, string> = {
  '/': 'Dashboard',
  '/scan/new': 'New Security Scan',
  '/reports': 'Reports',
  '/settings': 'Settings',
  '/full-ia': 'FULL AI TESTING',
}

export default function Header() {
  const location = useLocation()
  const title = pageTitles[location.pathname] || 'NeuroSploit'

  return (
    <header className="h-16 glass-panel border-b border-cyber-green/10 flex items-center justify-between px-8 z-40">
      <div className="flex items-center gap-4">
        <div className="w-1 h-6 bg-cyber-green/50 rounded-full animate-pulse"></div>
        <h1 className="text-xl font-bold text-white tracking-tighter uppercase font-sans">
          {title}
        </h1>
      </div>
      
      <div className="flex items-center gap-6 font-mono text-[11px]">
        <div className="flex items-center gap-2 px-3 py-1 bg-cyber-green/5 border border-cyber-green/20 rounded text-cyber-green">
          <span className="w-1.5 h-1.5 bg-cyber-green rounded-full animate-pulse"></span>
          SCANNER_ACTIVE
        </div>
        
        <span className="text-dark-400 uppercase tracking-widest hidden sm:block">
          {new Date().toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
          })}
          <span className="ml-2 text-cyber-green/30">|</span>
          <span className="ml-2">SEC_LEVEL: ALPHA</span>
        </span>
      </div>
    </header>
  )
}
