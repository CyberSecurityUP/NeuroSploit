import { ReactNode } from 'react'
import Sidebar from './Sidebar'
import Header from './Header'

interface LayoutProps {
  children: ReactNode
}

export default function Layout({ children }: LayoutProps) {
  return (
    <div className="flex min-h-screen bg-cyber-black overflow-hidden selection:bg-cyber-green selection:text-black">
      {/* Dynamic scanning line */}
      <div className="fixed top-0 left-0 w-full h-1 bg-cyber-green/20 blur-[2px] z-[9999] animate-scanline pointer-events-none"></div>
      
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 relative">
        <Header />
        <main className="flex-1 p-6 overflow-auto scrollbar-thin scrollbar-thumb-cyber-green/20">
          <div className="max-w-[1600px] mx-auto animate-fadeIn">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}
