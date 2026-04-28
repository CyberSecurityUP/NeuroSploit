import { ReactNode } from 'react'
import { clsx } from 'clsx'

interface CardProps {
  children: ReactNode
  className?: string
  title?: ReactNode
  subtitle?: string
  action?: ReactNode
}

export default function Card({ children, className, title, subtitle, action }: CardProps) {
  return (
    <div className={clsx('cyber-card group', className)}>
      {(title || action) && (
        <div className="flex items-center justify-between p-5 border-b border-cyber-green/10 relative overflow-hidden">
          {/* Subtle header pulse glow */}
          <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyber-green/20 to-transparent"></div>
          
          <div className="z-10">
            {title && (
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span className="w-1.5 h-1.5 bg-cyber-green rounded-full shadow-neon-green"></span>
                {title}
              </h3>
            )}
            {subtitle && <p className="text-[10px] text-dark-400 mt-1 uppercase tracking-widest font-mono">{subtitle}</p>}
          </div>
          <div className="z-10">{action}</div>
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  )
}
