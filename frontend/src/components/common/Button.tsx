import { ButtonHTMLAttributes, ReactNode } from 'react'
import { clsx } from 'clsx'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
  isLoading?: boolean
  children: ReactNode
}

export default function Button({
  variant = 'primary',
  size = 'md',
  isLoading = false,
  children,
  className,
  disabled,
  ...props
}: ButtonProps) {
  const baseStyles = 'inline-flex items-center justify-center font-bold uppercase tracking-widest rounded-none transition-all duration-300 focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed border'

  const variants = {
    primary: 'bg-cyber-green/10 text-cyber-green border-cyber-green/50 hover:bg-cyber-green hover:text-black hover:shadow-neon-green',
    secondary: 'bg-cyber-blue/10 text-cyber-blue border-cyber-blue/50 hover:bg-cyber-blue hover:text-black hover:shadow-neon-blue',
    danger: 'bg-cyber-red/10 text-cyber-red border-cyber-red/50 hover:bg-cyber-red hover:text-black hover:shadow-[0_0_20px_rgba(255,0,85,0.4)]',
    ghost: 'bg-transparent text-dark-400 border-transparent hover:text-white hover:bg-white/5',
  }

  const sizes = {
    sm: 'px-4 py-1.5 text-[10px] font-mono',
    md: 'px-6 py-2.5 text-xs font-mono',
    lg: 'px-8 py-3.5 text-sm font-mono',
  }

  return (
    <button
      className={clsx(baseStyles, variants[variant], sizes[size], className)}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <>
          <svg
            className="animate-spin -ml-1 mr-2 h-4 w-4"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
            />
          </svg>
          Loading...
        </>
      ) : (
        children
      )}
    </button>
  )
}
