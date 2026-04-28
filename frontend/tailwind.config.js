/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Space Grotesk', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        cyber: {
          black: '#050505',
          darker: '#0a0a0a',
          dark: '#121212',
          gray: '#1a1a1a',
          green: '#00ff66',
          blue: '#00f0ff',
          purple: '#bd00ff',
          red: '#ff0055',
          yellow: '#f3ff00',
        },
        primary: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#00ff66', // Switching primary to cyber green
          600: '#00e65c',
          700: '#00cc52',
          800: '#00b347',
          900: '#00993d',
        },
        dark: {
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#050505', // True black for main bg
          800: '#0a0a0a', // Darker cards
          900: '#121212', // Subtle borders
          950: '#020202',
        },
      },
      animation: {
        'glitch': 'glitch 1s linear infinite',
        'scanline': 'scanline 8s linear infinite',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'matrix': 'matrix 20s linear infinite',
      },
      keyframes: {
        glitch: {
          '2%, 64%': { transform: 'translate(2px, 0) skew(0deg)' },
          '4%, 60%': { transform: 'translate(-2px, 0) skew(0deg)' },
          '62%': { transform: 'translate(0, 0) skew(5deg)' },
        },
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        'pulse-glow': {
          '0%, 100%': { opacity: '1', filter: 'drop-shadow(0 0 5px #00ff66)' },
          '50%': { opacity: '0.7', filter: 'drop-shadow(0 0 20px #00ff66)' },
        },
      },
      boxShadow: {
        'neon-green': '0 0 5px #00ff66, 0 0 20px rgba(0, 255, 102, 0.2)',
        'neon-blue': '0 0 5px #00f0ff, 0 0 20px rgba(0, 240, 255, 0.2)',
        'neon-purple': '0 0 5px #bd00ff, 0 0 20px rgba(189, 0, 255, 0.2)',
      },
    },
  },
  plugins: [],
}
