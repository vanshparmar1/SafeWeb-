/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          950: '#070a10',
          900: '#0b0f19',
          850: '#0f1422',
          800: '#141c2e',
          700: '#1e293b',
          600: '#334155',
          accent: '#06b6d4',
        },
        safe: {
          light: '#34d399',
          DEFAULT: '#10b981',
          dark: '#059669',
          glow: 'rgba(16, 185, 129, 0.4)',
        },
        suspicious: {
          light: '#fbbf24',
          DEFAULT: '#f59e0b',
          dark: '#d97706',
          glow: 'rgba(245, 158, 11, 0.4)',
        },
        phish: {
          light: '#f87171',
          DEFAULT: '#ef4444',
          dark: '#dc2626',
          glow: 'rgba(239, 68, 68, 0.45)',
        },
        invalid: {
          light: '#94a3b8',
          DEFAULT: '#64748b',
          dark: '#475569',
          glow: 'rgba(100, 116, 139, 0.3)',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
        display: ['"Space Grotesk"', 'Inter', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 12s linear infinite',
      }
    },
  },
  plugins: [],
}

