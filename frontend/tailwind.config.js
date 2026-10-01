/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      colors: {
        cyber: {
          dark: '#030712',
          surface: '#0B132B',
          card: '#111B35',
          border: '#1E293B',
          accent: '#06B6D4',
          glow: '#38BDF8',
          success: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444',
          critical: '#DC2626',
        },
      },
      boxShadow: {
        'cyber-card': '0 4px 20px -2px rgba(0, 0, 0, 0.5), 0 0 1px 1px rgba(255, 255, 255, 0.05)',
        'cyber-glow': '0 0 15px -3px rgba(6, 182, 212, 0.3)',
      },
    },
  },
  plugins: [],
}
