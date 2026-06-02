/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        border: 'hsl(220 20% 22%)',
        background: '#151c2b',
        foreground: '#e8edf5',
        card: { DEFAULT: '#1c2532', foreground: '#e8edf5' },
        primary: { DEFAULT: '#9fef00', foreground: '#151c2b' },
        accent: { DEFAULT: '#7c5cff', foreground: '#ffffff' },
        muted: { DEFAULT: '#243044', foreground: '#9aa5b8' },
        destructive: '#ff6b6b',
        warning: '#ffb347',
        thm: {
          green: '#9fef00',
          dark: '#151c2b',
          panel: '#1c2532',
          border: '#2d3a4f',
        },
      },
      fontFamily: {
        sans: ['"DM Sans"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      borderRadius: {
        thm: '12px',
      },
      boxShadow: {
        thm: '0 4px 24px rgba(0,0,0,0.35)',
        'thm-glow': '0 0 20px rgba(159, 239, 0, 0.25)',
      },
    },
  },
  plugins: [],
}
