/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx}',
    './src/components/**/*.{js,ts,jsx,tsx}',
    './src/app/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        // SENTINEL design tokens
        bg: {
          primary: '#080b14',
          secondary: '#0d1220',
          tertiary: '#131b2d',
          elevated: '#18233a',
        },
        border: {
          default: '#22304a',
          strong: '#33466a',
        },
        text: {
          primary: '#f4f7ff',
          secondary: '#a7b2c9',
          muted: '#71809c',
        },
        accent: {
          cyan: '#57d8ff',
          amber: '#f8c76a',
          green: '#5ee6a8',
          red: '#ff7084',
          purple: '#9e8cff',
        },
        severity: {
          low: '#00ff88',
          medium: '#ffb800',
          high: '#ff8c00',
          critical: '#ff4444',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
};