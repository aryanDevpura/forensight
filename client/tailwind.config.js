/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // ForenSight investigation console palette
        obsidian: {
          dark: '#0f1c13',
          DEFAULT: '#132318',
          light: '#1a3122',
          border: '#1f3b2a',
          hover: '#183020',
          active: '#1e3d29',
        },
        cream: {
          50: '#fdfdfb',
          100: '#faf8f3',
          DEFAULT: '#f4f1ea',
          dark: '#eae5dc',
          border: '#d7d2c5',
        },
        olive: {
          50: '#f6f7f5',
          100: '#eaede8',
          200: '#d7ded4',
          300: '#bdc7ba',
          400: '#94a190',
          500: '#6c7a68',
          600: '#536050',
          700: '#3e483c',
          800: '#2b332a',
          900: '#1b201a',
        },
        forest: {
          50: '#f0f9f3',
          100: '#daf1e2',
          500: '#227244',
          600: '#1a5935',
          700: '#144629',
          800: '#0e331e',
        },
        amberstatus: {
          bg: '#fef3c7',
          border: '#f59e0b',
          text: '#92400e',
        },
        criticalred: {
          bg: '#fee2e2',
          border: '#ef4444',
          text: '#991b1b',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Consolas', 'Courier New', 'monospace'],
      },
      borderRadius: {
        none: '0px',
        sm: '2px',
        DEFAULT: '3px',
        md: '4px',
        lg: '6px',
      },
    },
  },
  plugins: [],
};
