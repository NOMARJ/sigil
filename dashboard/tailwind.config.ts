import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  safelist: [
    // Dynamic accent colors used in StatsCard
    { pattern: /bg-(red|green|orange|blue|brand|success|warning|danger|info)-(400|500|600)\/(10|20|30)/ },
    { pattern: /text-(red|green|orange|blue|brand|success|warning|danger|info)-(400|500|600)/ },
    { pattern: /border-(red|green|orange|blue|brand|success|warning|danger|info)-(400|500|600)\/(20|30|40)/ },
    // Dark theme utilities
    { pattern: /bg-dark-(50|100|200|300|400|500|600|700|800|900|950)/ },
    { pattern: /border-dark-(50|100|200|300|400|500|600|700|800|900|950)/ },
    { pattern: /text-dark-(50|100|200|300|400|500|600|700|800|900|950)/ },
  ],
  theme: {
    extend: {
      colors: {
        // Professional security green brand colors (replacing purple AI look)
        brand: {
          50: "#ecfdf5",
          100: "#d1fae5",
          200: "#a7f3d0",
          300: "#6ee7b7",
          400: "#34d399",
          500: "#10b981",  // Primary brand green
          600: "#059669",
          700: "#047857",
          800: "#065f46",
          900: "#064e3b",
          950: "#022c22",
        },
        // Custom dark theme colors
        dark: {
          50: "#e8ebf0",
          100: "#d1d8e3",
          200: "#a3b1c7",
          300: "#7589ab",
          400: "#47628f",
          500: "#2a3551",
          600: "#1f2842",
          700: "#1a2236",
          800: "#141b2d",
          900: "#0a0f1b",
          950: "#050812",
        },
        // Improved status colors
        success: {
          400: "#4ade80",
          500: "#22c55e",
          600: "#16a34a",
        },
        warning: {
          400: "#fbbf24",
          500: "#f59e0b",
          600: "#d97706",
        },
        danger: {
          400: "#f87171",
          500: "#ef4444",
          600: "#dc2626",
        },
        info: {
          400: "#60a5fa",
          500: "#3b82f6",
          600: "#2563eb",
        },
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Helvetica",
          "Arial",
          "sans-serif",
          "Apple Color Emoji",
          "Segoe UI Emoji"
        ],
        mono: ["SF Mono", "Monaco", "Inconsolata", "Fira Code", "monospace"],
      },
      fontSize: {
        'xs': ['0.75rem', { lineHeight: '1.5' }],
        'sm': ['0.875rem', { lineHeight: '1.5' }],
        'base': ['1rem', { lineHeight: '1.5' }],
        'lg': ['1.125rem', { lineHeight: '1.5' }],
        'xl': ['1.25rem', { lineHeight: '1.4' }],
        '2xl': ['1.5rem', { lineHeight: '1.3' }],
        '3xl': ['1.875rem', { lineHeight: '1.3' }],
      },
    },
  },
  plugins: [],
};

export default config;
