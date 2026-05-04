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
        // Brand v1.0 greens (directive 2026-05-04 §2)
        brand: {
          50: "#ecfdf3",
          100: "#d1fadf",
          200: "#a6f4c5",
          300: "#6ee7b0",
          400: "#56D364",   // sigil-green-soft (hover/active)
          500: "#3FB950",   // sigil-green — primary mark colour, primary CTA
          600: "#238636",   // sigil-green-mid — secondary emphasis
          700: "#196C2E",   // sigil-green-deep — pressed
          800: "#0f4d20",
          900: "#0a3417",
          950: "#04190a",
          deep: "#196C2E",
          mid:  "#238636",
          soft: "#56D364",
        },
        // Brand v1.0 surface scale
        surface: {
          black:    "#0A0A0A",
          surface:  "#161616",
          elevated: "#1C1C1C",
          border:   "#262626",
          muted:    "#404040",
          gray:     "#787878",
          light:    "#A3A3A3",
          offwhite: "#E5E5E5",
          white:    "#FAFAFA",
        },
        // Verdict family — 5-tier (directive §3)
        verdict: {
          clean:    "#22C55E",
          low:      "#EAB308",
          medium:   "#F97316",
          high:     "#EF4444",
          critical: "#DC2626",
        },
        // Legacy `dark` palette — kept so existing `bg-dark-900` etc still resolve.
        // Values now follow the brand surface scale; map index by approximate luminance.
        dark: {
          50:  "#FAFAFA",
          100: "#E5E5E5",
          200: "#A3A3A3",
          300: "#787878",
          400: "#404040",
          500: "#262626",
          600: "#1C1C1C",
          700: "#161616",
          800: "#0F0F0F",
          900: "#0A0A0A",
          950: "#000000",
        },
        // Status colours — aligned with the 5-tier verdict family
        success: {
          400: "#4ade80",
          500: "#22C55E",   // verdict-clean
          600: "#16a34a",
        },
        warning: {
          400: "#facc15",
          500: "#EAB308",   // verdict-low
          600: "#ca8a04",
        },
        danger: {
          400: "#f87171",
          500: "#EF4444",   // verdict-high
          600: "#DC2626",   // verdict-critical
        },
        // Blue removed from the system per directive §2 — neutral grey for legacy `info` refs.
        info: {
          400: "#A3A3A3",
          500: "#787878",
          600: "#404040",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Helvetica",
          "Arial",
          "sans-serif",
          "Apple Color Emoji",
          "Segoe UI Emoji",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
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
