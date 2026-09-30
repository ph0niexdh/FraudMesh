/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: { 950: "#060a0e", 900: "#0a1016", 850: "#0d141b", 800: "#111a22", 700: "#1b2733", 600: "#263545" },
        fg: { DEFAULT: "#d8e3ea", muted: "#8a9bab", dim: "#5d6f80" },
        accent: { DEFAULT: "#2dd4bf", strong: "#14b8a6", soft: "#0f3b37" },
        sev: { low: "#10b981", medium: "#eab308", high: "#f97316", critical: "#e11d48" },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
      keyframes: {
        flash: { "0%": { backgroundColor: "rgba(45,212,191,0.25)" }, "100%": { backgroundColor: "transparent" } },
        pulseRing: { "0%": { boxShadow: "0 0 0 0 rgba(225,29,72,0.6)" }, "100%": { boxShadow: "0 0 0 10px rgba(225,29,72,0)" } },
      },
      animation: { flash: "flash 1.6s ease-out", pulseRing: "pulseRing 1.4s ease-out infinite" },
    },
  },
  plugins: [],
};
