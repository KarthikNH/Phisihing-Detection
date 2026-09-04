/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#050508",
          card: "rgba(12, 16, 24, 0.85)",
          cyan: "#00f0ff",
          red: "#ff2a5f",
          orange: "#ff7700",
          yellow: "#ffcc00",
          green: "#00ff88",
          muted: "#8492a6"
        }
      },
      fontFamily: {
        syne: ['Syne', 'sans-serif'],
        orbitron: ['Orbitron', 'sans-serif'],
        rajdhani: ['Rajdhani', 'sans-serif'],
        jakarta: ['Plus Jakarta Sans', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
        sans: ['Space Grotesk', 'Plus Jakarta Sans', 'system-ui', 'sans-serif']
      }
    },
  },
  plugins: [],
}
