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
        orbitron: ['Orbitron', 'sans-serif'],
        rajdhani: ['Rajdhani', 'sans-serif'],
        sans: ['Space Grotesk', 'system-ui', 'sans-serif']
      }
    },
  },
  plugins: [],
}
