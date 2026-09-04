import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig(({ command }) => ({
  // FastAPI serves the production build from the site root.
  base: '/',

  plugins: [react()],

  server: {
    port: 3000,

    proxy: {
      '/analyze': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true
      },

      '/health': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true
      },

      '/metrics': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true
      },

      '/chat': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true
      },

      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true
      },

      '/static': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true
      }
    }
  }
}))

