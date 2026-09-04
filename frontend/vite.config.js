import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig(({ command }) => ({
  // Use '/Phisihing-Detection/' base only when building for GitHub Pages deployment.
  // During local dev ('serve'), use '/' so assets load correctly on localhost.
  base: command === 'build' ? '/Phisihing-Detection/' : '/',

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

