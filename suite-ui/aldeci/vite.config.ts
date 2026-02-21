import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3001,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        timeout: 120_000,  // 120s — pentest scans can take 30-60s
      },
      '/health': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/evidence': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/graph': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/inputs': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
