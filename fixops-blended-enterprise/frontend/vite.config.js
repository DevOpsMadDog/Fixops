import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: true,
    allowedHosts: [
      'localhost',
      '127.0.0.1',
      '.emergentagent.com',
      'fixops-devsec.preview.emergentagent.com'
    ],
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
      }
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    minify: 'esbuild',
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          router: ['react-router-dom'],
          ui: ['lucide-react', '@headlessui/react', 'framer-motion'],
          charts: ['recharts'],
          forms: ['react-hook-form'],
          utils: ['axios', '@tanstack/react-query', 'zustand']
        }
      }
    }
  },
  resolve: {
    alias: {
      '@': '/src'
    }
  }
})