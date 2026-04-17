import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';

export default defineConfig({
  base: '/',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/__tests__/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
    testTimeout: 10000,
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks(id) {
          // Core React runtime
          if (id.includes('node_modules/react/') || id.includes('node_modules/react-dom/') || id.includes('node_modules/scheduler/')) {
            return 'vendor-react';
          }
          // Router
          if (id.includes('node_modules/react-router') || id.includes('node_modules/@remix-run/')) {
            return 'vendor-router';
          }
          // Data fetching
          if (id.includes('node_modules/@tanstack/') || id.includes('node_modules/axios/')) {
            return 'vendor-query';
          }
          // Charts — large, deserves its own chunk
          if (id.includes('node_modules/recharts/') || id.includes('node_modules/d3-') || id.includes('node_modules/victory-')) {
            return 'vendor-charts';
          }
          // Animation — large, deserves its own chunk
          if (id.includes('node_modules/framer-motion/')) {
            return 'vendor-motion';
          }
          // Icons — large, deserves its own chunk
          if (id.includes('node_modules/lucide-react/')) {
            return 'vendor-icons';
          }
          // Radix UI primitives
          if (id.includes('node_modules/@radix-ui/')) {
            return 'vendor-radix';
          }
          // Remaining utility libs (clsx, tailwind-merge, class-variance-authority, zustand, sonner, date-fns)
          if (id.includes('node_modules/')) {
            return 'vendor-utils';
          }
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
});
