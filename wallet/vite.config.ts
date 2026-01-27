import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/',
  // Polyfill Buffer for browser
  define: {
    'global': 'globalThis',
  },
  build: {
    outDir: '../static',
    emptyOutDir: true,
    // Increase chunk size warning limit for large ZK proving keys
    chunkSizeWarningLimit: 5000,
  },
  // Optimize dependencies for snarkjs
  optimizeDeps: {
    esbuildOptions: {
      define: {
        global: 'globalThis',
      },
    },
  },
  server: {
    proxy: {
      '/account': 'http://localhost:8333',
      '/accounts': 'http://localhost:8333',
      '/transactions': 'http://localhost:8333',
      '/tx': 'http://localhost:8333',
      '/chain': 'http://localhost:8333',
      '/block': 'http://localhost:8333',
      '/mempool': 'http://localhost:8333',
      // Shielded wallet API endpoints
      '/outputs': 'http://localhost:8333',
      '/witness': 'http://localhost:8333',
      '/nullifiers': 'http://localhost:8333',
    },
    // Allow serving circuit files from public directory
    fs: {
      allow: ['..'],
    },
  },
  // Configure WASM handling
  assetsInclude: ['**/*.wasm', '**/*.zkey'],
})
