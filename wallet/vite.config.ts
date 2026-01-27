import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      include: ['buffer', 'process'],
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
    }),
  ],
  base: '/',
  build: {
    outDir: '../static',
    emptyOutDir: true,
    // Increase chunk size warning limit for large ZK proving keys
    chunkSizeWarningLimit: 5000,
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
