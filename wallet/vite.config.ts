import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: '../static',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/account': 'http://localhost:8080',
      '/accounts': 'http://localhost:8080',
      '/transactions': 'http://localhost:8080',
      '/tx': 'http://localhost:8080',
      '/chain': 'http://localhost:8080',
      '/block': 'http://localhost:8080',
      '/mempool': 'http://localhost:8080',
    },
  },
})
