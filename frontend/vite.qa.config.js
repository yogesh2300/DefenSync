import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

/** Isolated QA frontend — proxies to the QA backend on :8001 so :8000/:5173 stay untouched. */
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5174,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:8001',
      '/health': 'http://127.0.0.1:8001',
    },
  },
})
