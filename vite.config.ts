import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import mkcert from 'vite-plugin-mkcert'

// https://vite.dev/config/
export default defineConfig({
  // Enable HTTPS but make it optional to avoid mkcert issues
  server: { 
    https: process.env.USE_HTTPS === 'true' ? true : false
  },
  plugins: [
    react(),
    process.env.USE_HTTPS === 'true' ? mkcert() : null
  ].filter(Boolean),
})