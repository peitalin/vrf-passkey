import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'
import path from 'path';

export default defineConfig({
  server: {
    port: 5173, // The port Caddy is reverse_proxying to
    host: 'localhost', // Ensure Vite is accessible by Caddy on localhost
    open: 'https://example.localhost', // Automatically open this URL in the browser
    fs: {
      // Allow serving files from the linked package directory
      allow: [
        // Default: serve files from project root
        '..',
        // Allow serving from the linked passkey package
        '../packages/passkey/dist'
      ]
    }
  },
  plugins: [
    react(),
    nodePolyfills({
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
      protocolImports: true,
    }),
  ],
  resolve: {
    alias: {
      // The plugin should handle buffer aliasing if needed.
    },
  },
  define: {
    'process.env.NODE_ENV': JSON.stringify('development'), // Hardcode for client bundle
  },
  optimizeDeps: {
  },
})