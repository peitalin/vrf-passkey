import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

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
      // If issues persist, we can re-add: buffer: 'buffer'
    },
  },
  define: {
    // Let nodePolyfills handle global, process, and Buffer definitions.
    // Keep environment-specific variables if needed.
    'process.env.NODE_ENV': JSON.stringify('development'), // Hardcode for client bundle
    // 'process.env': JSON.stringify({}), // Likely handled by plugin
    // 'process': JSON.stringify({ env: {} }), // Likely handled by plugin
    // 'global.Buffer': 'Buffer', // Handled by plugin
    // 'globalThis.Buffer': 'Buffer', // Handled by plugin
  },
  optimizeDeps: {
    // The plugin might also influence what needs to be optimized.
    // If 'buffer' is correctly polyfilled and resolved by the plugin,
    // explicitly including it here might not be necessary.
    // include: ['buffer'],
  },
})