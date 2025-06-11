# Development Setup - Worker Loading

## 🛠️ Current Development Solution

This document explains the **environment-aware worker loading system** implemented for robust development and production deployment.

## Architecture

The `WebAuthnManager` now uses intelligent path resolution that works across different environments:

### Development Mode (localhost)
```javascript
// Automatically detects localhost and uses frontend public directory
workerUrl = new URL('/workers/onetimePasskeySigner.worker.js', window.location.origin);
```

### Production Mode (deployed)
```javascript
// Uses package-relative paths with build detection
if (currentUrl.pathname.includes('/react/src/core/')) {
  // React build: dist/esm/react/src/core/
  workerUrl = new URL('../../../../onetimePasskeySigner.worker.js', currentUrl);
} else {
  // Main build: dist/esm/core/
  workerUrl = new URL('../../onetimePasskeySigner.worker.js', currentUrl);
}
```

## Development Workflow

### 1. Build and Copy Workers
```bash
cd packages/passkey
npm run build:all  # Builds package and automatically copies workers to frontend
```

### 2. Development Server
```bash
cd frontend
npm run dev  # Workers are served from public/workers/
```

### 3. Updating Workers
```bash
cd packages/passkey
npm run copy-assets  # Copy latest workers to frontend
```

## File Structure

```
frontend/
├── public/
│   └── workers/           # 🛠️ Development worker files
│       ├── onetimePasskeySigner.worker.js
│       ├── passkey_crypto_worker.js
│       └── passkey_crypto_worker_bg.wasm
└── src/

packages/passkey/
├── dist/
│   ├── onetimePasskeySigner.worker.js  # 🚀 Production worker
│   ├── passkey_crypto_worker.js
│   └── passkey_crypto_worker_bg.wasm
└── src/
```

## Robustness Features

### 1. Environment Detection
- ✅ **Automatic detection** of development vs production
- ✅ **Hostname-based switching** (`localhost` detection)
- ✅ **Graceful fallbacks** to package paths

### 2. Build-aware Path Resolution
- ✅ **Main build detection** (`dist/esm/core/`)
- ✅ **React build detection** (`dist/esm/react/src/core/`)
- ✅ **Correct relative path calculation** for each build

### 3. Development Convenience
- ✅ **Automated copying** with `npm run build:all`
- ✅ **Manual copying** with `npm run copy-assets`
- ✅ **Hot reloading** support in development

## Production Deployment

### No Changes Required!
The environment-aware system automatically:
- 🚀 Uses package paths in production
- 📦 Works with any bundler (Vite, Webpack, Next.js)
- 🔄 Falls back gracefully if needed

### Deployment Options

1. **Package Distribution**: Workers bundled with package
2. **CDN Distribution**: Workers served from CDN
3. **Public Directory**: Workers in app's public folder

## Testing the Implementation

### Development Console Logs
```
🛠️ Development mode: Using frontend public workers directory
WebAuthnManager: Worker config: {
  isDevelopment: true,
  resolved workerUrl: "https://example.localhost:3000/workers/onetimePasskeySigner.worker.js"
}
```

### Production Console Logs
```
🚀 Production mode: Using package worker paths
WebAuthnManager: Worker config: {
  isDevelopment: false,
  detected location: "main build",
  resolved workerUrl: "https://example.com/assets/onetimePasskeySigner.worker.js"
}
```

## Future Improvements

When proper packaging is implemented:

1. Remove `frontend/public/workers/` directory
2. Remove `copy-assets` script
3. Keep environment-aware code for robustness
4. Update documentation

## Security Considerations

- ✅ **Worker isolation** maintained in all environments
- ✅ **Same-origin policy** enforced
- ✅ **HTTPS requirement** for WebAuthn
- ✅ **Single-use workers** with automatic cleanup

## Troubleshooting

### Worker Loading Fails
1. Check console for environment detection logs
2. Verify worker files exist in expected location
3. Ensure CORS headers allow worker loading
4. Confirm HTTPS in production

### Development Issues
```bash
# Rebuild and copy workers
cd packages/passkey
npm run build:all

# Verify files copied
ls -la ../../frontend/public/workers/
```

### Production Issues
```bash
# Check package build
ls -la dist/

# Verify worker bundle
cat dist/onetimePasskeySigner.worker.js | head -10
```

## Summary

This solution provides:
- 🛠️ **Immediate development workflow** with copied workers
- 🚀 **Production-ready deployment** with package paths
- 🔄 **Robust fallbacks** for all scenarios
- 📦 **Environment awareness** for optimal performance

The code remains clean, maintainable, and ready for future packaging improvements while solving the immediate development needs.