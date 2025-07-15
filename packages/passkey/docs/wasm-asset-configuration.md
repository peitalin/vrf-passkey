# WASM Asset Configuration Guide

## Overview

The PasskeyManager SDK uses Web Workers with WASM binaries for cryptographic operations. This guide explains how to configure WASM asset paths for different deployment scenarios.

## Default Behavior

By default, the SDK uses relative paths that work for most scenarios:

```
node_modules/@web3authn/passkey/dist/workers/
├── web3authn-signer.worker.js
├── wasm_signer_worker_bg.wasm
├── web3authn-vrf.worker.js
└── wasm_vrf_worker_bg.wasm
```

The workers expect WASM files in the same directory using relative paths like `./wasm_signer_worker_bg.wasm`.

## When Configuration is Needed

You may need to configure WASM asset paths if:

- ✅ **Works by default**: Standard React/Vue/Angular apps with Webpack/Vite
- ✅ **Works by default**: Next.js apps with default configuration
- ❌ **Needs configuration**: CDN hosting with custom paths
- ❌ **Needs configuration**: Monorepo builds with complex asset routing
- ❌ **Needs configuration**: Bundlers that separate workers from assets

## Configuration Methods

### Method 1: Environment Variables (Build-time)

Set environment variables in your build process:

```bash
# For Signer Worker
SIGNER_WASM_BASE_URL=https://cdn.example.com/wasm/

# For VRF Worker
VRF_WASM_BASE_URL=https://cdn.example.com/wasm/
```

### Method 2: Worker Global Configuration (Runtime)

Set global variables before loading the SDK:

```javascript
// Set global WASM base URL for all workers
self.WASM_BASE_URL = 'https://cdn.example.com/wasm/';

// Or import and use the SDK normally
import { PasskeyManager } from '@web3authn/passkey';
```

