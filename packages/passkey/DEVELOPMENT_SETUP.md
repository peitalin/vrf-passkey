# Development Setup - Worker Loading


## Development Workflow

### 1. Build and Copy Workers
```bash
cd packages/passkey
npm run build:all  # Builds package and automatically copies workers to frontend

sh npm_link.sh # link local @web3authn/passkey folder to node_modules in developing locally
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
