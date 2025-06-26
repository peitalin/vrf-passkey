# @web3authn/passkey

> **⚠️ Development Note**: Currently using a temporary solution where worker files are copied to `frontend/public/workers/` for development. The code is environment-aware and will automatically use the correct paths in production. This ensures robust operation across different deployment scenarios.

Web3Authn Passkey SDK for NEAR Protocol integration with React components and TypeScript support.


## Installation

```bash
npm install @web3authn/passkey
# or
yarn add @web3authn/passkey
# or
pnpm add @web3authn/passkey
```


### Building from Source

#### Prerequisites

This SDK includes Rust-based WASM modules. You'll need:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Add WASM target
rustup target add wasm32-unknown-unknown
```

#### Building

```bash
git clone https://github.com/near/passkey.git
cd passkey/packages/passkey
npm install

# Build WASM modules
npm run build:wasm

# Build complete SDK
npm run build
```

#### WASM Development

```bash
# Build WASM in development mode (faster, with debug info)
npm run build:wasm:dev

# Build optimized WASM for production
npm run build:wasm
```

### Testing

```bash
npm test           # Run tests
npm run test:watch # Watch mode
npm run lint       # Lint code
```

### Project Structure

```
src/
├── core/              # Framework-agnostic core
│   ├── PasskeyManager.ts
│   ├── WebAuthnManager.ts
│   ├── types.ts
│   └── utils/
├── react/             # React-specific exports
│   ├── components/
│   ├── hooks/
│   ├── context/
│   └── index.ts
└── index.ts           # Main entry point
```

