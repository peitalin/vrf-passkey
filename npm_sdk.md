# NEAR Passkey SDK - NPM Package Development Plan

## 📋 Overview

This document outlines the plan to refactor the existing passkey-based NEAR authentication system into a reusable NPM SDK that other developers can integrate into their applications.

## 🎯 Package Goals

- **Easy Integration**: Drop-in React components and hooks
- **Framework Agnostic**: Core functionality usable without React
- **Type Safe**: Full TypeScript support with comprehensive types
- **Secure**: Built-in security best practices for passkey handling
- **WASM Optimized**: Efficient WebAssembly worker management
- **Developer Friendly**: Great DX with clear documentation and examples

## 🏗️ Package Architecture

### Core Package Structure
```
@near/passkey-sdk/
├── dist/                     # Built outputs
│   ├── esm/                 # ES modules
│   ├── cjs/                 # CommonJS
│   ├── types/               # TypeScript declarations
│   └── wasm/                # WASM worker files
├── src/
│   ├── core/                # Framework-agnostic core
│   │   ├── WebAuthnManager.ts
│   │   ├── PasskeyManager.ts
│   │   ├── types.ts
│   │   └── utils/
│   ├── react/               # React-specific exports
│   │   ├── components/
│   │   ├── hooks/
│   │   ├── context/
│   │   └── index.ts
│   ├── wasm-worker/         # WASM worker source
│   └── index.ts             # Main entry point
├── examples/                # Usage examples
├── docs/                   # Documentation
└── scripts/                # Build scripts
```

## 🔌 Public API Design

### 1. Main Entry Points

#### Core API (Framework Agnostic)
```typescript
// @near/passkey-sdk
export class PasskeyManager {
  constructor(config: PasskeyConfig)

  // Authentication
  register(username: string, options?: RegisterOptions): Promise<RegisterResult>
  login(username?: string, options?: LoginOptions): Promise<LoginResult>
  logout(): Promise<void>

  // Transaction Signing
  signTransaction(transaction: TransactionParams): Promise<SignedTransaction>

  // State Management
  getCurrentUser(): Promise<UserData | null>
  isLoggedIn(): Promise<boolean>

  // Configuration
  updateConfig(config: Partial<PasskeyConfig>): void
}

// Types
export interface PasskeyConfig {
  serverUrl: string
  nearNetwork: 'testnet' | 'mainnet'
  relayerAccount: string
  optimisticAuth?: boolean
  debugMode?: boolean
}
```

#### React API
```typescript
// @near/passkey-sdk/react
export const PasskeyProvider: React.FC<PasskeyProviderProps>
export const usePasskey: () => PasskeyContextType
export const usePasskeyAuth: () => AuthHooks
export const useNearTransaction: () => TransactionHooks

// Components
export const PasskeyLogin: React.FC<PasskeyLoginProps>
export const PasskeyRegister: React.FC<PasskeyRegisterProps>
export const TransactionSigner: React.FC<TransactionSignerProps>
```

### 2. Exposed Components & Hooks

#### High-Level Components (Recommended)
- `<PasskeyProvider>` - Context provider with configuration
- `<PasskeyAuth>` - Complete auth UI (login/register)
- `<PasskeyLogin>` - Login-only component
- `<PasskeyRegister>` - Registration-only component
- `<TransactionSigner>` - Transaction signing interface

#### Hooks for Custom UIs
- `usePasskey()` - Complete passkey functionality
- `usePasskeyAuth()` - Authentication only
- `useNearTransaction()` - Transaction signing
- `usePasskeyState()` - State management
- `useOptimisticAuth()` - Auth mode configuration

#### Low-Level API (Advanced Users)
- `WebAuthnManager` class
- Core utility functions
- Type definitions
- Configuration helpers

## 🛠️ Build Setup & Tooling

### 1. Package Configuration

#### package.json
```json
{
  "name": "@near/passkey-sdk",
  "version": "1.0.0",
  "description": "NEAR Protocol passkey authentication SDK",
  "main": "./dist/cjs/index.js",
  "module": "./dist/esm/index.js",
  "types": "./dist/types/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/esm/index.js",
      "require": "./dist/cjs/index.js",
      "types": "./dist/types/index.d.ts"
    },
    "./react": {
      "import": "./dist/esm/react/index.js",
      "require": "./dist/cjs/react/index.js",
      "types": "./dist/types/react/index.d.ts"
    },
    "./wasm-worker": "./dist/wasm/passkey-worker.js"
  },
  "files": [
    "dist/",
    "README.md",
    "CHANGELOG.md"
  ],
  "scripts": {
    "build": "npm run build:wasm && npm run build:ts && npm run build:bundle",
    "build:wasm": "wasm-pack build --target web --out-dir dist/wasm",
    "build:ts": "tsc -p tsconfig.build.json",
    "build:bundle": "rollup -c rollup.config.js",
    "dev": "rollup -c rollup.config.js -w",
    "test": "jest",
    "lint": "eslint src/**/*.ts",
    "prepublishOnly": "npm run build && npm test"
  },
  "peerDependencies": {
    "react": ">=16.8.0",
    "react-dom": ">=16.8.0"
  },
  "peerDependenciesMeta": {
    "react": {
      "optional": true
    },
    "react-dom": {
      "optional": true
    }
  },
  "dependencies": {
    "@near-js/client": "^0.0.5",
    "@near-js/crypto": "^1.2.3",
    "@near-js/transactions": "^1.2.3",
    "@near-js/providers": "^0.2.3",
    "borsh": "^0.7.0",
    "bs58": "^5.0.0",
    "js-sha256": "^0.9.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0",
    "rollup": "^3.0.0",
    "@rollup/plugin-typescript": "^11.0.0",
    "@rollup/plugin-node-resolve": "^15.0.0",
    "@rollup/plugin-commonjs": "^24.0.0",
    "wasm-pack": "^0.12.0"
  }
}
```

### 2. Build Tools Configuration

#### TypeScript (tsconfig.build.json)
```json
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "outDir": "./dist/types",
    "declaration": true,
    "declarationMap": true,
    "emitDeclarationOnly": true,
    "declarationDir": "./dist/types"
  },
  "include": ["src/**/*"],
  "exclude": ["src/**/*.test.ts", "examples/", "docs/"]
}
```

#### Rollup (rollup.config.js)
```javascript
import typescript from '@rollup/plugin-typescript';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

const external = ['react', 'react-dom', '@near-js/client', '@near-js/crypto'];

export default [
  // ESM build
  {
    input: 'src/index.ts',
    output: {
      dir: 'dist/esm',
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: 'src'
    },
    external,
    plugins: [resolve(), commonjs(), typescript()]
  },
  // CJS build
  {
    input: 'src/index.ts',
    output: {
      dir: 'dist/cjs',
      format: 'cjs',
      preserveModules: true,
      preserveModulesRoot: 'src'
    },
    external,
    plugins: [resolve(), commonjs(), typescript()]
  }
];
```

## 🦀 WASM Worker Strategy

### 1. Build Process
```bash
# Build WASM module
wasm-pack build --target web --out-dir dist/wasm

# Custom post-build script to:
# - Rename files for consistent naming
# - Generate worker wrapper
# - Create URL exports for dynamic imports
```

### 2. Worker Packaging
- **Pre-built WASM**: Ship compiled WASM files with the package
- **Worker Wrapper**: Create a JS wrapper that handles WASM loading
- **URL Export**: Provide importable URLs for different bundlers
- **CDN Support**: Support loading from CDN for non-bundled environments

#### Example Worker Export
```typescript
// src/wasm-worker/index.ts
export const PASSKEY_WORKER_URL = new URL('./passkey-worker.js', import.meta.url);

// For bundlers that don't support import.meta.url
export function getWorkerURL(): string {
  return '/node_modules/@near/passkey-sdk/dist/wasm/passkey-worker.js';
}
```

### 3. Runtime WASM Loading
```typescript
// Dynamic WASM loading with fallbacks
export class WasmLoader {
  private static instance: WasmLoader;

  async loadWasm(): Promise<WebAssembly.Module> {
    // Try different loading strategies:
    // 1. Import from package
    // 2. Fetch from CDN
    // 3. Inline base64 fallback
  }
}
```

## 🚀 CI/CD Pipeline

### 1. GitHub Actions Workflow

#### .github/workflows/publish.yml
```yaml
name: Publish NPM Package

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm test

      - name: Run linting
        run: npm run lint

      - name: Type check
        run: npm run type-check

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          target: wasm32-unknown-unknown

      - name: Install wasm-pack
        run: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

      - name: Install dependencies
        run: npm ci

      - name: Build package
        run: npm run build

      - name: Upload build artifacts
        uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  publish:
    needs: build
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/')
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
          registry-url: 'https://registry.npmjs.org'

      - name: Download build artifacts
        uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/

      - name: Publish to NPM
        run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

      - name: Create GitHub Release
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tag_name: ${{ github.ref }}
          release_name: Release ${{ github.ref }}
          draft: false
          prerelease: false
```

#### .github/workflows/test.yml
```yaml
name: Test

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [16, 18, 20]

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'

      - run: npm ci
      - run: npm test
      - run: npm run build
```

### 2. Automated Release Process

#### .github/workflows/release.yml
```yaml
name: Release

on:
  push:
    branches: [main]

jobs:
  release:
    runs-on: ubuntu-latest
    if: "!contains(github.event.head_commit.message, 'skip ci')"

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}

      - uses: actions/setup-node@v4
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Release
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: npx semantic-release
```

## 📦 Refactoring Steps

### Phase 1: Core Extraction (Week 1)
1. **Create new package structure**
   ```bash
   mkdir packages/passkey-sdk
   cd packages/passkey-sdk
   npm init -y
   ```

2. **Extract core functionality**
   - Move `WebAuthnManager` to `src/core/`
   - Extract types to `src/core/types.ts`
   - Create framework-agnostic `PasskeyManager` class
   - Move utilities to `src/core/utils/`

3. **Setup basic build pipeline**
   - Configure TypeScript
   - Setup Rollup for dual builds (ESM/CJS)
   - Add basic test structure

### Phase 2: React Layer (Week 2)
1. **Create React wrapper**
   - Move React hooks to `src/react/hooks/`
   - Refactor context to use core `PasskeyManager`
   - Create high-level React components
   - Setup React-specific exports

2. **Handle peer dependencies**
   - Make React optional
   - Add proper peer dependency configuration
   - Test without React environment

### Phase 3: WASM Integration (Week 2-3)
1. **WASM build pipeline**
   - Setup wasm-pack integration
   - Create worker wrapper scripts
   - Handle different bundler environments
   - Add CDN support for WASM files

2. **Worker management**
   - Abstract worker creation
   - Handle dynamic imports
   - Provide fallback strategies

### Phase 4: Testing & Documentation (Week 3-4)
1. **Comprehensive testing**
   - Unit tests for core functionality
   - Integration tests for React components
   - Browser testing with different bundlers
   - WASM loading tests

2. **Documentation & Examples**
   - API documentation
   - Integration guides
   - Example applications
   - Migration guide from current implementation

### Phase 5: CI/CD & Publishing (Week 4)
1. **GitHub Actions setup**
   - Automated testing
   - Build verification
   - Automated publishing
   - Release management

2. **NPM package optimization**
   - Tree-shaking verification
   - Bundle size analysis
   - Performance testing
   - Security audit

## 📚 Usage Examples

### Basic Integration
```typescript
import { PasskeyManager } from '@near/passkey-sdk';

const passkey = new PasskeyManager({
  serverUrl: 'https://your-server.com',
  nearNetwork: 'testnet',
  relayerAccount: 'relayer.testnet'
});

// Register user
const result = await passkey.register('username');
if (result.success) {
  console.log('Registered successfully!');
}
```

### React Integration
```tsx
import { PasskeyProvider, usePasskey } from '@near/passkey-sdk/react';

function App() {
  return (
    <PasskeyProvider config={{
      serverUrl: process.env.REACT_APP_SERVER_URL,
      nearNetwork: 'testnet',
      relayerAccount: 'relayer.testnet'
    }}>
      <AuthComponent />
    </PasskeyProvider>
  );
}

function AuthComponent() {
  const { login, register, user, isLoggedIn } = usePasskey();

  // Your auth UI here
}
```

## 🔒 Security Considerations

1. **WASM Integrity**: Verify WASM file integrity
2. **Worker Isolation**: Ensure workers are properly sandboxed
3. **API Keys**: Never expose sensitive configuration
4. **CSP Compatibility**: Support Content Security Policy
5. **Audit Trail**: Provide security event logging

## 📈 Success Metrics

- **Adoption**: Download statistics and GitHub stars
- **Developer Experience**: Issue resolution time and documentation quality
- **Performance**: Bundle size and load time benchmarks
- **Reliability**: Error rates and uptime statistics
- **Security**: Security audit results and vulnerability reports

## 🗓️ Timeline Summary

- **Week 1**: Core extraction and basic build
- **Week 2**: React layer and WASM integration
- **Week 3**: WASM optimization and testing
- **Week 4**: CI/CD, documentation, and initial release
- **Ongoing**: Community support and feature development

This plan provides a comprehensive approach to creating a production-ready NPM SDK that maintains security while providing excellent developer experience.