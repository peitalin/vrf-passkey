# @web3authn/passkey

Passkey authentication SDK with onchain WebAuthn.

## Features

- **Passkey Authentication**: Secure login/registration using WebAuthn
- **PRF Support**: Pseudorandom Function for enhanced security
- **Optimistic Auth**: Fast transaction signing
- **️ React Ready**: Drop-in React components and hooks
- **Framework Agnostic**: Core functionality works without React
- **TypeScript**: Full type safety and IntelliSense
- **WASM Powered**: Efficient cryptographic operations

## Installation

```bash
npm install @web3authn/passkey
# or
yarn add @web3authn/passkey
# or
pnpm add @web3authn/passkey
```

## Quick Start

### Framework Agnostic Usage

```typescript
import { PasskeyManager } from '@web3authn/passkey';

// Initialize the SDK
const passkey = new PasskeyManager({
  serverUrl: 'https://your-server.com',
  nearNetwork: 'testnet',
  relayerAccount: 'relayer.testnet'
});

// Register a new user
try {
  const result = await passkey.register('username');
  if (result.success) {
    console.log('Registration successful!', result.nearAccountId);
  }
} catch (error) {
  console.error('Registration failed:', error.message);
}

// Login
try {
  const result = await passkey.login('username');
  if (result.success) {
    console.log('Logged in!', result.loggedInUsername);
  }
} catch (error) {
  console.error('Login failed:', error.message);
}

// Sign transaction
try {
  const result = await passkey.signTransaction({
    receiverId: 'contract.testnet',
    methodName: 'transfer',
    args: { amount: '1000000000000000000000000' } // 1 NEAR
  });

  if (result.success) {
    console.log('Transaction signed!', result.transactionId);
  }
} catch (error) {
  console.error('Transaction failed:', error.message);
}
```

### React Usage

```tsx
import React from 'react';
import {
  PasskeyProvider,
  usePasskeyContext,
  PasskeyLogin
} from '@web3authn/passkey/react';

function App() {
  return (
    <PasskeyProvider config={{
      serverUrl: process.env.REACT_APP_SERVER_URL!,
      nearNetwork: 'testnet',
      relayerAccount: 'relayer.testnet'
    }}>
      <AuthComponent />
    </PasskeyProvider>
  );
}

function AuthComponent() {
  const {
    isLoggedIn,
    currentUser,
    register,
    login,
    logout
  } = usePasskeyContext();

  if (isLoggedIn) {
    return (
      <div>
        <h1>Welcome, {currentUser?.username}!</h1>
        <button onClick={logout}>Logout</button>
      </div>
    );
  }

  return <PasskeyLogin />;
}
```

## API Reference

### Core API

#### `PasskeyManager`

The main class for framework-agnostic usage.

```typescript
class PasskeyManager {
  constructor(config: PasskeyConfig)

  // Authentication
  register(username: string, options?: RegisterOptions): Promise<RegisterResult>
  login(username?: string, options?: LoginOptions): Promise<LoginResult>
  logout(): Promise<void>

  // Transaction Signing
  signTransaction(params: TransactionParams): Promise<SignTransactionResult>

  // State Management
  getCurrentUser(): Promise<UserData | null>
  isLoggedIn(): Promise<boolean>
  hasPasskeyCredential(username: string): Promise<boolean>

  // Configuration
  updateConfig(config: Partial<PasskeyConfig>): void
  getConfig(): PasskeyConfig
}
```

#### Configuration

```typescript
interface PasskeyConfig {
  serverUrl: string              // Your backend server URL
  nearNetwork: 'testnet' | 'mainnet'
  relayerAccount: string         // Account that pays for transactions
  optimisticAuth?: boolean       // Enable fast auth (default: true)
  debugMode?: boolean           // Enable debug logging
}
```

### React API

#### `PasskeyProvider`

Context provider that wraps your app.

```tsx
<PasskeyProvider config={passkeyConfig}>
  {children}
</PasskeyProvider>
```

#### `usePasskeyContext()`

Main hook for accessing passkey functionality.

```typescript
const {
  // State
  isLoggedIn: boolean,
  username: string | null,
  nearAccountId: string | null,
  isProcessing: boolean,

  // Actions
  registerPasskey: (username: string) => Promise<RegistrationResult>,
  loginPasskey: (username?: string) => Promise<LoginResult>,
  logoutPasskey: () => void,

  // Transaction
  executeDirectActionViaWorker: (action, callbacks?) => Promise<void>,

  // Configuration
  optimisticAuth: boolean,
  setOptimisticAuth: (value: boolean) => void
} = usePasskeyContext();
```

#### Components

- `<PasskeyLogin />` - Complete login/registration UI
- `<Toggle />` - Reusable toggle component

### Error Handling

The SDK provides typed error classes:

```typescript
import {
  PasskeyError,
  AuthenticationError,
  RegistrationError,
  TransactionError
} from '@web3authn/passkey';

try {
  await passkey.register('username');
} catch (error) {
  if (error instanceof RegistrationError) {
    console.error('Registration specific error:', error.message);
  } else if (error instanceof PasskeyError) {
    console.error('General passkey error:', error.message);
  }
}
```

## 🛠️ Development

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

## 🔧 Configuration Options

### Optimistic Auth

Enable fast transaction signing without server roundtrips:

```typescript
const passkey = new PasskeyManager({
  // ... other config
  optimisticAuth: true  // Default: true
});

// Or per-operation
await passkey.login('username', { optimisticAuth: false });
```

### Debug Mode

Enable detailed logging for development:

```typescript
const passkey = new PasskeyManager({
  // ... other config
  debugMode: true
});
```

## 🌐 Browser Support

- **Chrome/Edge**: Full support with PRF
- **Firefox**: Basic WebAuthn (PRF support pending)
- **Safari**: Basic WebAuthn (PRF support pending)

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](https://github.com/near/passkey/docs)
- 🐛 [Issue Tracker](https://github.com/near/passkey/issues)
- 💬 [Discord Community](https://discord.gg/near)

## 🏗️ Roadmap

- [ ] MainNet support
- [ ] Additional authenticator support
- [ ] Vue.js bindings
- [ ] Angular bindings
- [ ] Mobile SDK (React Native)
- [ ] Advanced transaction batching

---

Built with ❤️ by the NEAR Protocol team