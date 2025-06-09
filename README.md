# NEAR Passkey Authentication System

A comprehensive WebAuthn passkey authentication system built for NEAR blockchain, featuring dual-mode authentication, client-side user management, and decentralized identity.

## 🚀 Key Features

### 🔐 **Dual-Mode Authentication**
- **FastAuth (Optimistic)**: Instant response with background blockchain updates
- **SecureAuth (Contract Sync)**: Full on-chain verification before response
- **User-configurable**: Toggle between modes based on preference

### 👤 **Decentralized User Management**
- **Client-side state**: No server dependency for user data
- **On-chain registry**: Decentralized user existence tracking
- **Multi-user support**: Multiple NEAR accounts per device
- **Privacy-focused**: Personal data stays local

### 🔑 **Advanced Passkey Features**
- **PRF (Pseudo-Random Function)**: Secure key derivation from biometrics
- **WASM crypto worker**: Isolated key management and transaction signing
- **Cross-device sync**: Passkey backup and recovery support
- **Resident keys**: No username required for login

## 📱 User Experience Flows

### 🔐 **Registration Flow**

```mermaid
graph TD
    A[User enters username] --> B{Select auth mode}
    B -->|FastAuth| C[SimpleWebAuthn registration]
    B -->|SecureAuth| D[Contract registration with commitment]
    C --> E[Store authenticator locally]
    D --> F[Store authenticator on-chain]
    E --> G[Background user registry update]
    F --> H[Immediate user registry update]
    G --> I[Registration complete]
    H --> I
```

**FastAuth Registration:**
1. User enters username and selects "Fast Auth (Optimistic)"
2. WebAuthn credential creation with PRF extension
3. SimpleWebAuthn verification (instant)
4. Store authenticator in local database
5. Background contract update (fire-and-forget)
6. Immediate success response

**SecureAuth Registration:**
1. User enters username and selects "Secure Auth (Contract Sync)"
2. Contract generates on-chain commitment
3. WebAuthn credential creation
4. Full contract verification with commitment validation
5. Store authenticator on-chain
6. User registry automatically updated
7. Success response after contract confirmation

### 🔓 **Authentication Flow**

```mermaid
graph TD
    A[User initiates login] --> B{Auth mode setting}
    B -->|FastAuth| C[SimpleWebAuthn challenge]
    B -->|SecureAuth| D[Contract challenge with commitment]
    C --> E[WebAuthn assertion]
    D --> F[WebAuthn assertion]
    E --> G[SimpleWebAuthn verification]
    F --> H[Contract verification]
    G --> I[Background counter update]
    H --> J[On-chain counter update]
    I --> K[Login success]
    J --> K
```

**FastAuth Authentication:**
- Instant challenge generation
- Local credential verification
- Background authenticator counter update
- Immediate login success

**SecureAuth Authentication:**
- On-chain commitment creation
- Contract-based challenge verification
- Synchronous authenticator updates
- Login success after blockchain confirmation

### 💳 **Transaction Signing Flow**

```mermaid
graph TD
    A[User initiates transaction] --> B[PRF authentication]
    B --> C[Derive signing key from biometrics]
    C --> D[WASM worker signs transaction]
    D --> E[Broadcast to NEAR network]
    E --> F[Transaction confirmation]
```

1. User requests transaction (e.g., "Set Greeting")
2. PRF-enabled passkey authentication
3. Secure key derivation in WASM worker
4. Transaction signing with derived key
5. Direct broadcast to NEAR RPC
6. Success confirmation

## 🏗️ Architecture Overview

### **Client-Side Components**
- **ClientUserManager**: Local user data and preferences
- **WebAuthnChallengeManager**: Challenge lifecycle management
- **PasskeyContext**: React state management
- **SettingsContext**: User preferences and mode selection

### **Server Components**
- **Dual-mode routes**: Registration and authentication endpoints
- **Background workers**: Optimistic contract updates
- **Challenge store**: Temporary challenge management
- **Authenticator service**: Credential management

### **Smart Contract**
- **User registry**: On-chain user existence tracking
- **Authenticator storage**: WebAuthn credential management
- **Activity tracking**: Usage analytics and timestamps
- **Security validation**: Commitment-based verification

## ⚙️ Configuration Options

### **Authentication Modes**

| Mode | Speed | Security | Use Case |
|------|-------|----------|----------|
| **FastAuth** | ⚡ Instant | 🔒 High | Daily interactions, UX-focused |
| **SecureAuth** | 🐢 Slower | 🔒🔒 Maximum | High-value transactions, security-critical |

### **User Settings**
- **Mode preference**: Persisted per user
- **Multi-user support**: Switch between NEAR accounts
- **Challenge timeout**: Configurable expiration
- **Background sync**: Optional contract updates

## 🔧 Technical Benefits

### **Performance**
- **Sub-second authentication** with FastAuth mode
- **Parallel processing** of WebAuthn and blockchain operations
- **Optimistic updates** for immediate user feedback
- **Background synchronization** maintains consistency

### **Security**
- **Biometric key derivation** via PRF extension
- **Hardware security module** protection
- **On-chain commitment validation** for critical operations
- **Client-side encryption** with WASM isolation

### **Scalability**
- **Reduced server load** with client-side user management
- **Efficient blockchain usage** with batched updates
- **Local-first architecture** with optional sync
- **Multi-device support** through passkey standards

### **User Experience**
- **No passwords** required anywhere
- **Cross-device roaming** with passkey sync
- **Offline capability** for local operations
- **Progressive enhancement** from fast to secure modes

## 🚦 Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18.x or later recommended)
- [pnpm](https://pnpm.io/) (v8.x or later recommended)
- [Caddy](https://caddyserver.com/docs/install) (for HTTPS development)
- [Rust](https://www.rust-lang.org/tools/install) (for WASM module)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) (for WASM building)

### Installation

```bash
# Install all dependencies
pnpm install-all

# Build WASM crypto worker
pnpm build-wasm
```

### Development

```bash
# Start frontend (https://example.localhost)
pnpm dev

# Start backend (http://localhost:3001)
pnpm server
```

### Testing

```bash
# Test smart contract
cd webauthn-contract && cargo test

# Test user registry
cargo test test_user_registry

# Test authentication flows
cargo test test_authentication
```

## 🎯 Usage Examples

### **Register a New User**
1. Visit `https://example.localhost`
2. Enter username
3. Select authentication mode (Fast/Secure)
4. Complete WebAuthn ceremony
5. Success! User registered with NEAR account

### **Authenticate Existing User**
1. Click "Login with Passkey"
2. WebAuthn authentication (biometric/PIN)
3. Instant login (FastAuth) or wait for contract (SecureAuth)
4. Access authenticated features

### **Execute Blockchain Transaction**
1. Login with passkey
2. Click "Set Greeting" or other action
3. Biometric authentication for signing
4. Transaction broadcast and confirmation
5. Updated state reflected in UI

## 🔄 Migration & Deployment

### **User Migration Strategy**
- **No migration needed**: All users re-register with new system
- **Fresh start**: Clean implementation without legacy constraints
- **Backward compatibility**: Old users can re-register seamlessly

### **Deployment Steps**
1. Deploy updated smart contract
2. Update backend server configuration
3. Deploy frontend with new features
4. Users re-register to access new capabilities

## 🛣️ Roadmap

### **Phase 1 ✅ Complete**
- Client-side user management
- Local storage architecture
- Challenge management system

### **Phase 2 ✅ Complete**
- On-chain user registry
- Dual-mode authentication
- Background sync capabilities

### **Phase 3 🔄 Next**
- Enhanced challenge management
- Advanced security features
- Performance optimizations

### **Future Enhancements**
- Multi-signature support
- Advanced analytics
- Enterprise features
- Mobile app integration

---

**🔐 Built with security, performance, and user experience in mind.**
