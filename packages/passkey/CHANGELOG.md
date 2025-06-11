# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-06-11

### Added
- Initial release of @web3authn/passkey
- Framework-agnostic PasskeyManager class for WebAuthn authentication
- React components and hooks for easy integration
- TypeScript support with comprehensive type definitions
- PRF (Pseudorandom Function) support for enhanced security
- Optimistic authentication for fast transaction signing
- **Rust-based WASM worker** for secure cryptographic operations
- **Self-contained build system** with Rust source code included
- **PRF-based key derivation** using HKDF-SHA256
- **AES-GCM encryption** for NEAR private key protection
- Complete test suite with Jest
- Comprehensive documentation and examples

### Features
- **Core API**: PasskeyManager class for registration, login, and transaction signing
- **React API**: PasskeyProvider, usePasskeyContext, and related hooks
- **Components**: PasskeyLogin component with built-in UI
- **Security**: WebAuthn with PRF extension for secure key management
- **WASM Crypto**: Rust-based cryptographic worker with `npm run build:wasm`
- **Storage**: IndexedDB integration for local user data
- **Error Handling**: Custom error classes with detailed messages
- **TypeScript**: Full type safety and IntelliSense support

### Browser Support
**Requires full WebAuthn support with PRF**
- Chrome/Edge: Full support with PRF
- Firefox: WebAuthn with PRF1
- Safari: WebAuthn with PRF (limited to touchID authenticator)