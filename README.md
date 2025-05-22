# Porto Passkey Login Example with React & Vite

This project demonstrates how to implement passkey-based login for Ethereum accounts in a React application using [Porto](https://porto.sh/) and [Wagmi](https://wagmi.sh/). The application is built with Vite and uses TypeScript.

## Features

- **Passkey Signup**: Create a new passkey to generate an Ethereum account
- **Passkey Login**: Login with an existing passkey
- **Message Signing**: Sign messages with your passkey to authenticate transactions
- **Responsive UI**: Simple and clean interface that works on both desktop and mobile

## Prerequisites

Before you begin, ensure you have the following installed:

- [Node.js](https://nodejs.org/) (v18.x or later recommended)
- [npm](https://www.npmjs.com/) (comes with Node.js) or [yarn](https://yarnpkg.com/)

## Getting Started

Follow these steps to set up and run the project locally:

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd reveries-passkey
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Run the development server:**
   ```bash
   # Option 1: Run without HTTPS (will use popup fallback)
   npm run dev
   
   # Option 2: Run with HTTPS (required for direct WebAuthn)
   USE_HTTPS=true npm run dev
   ```

   The application will be accessible at:
   - Without HTTPS: `http://localhost:5173`
   - With HTTPS: `https://localhost:5173`

## HTTPS Setup for WebAuthn

WebAuthn (the technology behind passkeys) requires a secure context (HTTPS) to function correctly. This project provides two options:

### Option 1: Development without HTTPS

When running without HTTPS, Porto will attempt to use a popup fallback for WebAuthn operations. This works in development but is not ideal for production.

### Option 2: Development with HTTPS (Built-in)

For the best experience, run with HTTPS enabled:

```bash
USE_HTTPS=true npm run dev
```

This uses `vite-plugin-mkcert` to automatically generate a trusted self-signed SSL certificate for `localhost`. You may need to:

1. Accept the certificate warning in your browser
2. Grant permission to install the local CA (Certificate Authority) if prompted

If you encounter any issues with HTTPS, ensure that the local CA provided by `mkcert` is trusted by your system and browser.

### Option 3: Using Caddy as a Reverse Proxy

Another great option for HTTPS during development is to use [Caddy](https://caddyserver.com/) as a reverse proxy in front of your dev server.

1. **Install Caddy**: Follow the [installation instructions](https://caddyserver.com/docs/install) for your platform

2. **Create a Caddyfile** in your project root with the following content:
   ```
   example.localhost {
     reverse_proxy localhost:5173
   }
   ```

3. **Start your dev server** in one terminal:
   ```bash
   npm run dev
   ```

4. **Start Caddy** in another terminal:
   ```bash
   caddy run
   # or for background mode
   caddy start
   ```

5. **Visit** your application at `https://example.localhost`

This approach has several advantages:
- Automatic HTTPS with valid certificates
- No browser warnings or security exceptions
- Works for all WebAuthn/Passkey operations
- No need to modify the Vite configuration

## Usage Instructions

1. **Sign Up with Passkey**:
   - Click the "Sign Up with Passkey" button
   - Follow your browser's prompts to create a new passkey
   - This creates a new Ethereum account linked to your passkey

2. **Login with Passkey**:
   - Click the "Login with Passkey" button
   - Select your passkey when prompted by your browser
   - Your Ethereum address will be displayed upon successful login

3. **Sign Messages**:
   - After logging in, click "Create and Sign Hash"
   - A message will be hashed and signed with your passkey
   - The hash and signature will be displayed

4. **Disconnect**:
   - Click the "Disconnect" button to end your session

## Project Structure

- `src/App.tsx`: Main application component, sets up Wagmi providers
- `src/components/PasskeyLogin.tsx`: React component implementing the passkey functionality
- `src/wagmi.ts`: Wagmi configuration, including the Porto connector setup
- `vite.config.ts`: Vite configuration, including optional HTTPS setup
- `src/App.css`: Styling for the application

## Notes

- Passkeys are stored in your browser/device's secure storage
- Your passkey never leaves your device
- The Ethereum account is derived from your passkey credentials
- No private keys are exposed or transmitted

## Credits

Built with:
- [Porto](https://porto.sh/) - WebAuthn-based Ethereum accounts
- [Wagmi](https://wagmi.sh/) - React Hooks for Ethereum
- [React](https://reactjs.org/) - UI framework
- [Vite](https://vitejs.dev/) - Build tool and development server