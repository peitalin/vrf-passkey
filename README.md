# Passkey Example Repo

**How It Works:**
Fast Auth (Optimistic Mode):
✅ Immediate SimpleWebAuthn verification
✅ Instant response to user
✅ Background contract update (fire-and-forget)
✅ Much faster UX

**Secure Auth (Contract Sync Mode):**
✅ Full contract verification before response
✅ On-chain commitment validation
✅ Maximum security
The toggle defaults to synchronous mode for security, but users can switch to optimistic mode for faster authentication. The setting persists across sessions via localStorage.
Try toggling between the modes and notice the speed difference during authentication!


## Prerequisites

- [Node.js](https://nodejs.org/) (v18.x or later recommended)
- [pnpm](https://pnpm.io/) (v8.x or later recommended)
- [Caddy](https://caddyserver.com/docs/install) (for running the frontend with HTTPS via `pnpm dev`)
- [Rust](https://www.rust-lang.org/tools/install) (for building the WASM module)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) (for building the WASM module)

### Installing wasm-pack

```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

## Setup
From the root directory, run:
```bash
pnpm install-all
```
This will install dependencies for the root, `./server`, and `./frontend` directories.

### Building the WASM Module

Before running the frontend, you need to build the WASM module for secure key derivation:

```bash
pnpm build-wasm
```

This will build the WASM module located in `frontend/wasm-worker` and output the generated files to `frontend/wasm-worker/pkg`.

## Running the Application

All commands should be run from the **root directory** of the project.

### Running the Frontend (with Caddy for HTTPS)

To start the frontend application (which includes Vite and Caddy for HTTPS on `https://example.localhost`):

```bash
pnpm dev
```

This will:
1.  Print "starting app on https://example.localhost"
2.  Start the Caddy server (reverse proxying to Vite).
3.  Start the Vite development server.

Access the frontend at `https://example.localhost`.

### Running the Backend Server

To start the backend Node.js/Express server:

```bash
pnpm server
```

This will:
1.  Build the server TypeScript code (output to `server/dist`).
2.  Start the server, typically listening on `http://localhost:3001` (as configured in `server/src/index.ts`).
