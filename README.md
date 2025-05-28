# Passkey Example Repo

This project contains:
-   `/frontend`: React/Vite frontend application and its Caddyfile.
-   `/server`: Webauthn backend server.

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
