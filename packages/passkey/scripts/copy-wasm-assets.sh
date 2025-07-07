#!/bin/bash

# Copy worker assets to frontend directory
# This script copies all necessary worker files from the passkey package to the frontend public directory

set -e  # Exit on any error

FRONTEND_WORKERS_DIR="../../frontend/public/workers"

echo "Copying worker files to frontend..."

# Ensure the target directory exists
mkdir -p "$FRONTEND_WORKERS_DIR"

# Copy main passkey worker files
echo "Copying passkey signerworker files..."
# worker wrapper
cp dist/web3authn-signer.worker.js "$FRONTEND_WORKERS_DIR/"
# worker wasm files
cp dist/wasm_signer_worker.js "$FRONTEND_WORKERS_DIR/"
cp dist/wasm_signer_worker_bg.wasm "$FRONTEND_WORKERS_DIR/"

# Copy VRF worker files
echo "Copying VRF worker files..."
# worker wrapper
cp dist/web3authn-vrf.worker.js "$FRONTEND_WORKERS_DIR/"
# worker wasm files
cp dist/wasm_vrf_worker.js "$FRONTEND_WORKERS_DIR/"
cp dist/wasm_vrf_worker_bg.wasm "$FRONTEND_WORKERS_DIR/"

echo "Worker files copied to frontend/public/workers/"
echo "Signer Worker Files copied:"
echo "   - web3authn-signer.worker.js"
echo "   - wasm_signer_worker.js"
echo "   - wasm_signer_worker_bg.wasm"
echo "VRF Worker Files copied:"
echo "   - web3authn-vrf.worker.js"
echo "   - wasm_vrf_worker.js"
echo "   - wasm_vrf_worker_bg.wasm"