#!/bin/bash

# Copy worker assets to frontend directory
# This script copies all necessary worker files from the passkey package to the frontend public directory

set -e  # Exit on any error

FRONTEND_WORKERS_DIR="../../frontend/public/workers"

echo "🔧 Copying worker files to frontend..."

# Ensure the target directory exists
mkdir -p "$FRONTEND_WORKERS_DIR"

# Copy main passkey worker files
echo "📦 Copying main passkey worker files..."
cp dist/onetimePasskeySigner.worker.js "$FRONTEND_WORKERS_DIR/"
cp dist/web3authn_passkey_worker.js "$FRONTEND_WORKERS_DIR/"
cp dist/web3authn_passkey_worker_bg.wasm "$FRONTEND_WORKERS_DIR/"

# Copy VRF worker files
echo "🔐 Copying VRF worker files..."
cp src/wasm-vrf-worker/vrf_service_worker.js "$FRONTEND_WORKERS_DIR/"
cp src/wasm-vrf-worker/vrf_service_worker_bg.wasm "$FRONTEND_WORKERS_DIR/"
cp dist/vrf-service-worker.js "$FRONTEND_WORKERS_DIR/"

echo "✅ Worker files copied to frontend/public/workers/"
echo "📁 Files copied:"
echo "   - onetimePasskeySigner.worker.js"
echo "   - web3authn_passkey_worker.js"
echo "   - web3authn_passkey_worker_bg.wasm"
echo "   - vrf_service_worker.js"
echo "   - vrf_service_worker_bg.wasm"
echo "   - vrf-service-worker.js"