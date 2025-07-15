#!/bin/bash

# Copy worker assets to frontend directory
# This script copies all necessary worker files from the passkey package to the frontend public directory

set -e  # Exit on any error

# Source centralized build configuration
source "$(dirname "$0")/../build-paths.sh"

echo "Copying worker files to frontend..."

# Ensure the target directory exists
mkdir -p "$FRONTEND_SDK"

# Copy the entire workers directory
echo "Copying workers directory..."
cp -r "$BUILD_WORKERS" "$FRONTEND_SDK/"

echo "✅ Worker files copied successfully!"
echo "Files copied to: $FRONTEND_WORKERS"
echo ""
echo "Worker files available:"
ls -la "$FRONTEND_WORKERS"