#!/bin/bash

# Development contract upgrade script
# This script can be used to upgrade the contract without requiring a clean git state
# Useful for rapid development and testing

# Set the contract ID directly (no need for .env file)
WEBAUTHN_CONTRACT_ID="web3-authn-v1.testnet"

echo "Upgrading contract: $WEBAUTHN_CONTRACT_ID"
echo "Building contract with non-reproducible WASM (faster for dev)..."

# Build the contract using non-reproducible WASM for faster development builds
cargo near build non-reproducible-wasm

if [ $? -ne 0 ]; then
    echo "Build failed! Cannot proceed with upgrade."
    exit 1
fi

echo "Deploying contract upgrade..."

# Deploy contract without initialization call using keychain signing
cargo near deploy $WEBAUTHN_CONTRACT_ID \
    without-init-call \
    network-config testnet \
	sign-with-plaintext-private-key \
	--signer-public-key $DEPLOYER_PUBLIC_KEY \
	--signer-private-key $DEPLOYER_PRIVATE_KEY \
    send

if [ $? -eq 0 ]; then
    echo "Contract upgrade completed successfully!"
    echo "Contract ID: $WEBAUTHN_CONTRACT_ID"
    echo "Network: testnet"
    echo ""
    echo "️Note: This deployment uses non-reproducible WASM."
    echo "    For production deployments, use the regular upgrade.sh script."
else
    echo "Contract upgrade failed!"
    exit 1
fi