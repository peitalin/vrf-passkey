#!/bin/bash

# For local development, we need to symlink the SDK to the frontend node_modules
cd ./packages/passkey && pnpm link --global
cd ../../
cd frontend && pnpm link --global @web3authn/passkey
cd ../