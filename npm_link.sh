#!/bin/bash

cd ./packages/passkey && pnpm link --global
cd ../../
cd frontend && pnpm link --global @web3authn/passkey
cd ../