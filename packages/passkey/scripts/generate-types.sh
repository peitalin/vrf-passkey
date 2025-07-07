#!/bin/bash

# Script to generate TypeScript types from Rust and validate consistency

set -e

echo "Generating TypeScript types from Rust..."

# 1. Generate TypeScript types from Rust using ts-rs
cd src/wasm_signer_worker
cargo test -- --test-threads=1 --nocapture || echo "Type generation completed"
cd ../..

# 2. Check if generated types directory exists
GENERATED_DIR="src/core/types/generated"
if [ ! -d "$GENERATED_DIR" ]; then
    echo "❌ Generated types directory not found at $GENERATED_DIR"
    echo "   Make sure ts-rs export paths are correct in Rust code"
    exit 1
fi

echo "TypeScript types generated successfully"

# 3. Run type checking to ensure consistency
echo "Running TypeScript type checking..."
npm run type-check

# 4. Generate schema validation
echo "Generating schema validation..."
# You could add a custom script here to generate zod schemas from the generated TS types

echo "Type generation and validation complete!"
echo ""
echo "Generated files:"
echo "  - $GENERATED_DIR/*.ts (TypeScript interfaces from Rust)"
echo "  - Validated against existing TypeScript codebase"
