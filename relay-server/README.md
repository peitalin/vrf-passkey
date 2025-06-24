# Relay Server - Delegate Actions Implementation

A NEAR relay server that processes delegate actions, allowing users to sign transactions while the relayer pays gas fees.

## Features

- **Delegate Action Processing**: Accept and broadcast signed delegate actions
- **Account Creation**: Specialized support for account creation via delegate transactions
- **Transaction Queuing**: Prevents nonce conflicts with built-in transaction queue
- **Testing Endpoints**: Mock delegate creation for development and testing
- **Monitoring**: Queue diagnostics and transaction monitoring

## API Endpoints

### Core Endpoint

#### `POST /relay/create-account`
Create account via delegate action.

**Request:**
- Content-Type: `application/octet-stream`
- Body: Binary-encoded signed delegate action for account creation

**Response:**
```json
{
  "success": true,
  "transactionHash": "...",
  "outcome": { ... },
  "message": "Account created successfully via delegate action"
}
```

## Configuration

Set environment variables in `.env`:

```bash
# Relayer Account
RELAYER_ACCOUNT_ID=relayer.testnet
RELAYER_PRIVATE_KEY=ed25519:...

# NEAR Network
NEAR_NETWORK_ID=testnet
NEAR_NODE_URL=https://rpc.testnet.near.org

# Server Config
PORT=3001
EXPECTED_ORIGIN=https://example.localhost
```

## Usage Examples

### Client-Side (User Creates Signed Delegate)

```typescript
import { SignedTransactionComposer, getSignerFromKeystore } from '@near-js/client';

// User creates signed delegate for account creation
const signedDelegate = await SignedTransactionComposer.init({
  sender: 'user.testnet',
  receiver: 'newuser.testnet',
  deps: { rpcProvider, signer: userSigner },
})
.createAccount()
.toSignedDelegateAction({ blockHeightTtl: 60n });

// Send to relay server
const response = await fetch('http://localhost:3001/relay/create-account', {
  method: 'POST',
  headers: { 'Content-Type': 'application/octet-stream' },
  body: signedDelegate
});
```

### Testing

#### Prerequisites
The test script automatically generates new NEAR ed25519 keypairs and creates test accounts. It requires a **real NEAR testnet relayer account** that exists and has sufficient balance to fund the new test accounts.

**Create a Test Relayer Account:**
1. Go to [NEAR Wallet](https://testnet.mynearwallet.com/) and create a testnet account
2. Fund it with some testnet NEAR tokens from the [faucet](https://near-faucet.io/)
3. Export the private key from your wallet

**Option 1: Environment Variables**
```bash
export RELAYER_ACCOUNT_ID="your-real-account.testnet"
export RELAYER_PRIVATE_KEY="ed25519:your-real-private-key"
```

**Option 2: .env File**
Create a `.env` file in the `relay-server` directory:
```env
RELAYER_ACCOUNT_ID=your-real-account.testnet
RELAYER_PRIVATE_KEY=ed25519:your-real-private-key
```

**Important:** The relayer account must:
- Actually exist on NEAR testnet
- Have sufficient balance (at least 0.1 NEAR recommended)
- Have the correct private key that matches the account

#### Running Tests
```bash
# Run the comprehensive test suite
pnpm run test

# Or run directly
node test-delegate-flow.js

# The test script will:
# 1. Validate relayer credentials
# 2. Generate new ed25519 keypairs
# 3. Create test accounts using relayer
# 4. Check server health
# 5. Create signed delegates locally
# 6. Send to relay server
# 7. Validate end-to-end flow
```

**Notes**:
- The test script will wait for the server to be ready on `http://localhost:3001`
- Make sure to start the relay server first with `pnpm run dev`
- Only requires a relayer account with sufficient balance (~0.1 NEAR minimum)
- Test accounts are automatically generated and funded

## Development

```bash
# Install dependencies
pnpm install

# Build
pnpm run build

# Start development server
pnpm run dev

# Start production server
pnpm start

# Run tests
pnpm run test
```

## Architecture

- **DelegateService**: Core service handling delegate action processing
- **Transaction Queue**: Prevents nonce conflicts for relayer account
- **Binary Middleware**: Handles binary-encoded signed delegates
- **Validation**: Validates delegate actions and account IDs
- **BigInt Serialization**: Automatic conversion of BigInt values to prevent JSON serialization errors
- **Error Handling**: Comprehensive error handling and logging

### BigInt Serialization Handling

The server correctly handles BigInt values in delegate actions by using lower-level transaction functions:

- **Problem Identified**: `SignedTransactionComposer.signedDelegate()` calls `JSON.stringify()` internally, causing BigInt serialization errors
- **Solution**: Use `Account.signAndSendTransaction()` directly to create meta-transactions with signed delegate actions
- **Implementation**: Create signed delegate actions with proper enum structure and bypass the problematic higher-level composer
- **Decode Function**: Uses `deserialize(SCHEMA.SignedDelegate, bytes)` which correctly handles BigInt values through Borsh

This approach avoids the `"Do not know how to serialize a BigInt"` errors completely while maintaining proper NEAR transaction semantics.

## Implementation Notes

1. **Decode Function**: Successfully implemented using Borsh deserialization with `deserialize(SCHEMA.SignedDelegate, bytes)` from the existing schema in `@near-js/transactions`.

2. **Encoding/Decoding**: Full support for encoding and decoding signed delegates using the standard NEAR.js patterns.

3. **BigInt Resolution**: Successfully resolved BigInt serialization errors by using `Account.signAndSendTransaction()` instead of `SignedTransactionComposer.signedDelegate()`, avoiding internal JSON.stringify() calls that don't support BigInt.

4. **Meta-Transaction Pattern**: Implements proper delegate action relaying where the relayer creates a meta-transaction containing the user's signed delegate action as a `signedDelegate` action type.

## Security

- Validates delegate action signatures
- Restricts allowed action types (CreateAccount, AddKey, Transfer)
- Validates account ID formats
- Implements transaction queuing to prevent nonce conflicts
- Logs all transactions for monitoring

## Next Steps

1. Resolve the `decodeSignedDelegate` function implementation
2. Test with real signed delegates from frontend
3. Implement rate limiting
4. Add comprehensive monitoring and alerts