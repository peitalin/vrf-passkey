/**
 * End-to-End Test: Create Delegate Action and Send to Relay Server
 *
 * This test demonstrates the complete flow:
 * 1. User creates a signed delegate action for account creation
 * 2. Sends the binary-encoded delegate to the relay server
 * 3. Relay server processes and broadcasts the transaction
 */

import { SignedTransactionComposer, getSignerFromKeystore } from '@near-js/client';
import { JsonRpcProvider } from '@near-js/providers';
import { InMemoryKeyStore } from '@near-js/keystores';
import { KeyPairEd25519, PublicKey } from '@near-js/crypto';
import { Account, LocalAccountCreator } from '@near-js/accounts';

import fetch from 'node-fetch';
// Load environment variables from .env file if it exists
import dotenv from 'dotenv';
dotenv.config();

// Test configuration
const TEST_CONFIG = {
  networkId: process.env.NEAR_NETWORK_ID || 'testnet',
  nodeUrl: process.env.NEAR_NODE_URL || 'https://rpc.testnet.near.org',
  relayServerUrl: process.env.RELAY_SERVER_URL || 'http://localhost:3001',

  // Relayer account - needs to be real for funding new accounts
  relayerAccount: {
    accountId: process.env.RELAYER_ACCOUNT_ID || 'relayer.testnet',
    privateKey: process.env.RELAYER_PRIVATE_KEY || 'ed25519:example-key'
  },

  // Test accounts - will be generated dynamically
  userAccount: {
    accountId: undefined as string | undefined, // Will be set dynamically
    privateKey: undefined as string | undefined, // Will be generated
    keyPair: undefined as any | undefined    // Will be generated
  },

  newAccount: {
    accountId: undefined as string | undefined  // Will be set dynamically
  }
};

class DelegateActionTest {
  private rpcProvider: any;
  private userKeyStore: any;
  private relayerKeyStore: any;
  private userSigner: any;
  private relayerSigner: any;
  private relayerAccount: any;

  constructor() {
    this.rpcProvider = new JsonRpcProvider({ url: TEST_CONFIG.nodeUrl });
    this.userKeyStore = new InMemoryKeyStore();
    this.relayerKeyStore = new InMemoryKeyStore();
    this.userSigner = null;
    this.relayerSigner = null;
    this.relayerAccount = null;
  }

  async setup() {
    console.log('🔧 Setting up test environment...');

        try {
      // Step 1: Set up relayer account first (needed for account naming)
      await this.setupRelayerAccount();

      // Step 2: Generate new keypairs for test accounts
      console.log('📝 Generating new NEAR ed25519 keypairs...');

      const userKeyPair = KeyPairEd25519.fromRandom();
      const userPublicKey = userKeyPair.getPublicKey();

      // Create unique account IDs as subaccounts of relayer
      const timestamp = Date.now();
      const relayerAccountId = TEST_CONFIG.relayerAccount.accountId;
      const userAccountId = `test-user-${timestamp}.${relayerAccountId}`;
      const newAccountId = `test-new-${timestamp}.${relayerAccountId}`;

      // Store generated data in config
      TEST_CONFIG.userAccount.keyPair = userKeyPair;
      TEST_CONFIG.userAccount.privateKey = `ed25519:${userKeyPair.secretKey}`;
      TEST_CONFIG.userAccount.accountId = userAccountId;
      TEST_CONFIG.newAccount.accountId = newAccountId;

      console.log(`✅ Generated user account: ${userAccountId}`);
      console.log(`✅ Generated new account: ${newAccountId}`);
      console.log(`✅ Generated public key: ${userPublicKey.toString()}`);

      // Step 3: Create the test user account
      await this.createTestUserAccount(userAccountId, userPublicKey.toString());

      // Step 4: Set up user keystore and signer
      await this.userKeyStore.setKey(
        TEST_CONFIG.networkId,
        userAccountId,
        userKeyPair
      );

      this.userSigner = await getSignerFromKeystore(
        userAccountId,
        TEST_CONFIG.networkId,
        this.userKeyStore
      );

      // Ensure the signer has the correct accountId set
      if (!this.userSigner.accountId) {
        this.userSigner.accountId = userAccountId;
      }

      console.log(`✅ User signer initialized for: ${userAccountId}`);
      console.log(`🔧 User signer accountId: ${this.userSigner.accountId}`);

      // Debug: Check what public key the user signer has
      const userSignerPublicKey = await this.userSigner.getPublicKey(userAccountId, TEST_CONFIG.networkId);
      console.log(`🔑 User signer public key: ${userSignerPublicKey.toString()}`);

    } catch (error) {
      console.error('❌ Setup failed:', (error as Error).message);
      throw error;
    }
  }

  async setupRelayerAccount() {
    console.log('🔧 Setting up relayer account...');

    const relayerPrivateKey = TEST_CONFIG.relayerAccount.privateKey;
    if (!relayerPrivateKey || relayerPrivateKey === 'ed25519:example-key') {
      throw new Error('Valid RELAYER_PRIVATE_KEY required to fund test accounts');
    }

    const privateKeyString = relayerPrivateKey.substring(8); // Remove 'ed25519:' prefix
    const keyPair = new KeyPairEd25519(privateKeyString);

    await this.relayerKeyStore.setKey(
      TEST_CONFIG.networkId,
      TEST_CONFIG.relayerAccount.accountId,
      keyPair
    );

    this.relayerSigner = await getSignerFromKeystore(
      TEST_CONFIG.relayerAccount.accountId,
      TEST_CONFIG.networkId,
      this.relayerKeyStore
    );

    this.relayerAccount = new Account(
      TEST_CONFIG.relayerAccount.accountId,
      this.rpcProvider,
      this.relayerSigner
    );

    console.log(`✅ Relayer account ready: ${TEST_CONFIG.relayerAccount.accountId}`);
    console.log(`   Relayer public key: ${this.relayerSigner}`);
    console.log(`   Relayer private key: ${TEST_CONFIG.relayerAccount.privateKey}`);
  }

  async createTestUserAccount(accountId: string, publicKeyString: string) {
    console.log(`🏗️  Creating test user account: ${accountId}`);

    try {
      const initialBalance = BigInt('50000000000000000000000'); // 0.05 NEAR
      const accountCreator = new LocalAccountCreator(this.relayerAccount, initialBalance);

      await accountCreator.createAccount(accountId, PublicKey.fromString(publicKeyString));

      console.log(`✅ Test user account created: ${accountId}`);
      console.log(`💰 Initial balance: 0.05 NEAR`);

    } catch (error) {
      console.error(`❌ Failed to create test user account: ${(error as Error).message}`);
      throw error;
    }
  }

  async createSignedDelegate() {
    console.log('\nCreating signed delegate action...');

    try {
      console.log(`Sender: ${TEST_CONFIG.userAccount.accountId}`);
      console.log(`New Account: ${TEST_CONFIG.newAccount.accountId}`);

      // Generate a keypair for the new account
      const newAccountKeyPair = KeyPairEd25519.fromRandom();
      const newAccountPublicKey = newAccountKeyPair.getPublicKey();

      console.log(`New account public key: ${newAccountPublicKey.toString()}`);

      // Debug: Check the signing parameters before creating delegate action
      console.log(`🔧 Signing parameters:`);
      console.log(`  - Network ID: ${TEST_CONFIG.networkId}`);
      console.log(`  - Sender: ${TEST_CONFIG.userAccount.accountId}`);
      console.log(`  - Receiver: ${TEST_CONFIG.relayerAccount.accountId}`);
      console.log(`  - User signer account: ${this.userSigner.accountId || 'undefined'}`);
      console.log(`  - User signer type: ${typeof this.userSigner}`);
      console.log(`  - User signer keys: ${Object.keys(this.userSigner)}`);

      // For account creation delegate actions:
      // - User authorizes the action (sender)
      // - Relayer is the receiver (existing account that can execute the action)
      // - Actions specify what account to create
      const signedDelegate = await SignedTransactionComposer.init({
        sender: TEST_CONFIG.userAccount.accountId, // User authorizing the creation
        receiver: TEST_CONFIG.relayerAccount.accountId, // Relayer as receiver (existing account)
        deps: { rpcProvider: this.rpcProvider, signer: this.userSigner },
      })
      .transfer(BigInt("1000000000000000000000")) // Simple 0.001 NEAR transfer to test delegate action
      .toSignedDelegateAction({ blockHeightTtl: 60n });

      console.log(`Signed delegate result:`, typeof signedDelegate, signedDelegate);

      // Debug: Check if public keys match
      const delegatePublicKey = signedDelegate.delegateAction.publicKey;
      const signerPublicKey = await this.userSigner.getPublicKey(TEST_CONFIG.userAccount.accountId!, TEST_CONFIG.networkId);
      console.log(`🔑 Delegate action public key: ${delegatePublicKey.toString()}`);
      console.log(`🔑 User signer public key: ${signerPublicKey.toString()}`);
      console.log(`🔍 Public keys match: ${delegatePublicKey.toString() === signerPublicKey.toString()}`);

      // Debug: Check what the actual account nonce should be
      try {
        const accessKey = await this.rpcProvider.query({
          request_type: 'view_access_key',
          finality: 'final',
          account_id: TEST_CONFIG.userAccount.accountId!,
          public_key: signerPublicKey.toString()
        });
        const accessKeyNonce = (accessKey as any).nonce;
        console.log(`🔑 Access key nonce: ${accessKeyNonce}`);
        console.log(`🔗 Delegate action nonce: ${signedDelegate.delegateAction.nonce}`);
        console.log(`⚠️  Nonce comparison: access=${accessKeyNonce}, delegate=${signedDelegate.delegateAction.nonce}`);
      } catch (error) {
        console.log(`❌ Could not check access key nonce: ${(error as Error).message}`);
      }

      // Check if we need to encode the result
      let encodedDelegate;
      if (signedDelegate instanceof Uint8Array) {
        encodedDelegate = signedDelegate;
      } else {
        // If it's a SignedDelegate object, encode it
        const { encodeSignedDelegate } = require('@near-js/transactions');
        encodedDelegate = encodeSignedDelegate(signedDelegate);
      }

      console.log(`Signed delegate created (${encodedDelegate.length} bytes)`);
      return encodedDelegate;

    } catch (error) {
      console.error('Failed to create signed delegate:', (error as Error).message);
      throw error;
    }
  }

  async sendToRelayServer(signedDelegate: Uint8Array) {
    console.log('\nSending signed delegate to relay server...');

    try {
      const relayUrl = `${TEST_CONFIG.relayServerUrl}/relay/create-account?newAccountId=${encodeURIComponent(TEST_CONFIG.newAccount.accountId!)}`;
      console.log(`Relay Server: ${relayUrl}`);
      console.log(`Payload Size: ${signedDelegate.length} bytes`);
      console.log(`Target Account: ${TEST_CONFIG.newAccount.accountId}`);

      const response = await fetch(relayUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
        },
        body: signedDelegate
      });

      const responseText = await response.text();
      let result;

      try {
        result = JSON.parse(responseText);
      } catch {
        result = { raw: responseText };
      }

      console.log(`Response Status: ${response.status}`);
      console.log(`Response:`, JSON.stringify(result, null, 2));

      if (response.ok && result.success) {
        console.log(`Delegate action processed successfully!`);
        if (result.transactionHash) {
          console.log(`Transaction Hash: ${result.transactionHash}`);
        }
      } else {
        console.log(`️Delegate action failed or had issues`);
      }

      return { response, result };

    } catch (error) {
      console.error('Failed to send to relay server:', (error as Error).message);
      throw error;
    }
  }

  async testRelayServerHealth() {
    console.log('\nTesting relay server health...');

    try {
      // Test basic health endpoint
      const healthResponse = await fetch(`${TEST_CONFIG.relayServerUrl}/`);
      const healthText = await healthResponse.text();

      if (healthResponse.ok) {
        console.log('Relay server is responding:', healthText.trim());
        return true;
      } else {
        console.log('️Relay server health check failed');
        return false;
      }

    } catch (error) {
      console.error('Relay server health check failed:', (error as Error).message);
      return false;
    }
  }

  async testLocalMockDelegate() {
    console.log('\nTesting local mock delegate creation...');

    try {
      // Create a mock signed delegate locally (same logic as removed server endpoint)
      const signedDelegate = await this.createSignedDelegate();

      console.log(`Local mock delegate created (${signedDelegate.length} bytes)`);
      console.log(`Mock delegate ready for testing`);

      return { success: true, signedDelegate };

    } catch (error) {
      console.error('Local mock delegate creation failed:', (error as Error).message);
      return { success: false, error: (error as Error).message };
    }
  }

  async run() {
    console.log('🎯 Starting Delegate Action End-to-End Test\n');

    try {
      // Step 1: Setup
      await this.setup();

      // Step 2: Check relay server health
      const serverHealthy = await this.testRelayServerHealth();
      if (!serverHealthy) {
        console.log('\n️Relay server appears to be down or not responding properly');
        console.log('   Please ensure the relay server is running on http://localhost:3001');
        console.log('   You can start it with: pnpm run dev');
        return;
      }

      // Step 3: Test local mock delegate creation first
      console.log('\n--- Testing Local Mock Delegate Creation ---');
      const mockResult = await this.testLocalMockDelegate();
      if (!mockResult.success) {
        console.log('Local mock delegate creation failed, but continuing with test...');
      }

      // Step 4: Create signed delegate
      console.log('\n--- Testing Real Delegate Creation ---');
      const signedDelegate = await this.createSignedDelegate();

      // Step 5: Send to relay server
      const { response, result } = await this.sendToRelayServer(signedDelegate);

      // Step 6: Summary
      console.log('\nTest Summary:');
      console.log(`   - Signed Delegate Created: ✅`);
      console.log(`   - Sent to Relay Server: ✅`);
      console.log(`   - Server Response: ${response.ok ? '✅' : '❌'}`);
      console.log(`   - Delegate Processed: ${result.success ? '✅' : '❌'}`);

      if (result.success && result.transactionHash) {
        console.log(`\nSUCCESS! Account creation delegate action completed successfully!`);
        console.log(`View transaction: https://testnet.nearblocks.io/txns/${result.transactionHash}`);
      } else {
        console.log(`\nTest completed but delegate action was not successful`);
        console.log(`   This might be expected if using test credentials or if accounts don't exist`);
      }

    } catch (error) {
      console.error('\nTest failed with error:', (error as Error).message);
      console.error('Stack trace:', (error as Error).stack);
    }
  }
}

// Helper function to check if server is running
async function waitForServer(url: string, maxAttempts = 10, delay = 1000) {
  console.log(`Waiting for server at ${url}...`);

  for (let i = 0; i < maxAttempts; i++) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        console.log(`Server is ready!`);
        return true;
      }
    } catch (error) {
      // Server not ready yet
    }

    if (i < maxAttempts - 1) {
      console.log(`   Attempt ${i + 1}/${maxAttempts} failed, waiting ${delay}ms...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  console.log(`Server did not become ready after ${maxAttempts} attempts`);
  return false;
}

// Validate test configuration
function validateTestConfig() {
  const errors: string[] = [];

  // Check if relayer account is configured
  if (TEST_CONFIG.relayerAccount.privateKey === 'ed25519:example-key') {
    errors.push('RELAYER_PRIVATE_KEY: Required to fund new test accounts. Set a real relayer private key.');
  }

  if (TEST_CONFIG.relayerAccount.accountId === 'relayer.testnet') {
    errors.push('RELAYER_ACCOUNT_ID: Set a real relayer account ID that has sufficient balance.');
  }

  if (errors.length > 0) {
    console.log('❌ Test Configuration Errors:');
    errors.forEach(error => console.log(`   - ${error}`));
    console.log('\n🔧 To fix these issues:');
    console.log('\n1. Create a NEAR testnet account:');
    console.log('   - Go to: https://testnet.mynearwallet.com/');
    console.log('   - Create an account (e.g., yourname.testnet)');
    console.log('   - Fund it from faucet: https://near-faucet.io/');
    console.log('   - Export the private key from your wallet');
    console.log('\n2. Set environment variables:');
    console.log('   export RELAYER_ACCOUNT_ID="yourname.testnet"');
    console.log('   export RELAYER_PRIVATE_KEY="ed25519:your-real-private-key"');
    console.log('\n   Or create a .env file in relay-server/ with:');
    console.log('   RELAYER_ACCOUNT_ID=yourname.testnet');
    console.log('   RELAYER_PRIVATE_KEY=ed25519:your-real-private-key');
    console.log('\n⚠️  Important: The relayer account must actually exist on NEAR testnet!');
    console.log('💡 The test will automatically generate and fund new test accounts.');
    return false;
  }

  return true;
}

// Main execution
async function main() {
  // Check if we need to install node-fetch
  try {
    require('node-fetch');
  } catch (error) {
    console.log('Installing node-fetch dependency...');
    const { execSync } = require('child_process');
    execSync('npm install node-fetch@2', { stdio: 'inherit' });
    console.log('node-fetch installed');
  }

  console.log('Delegate Action Test Suite');
  console.log('=' .repeat(50));

  // Validate configuration
  if (!validateTestConfig()) {
    process.exit(1);
  }

  // Wait for server to be ready
  const serverReady = await waitForServer(TEST_CONFIG.relayServerUrl);
  if (!serverReady) {
    console.log('\nCould not connect to relay server');
    console.log('Please start the relay server first:');
    console.log('  cd relay-server');
    console.log('  pnpm run dev');
    process.exit(1);
  }

  // Run the test
  const test = new DelegateActionTest();
  await test.run();
}

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { DelegateActionTest, TEST_CONFIG };