/**
 * Simple Account Creation Test
 * Tests the relay server's ability to create NEAR accounts
 */

import { KeyPairEd25519 } from '@near-js/crypto';
import fetch from 'node-fetch';
import dotenv from 'dotenv';

dotenv.config();

const RELAY_SERVER_URL = process.env.RELAY_SERVER_URL || 'http://localhost:3001';

async function checkServerHealth(): Promise<boolean> {
  console.log('Checking relay server health...');
  try {
    const response = await fetch(`${RELAY_SERVER_URL}/`);
    const healthText = await response.text();
    if (response.ok) {
      console.log('✅ Server is responding:', healthText.trim());
      return true;
    } else {
      console.log('❌ Server health check failed');
      return false;
    }
  } catch (error) {
    console.error('❌ Server health check failed:', (error as Error).message);
    return false;
  }
}

async function createTestAccount(): Promise<boolean> {
  console.log('\n🎯 Creating test account...\n');

  try {
    // Generate keypair and account ID
    const keyPair = KeyPairEd25519.fromRandom();
    const publicKey = keyPair.getPublicKey();
    const timestamp = Date.now();
    const accountId = `test-${timestamp}.web3-authn.testnet`;

    console.log(`Account ID: ${accountId}`);
    console.log(`Public Key: ${publicKey.toString()}`);

    // Send creation request
    console.log('\nSending request to relay server...');
    const response = await fetch(`${RELAY_SERVER_URL}/relay/create-account`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId: accountId,
        publicKey: publicKey.toString()
      })
    });

    const result = await response.json();

    console.log(`Status: ${response.status}`);
    console.log(`Response:`, JSON.stringify(result, null, 2));

    if (response.ok && result.success) {
      console.log(`\n✅ SUCCESS!`);
      console.log(`   Account: ${result.accountId}`);
      console.log(`   Transaction: ${result.transactionHash}`);
      console.log(`   Link: https://testnet.nearblocks.io/txns/${result.transactionHash}`);
      return true;
    } else {
      console.log(`\n❌ FAILED`);
      console.log(`   Error: ${result.error}`);
      return false;
    }

  } catch (error) {
    console.error('\n❌ Test failed:', (error as Error).message);
    return false;
  }
}

async function waitForServer(maxAttempts = 10, delay = 1000): Promise<boolean> {
  console.log(`Waiting for server at ${RELAY_SERVER_URL}...`);

  for (let i = 0; i < maxAttempts; i++) {
    try {
      const response = await fetch(RELAY_SERVER_URL);
      if (response.ok) {
        console.log('✅ Server ready!');
        return true;
      }
    } catch (error) {
      // Server not ready
    }

    if (i < maxAttempts - 1) {
      console.log(`   Attempt ${i + 1}/${maxAttempts}, retrying in ${delay}ms...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  console.log('❌ Server not ready after all attempts');
  return false;
}

async function runTests() {
  console.log('Account Creation Test');
  console.log('=' .repeat(40));

  // Wait for server
  const serverReady = await waitForServer();
  if (!serverReady) {
    console.log('\n❌ Server not available');
    console.log('Start with: pnpm run dev');
    process.exit(1);
  }

  // Check health
  const healthy = await checkServerHealth();
  if (!healthy) {
    console.log('\n❌ Server unhealthy');
    return;
  }

  // Test account creation
  const success = await createTestAccount();

  // Summary
  console.log('\n' + '=' .repeat(40));
  console.log('Results:');
  console.log(`   Server Health: ✅`);
  console.log(`   Account Creation: ${success ? '✅' : '❌'}`);

  if (success) {
    console.log('\nAll tests passed!');
  } else {
    console.log('\nSome tests failed');
  }
}

// Run tests if called directly
if (require.main === module) {
  runTests().catch(console.error);
}

export { runTests, createTestAccount, checkServerHealth };