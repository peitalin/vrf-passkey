/**
 * End-to-End Test: Simple Account Creation via Relay Server
 *
 * This test demonstrates the simplified flow:
 * 1. User sends accountId and publicKey to relay server
 * 2. Relay server creates the account directly using its authority
 */

import { KeyPairEd25519 } from '@near-js/crypto';
import fetch from 'node-fetch';

// Load environment variables from .env file if it exists
import dotenv from 'dotenv';
dotenv.config();

// Test configuration
const TEST_CONFIG = {
  relayServerUrl: process.env.RELAY_SERVER_URL || 'http://localhost:3001',
};

class SimpleAccountCreationTest {

  async testAccountCreation() {
    console.log('\n🎯 Testing Simple Account Creation via Relay Server\n');

    try {
      // Generate a keypair for the new account
      const keyPair = KeyPairEd25519.fromRandom();
      const publicKey = keyPair.getPublicKey();

      // Create a unique account ID as a subaccount of the relayer
      const timestamp = Date.now();
      const accountId = `test-simple-${timestamp}.web3-authn.testnet`;

      console.log(`✨ Generated new account details:`);
      console.log(`   Account ID: ${accountId}`);
      console.log(`   Public Key: ${publicKey.toString()}`);

      // Send request to relay server
      console.log(`\n📨 Sending account creation request to relay server...`);
      const response = await fetch(`${TEST_CONFIG.relayServerUrl}/relay/create-account`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          accountId: accountId,
          publicKey: publicKey.toString()
        })
      });

      const result = await response.json();

      console.log(`\nResponse Status: ${response.status}`);
      console.log(`Response:`, JSON.stringify(result, null, 2));

      if (response.ok && result.success) {
        console.log(`\n🎉 SUCCESS! Account created successfully!`);
        console.log(`   Account ID: ${result.accountId}`);
        console.log(`   Transaction Hash: ${result.transactionHash}`);
        console.log(`   View transaction: https://testnet.nearblocks.io/txns/${result.transactionHash}`);
        return true;
      } else {
        console.log(`\n❌ Account creation failed`);
        console.log(`   Error: ${result.error}`);
        console.log(`   Message: ${result.message}`);
        return false;
      }

    } catch (error) {
      console.error('\nTest failed with error:', (error as Error).message);
      console.error('Stack trace:', (error as Error).stack);
      return false;
    }
  }

  async testRelayServerHealth() {
    console.log('🔍 Testing relay server health...');

    try {
      const response = await fetch(`${TEST_CONFIG.relayServerUrl}/`);
      const healthText = await response.text();

      if (response.ok) {
        console.log('✅ Relay server is responding:', healthText.trim());
        return true;
      } else {
        console.log('❌ Relay server health check failed');
        return false;
      }

    } catch (error) {
      console.error('❌ Relay server health check failed:', (error as Error).message);
      return false;
    }
  }

  async run() {
    console.log('Simple Account Creation Test Suite');
    console.log('=' .repeat(50));

    // Step 1: Check relay server health
    const serverHealthy = await this.testRelayServerHealth();
    if (!serverHealthy) {
      console.log('\n❌ Relay server appears to be down or not responding properly');
      console.log('   Please ensure the relay server is running on http://localhost:3001');
      console.log('   You can start it with: pnpm run dev');
      return;
    }

    // Step 2: Test account creation
    const success = await this.testAccountCreation();

    // Step 3: Summary
    console.log('\n' + '=' .repeat(50));
    console.log('📊 Test Summary:');
    console.log(`   - Server Health: ✅`);
    console.log(`   - Account Creation: ${success ? '✅' : '❌'}`);

    if (success) {
      console.log(`\n🎊 All tests passed! The simplified account creation is working!`);
    } else {
      console.log(`\n⚠️  Some tests failed. Check the logs above for details.`);
    }
  }
}

// Helper function to check if server is running
async function waitForServer(url: string, maxAttempts = 10, delay = 1000) {
  console.log(`⏳ Waiting for server at ${url}...`);

  for (let i = 0; i < maxAttempts; i++) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        console.log(`✅ Server is ready!`);
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

  console.log(`❌ Server did not become ready after ${maxAttempts} attempts`);
  return false;
}

// Main execution
async function main() {
  // Wait for server to be ready
  const serverReady = await waitForServer(TEST_CONFIG.relayServerUrl);
  if (!serverReady) {
    console.log('\n❌ Could not connect to relay server');
    console.log('Please start the relay server first:');
    console.log('  cd relay-server');
    console.log('  pnpm run dev');
    process.exit(1);
  }

  // Run the test
  const test = new SimpleAccountCreationTest();
  await test.run();
}

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { SimpleAccountCreationTest, TEST_CONFIG };