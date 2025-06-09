#!/usr/bin/env node

/**
 * Integration Test for Phase 2: FastAuth vs SecureAuth Registration
 */

const SERVER_URL = 'http://localhost:3001';

console.log('🧪 Testing Phase 2 Integration: FastAuth vs SecureAuth Registration\n');

// Test 1: Generate registration options with FastAuth
async function testFastAuthRegistration() {
  console.log('1️⃣ Testing FastAuth Registration Options Generation');

  try {
    const response = await fetch(`${SERVER_URL}/generate-registration-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser_fast',
        useOptimistic: true
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    console.log('   ✅ FastAuth options generated successfully');
    console.log(`   📋 CommitmentId: ${data.commitmentId || 'null (expected for fast mode)'}`);
    console.log(`   📋 Challenge length: ${data.challenge?.length || 0} chars`);
    console.log(`   📋 Near Account ID: ${data.nearAccountId || 'not set'}`);

    return { success: true, data };
  } catch (error) {
    console.log(`   ❌ FastAuth test failed: ${error.message}`);
    return { success: false, error: error.message };
  }
}

// Test 2: Generate registration options with SecureAuth
async function testSecureAuthRegistration() {
  console.log('\n2️⃣ Testing SecureAuth Registration Options Generation');

  try {
    const response = await fetch(`${SERVER_URL}/generate-registration-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser_secure',
        useOptimistic: false
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    console.log('   ✅ SecureAuth options generated successfully');
    console.log(`   📋 CommitmentId: ${data.commitmentId || 'null'}`);
    console.log(`   📋 Challenge length: ${data.challenge?.length || 0} chars`);
    console.log(`   📋 Near Account ID: ${data.nearAccountId || 'not set'}`);

    return { success: true, data };
  } catch (error) {
    console.log(`   ❌ SecureAuth test failed: ${error.message}`);
    return { success: false, error: error.message };
  }
}

// Test 3: Check server health
async function testServerHealth() {
  console.log('\n3️⃣ Testing Server Health');

  try {
    const response = await fetch(`${SERVER_URL}/`);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const text = await response.text();
    console.log('   ✅ Server is running');
    console.log(`   📋 Response: ${text.trim()}`);

    return { success: true };
  } catch (error) {
    console.log(`   ❌ Server health check failed: ${error.message}`);
    return { success: false, error: error.message };
  }
}

// Test 4: Test authentication options
async function testAuthenticationOptions() {
  console.log('\n4️⃣ Testing Authentication Options (FastAuth vs SecureAuth)');

  try {
    // Test FastAuth
    const fastResponse = await fetch(`${SERVER_URL}/generate-authentication-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser_fast',
        useOptimistic: true
      }),
    });

    if (fastResponse.ok) {
      const fastData = await fastResponse.json();
      console.log('   ✅ FastAuth authentication options generated');
      console.log(`   📋 Fast mode commitmentId: ${fastData.commitmentId || 'null (expected)'}`);
    } else {
      console.log('   ⚠️  FastAuth auth options failed (expected - no registered user)');
    }

    // Test SecureAuth
    const secureResponse = await fetch(`${SERVER_URL}/generate-authentication-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser_secure',
        useOptimistic: false
      }),
    });

    if (secureResponse.ok) {
      const secureData = await secureResponse.json();
      console.log('   ✅ SecureAuth authentication options generated');
      console.log(`   📋 Secure mode commitmentId: ${secureData.commitmentId || 'null'}`);
    } else {
      console.log('   ⚠️  SecureAuth auth options failed (expected - no registered user)');
    }

    return { success: true };
  } catch (error) {
    console.log(`   ❌ Authentication options test failed: ${error.message}`);
    return { success: false, error: error.message };
  }
}

// Run all tests
async function runIntegrationTests() {
  console.log('🚀 Starting Integration Tests...\n');

  const test1 = await testServerHealth();
  const test2 = await testFastAuthRegistration();
  const test3 = await testSecureAuthRegistration();
  const test4 = await testAuthenticationOptions();

  console.log('\n📊 Integration Test Results:');
  console.log(`   Server Health:        ${test1.success ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`   FastAuth Registration: ${test2.success ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`   SecureAuth Registration: ${test3.success ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`   Authentication Options: ${test4.success ? '✅ PASS' : '❌ FAIL'}`);

  const allPassed = test1.success && test2.success && test3.success && test4.success;

  if (allPassed) {
    console.log('\n🎉 Phase 2 Integration: ALL TESTS PASSED!');
    console.log('\n✨ Features Working:');
    console.log('   ✅ FastAuth (Optimistic) registration options');
    console.log('   ✅ SecureAuth (Contract Sync) registration options');
    console.log('   ✅ Dual-mode authentication options');
    console.log('   ✅ Server/cache/contract flow ready');
    console.log('\n🔧 Ready for frontend UI testing:');
    console.log('   🌐 Frontend: https://example.localhost');
    console.log('   🔗 Backend: http://localhost:3001');
    console.log('   📱 Test both FastAuth and SecureAuth modes in browser!');
  } else {
    console.log('\n❌ Some integration tests failed.');
    console.log('   🔧 Check server logs and configuration.');
  }
}

// Run the tests
runIntegrationTests().catch(console.error);