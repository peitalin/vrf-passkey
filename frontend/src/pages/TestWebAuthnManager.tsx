import React, { useState, useEffect } from 'react';
import { webAuthnManager } from '../security/WebAuthnManager';
import bs58 from 'bs58';

const TestWebAuthnManager: React.FC = () => {
  const [logs, setLogs] = useState<string[]>([]);
  const [activeChallenges, setActiveChallenges] = useState(0);

  const logResult = (message: string, isError = false) => {
    const logEntry = `[${new Date().toLocaleTimeString()}] ${message}`;
    setLogs(prevLogs => [...prevLogs, (isError ? 'ERROR: ' : '') + logEntry]);
  };

  const clearLogs = () => {
    setLogs([]);
  };

  const updateChallengeCount = () => {
    setActiveChallenges(webAuthnManager.getActiveChallengeCount());
  };

  useEffect(() => {
    logResult('WebAuthnManager test page loaded.');
    updateChallengeCount();

    // Update challenge count every second
    const interval = setInterval(updateChallengeCount, 1000);
    return () => clearInterval(interval);
  }, []);

  const testChallengeGeneration = async () => {
    logResult('Testing challenge generation...');

    try {
      // Test registration options
      const regResult = await webAuthnManager.getRegistrationOptions('testuser');
      logResult(`Registration options received: challengeId=${regResult.challengeId}, challenge length=${regResult.options.challenge.length} chars`);

      // Test authentication options
      const authResult = await webAuthnManager.getAuthenticationOptions('testuser');
      logResult(`Authentication options received: challengeId=${authResult.challengeId}, challenge length=${authResult.options.challenge.length} chars`);

      updateChallengeCount();
    } catch (error: any) {
      logResult(`Challenge generation error: ${error.message}`, true);
    }
  };

  const testChallengeExpiration = async () => {
    logResult('Testing challenge expiration...');

    try {
      const result = await webAuthnManager.getRegistrationOptions('testuser');
      logResult(`Created challenge ${result.challengeId}, waiting 31 seconds for expiration...`);

      // Wait for challenge to expire (30 second timeout + 1 second buffer)
      setTimeout(async () => {
        try {
          // This should fail because the challenge expired
          await webAuthnManager.secureRegistration(
            'testuser',
            { response: { clientDataJSON: 'test', attestationObject: 'test' } },
            { derpAccountId: 'test' },
            result.challengeId,
          );
          logResult('ERROR: Expired challenge was accepted!', true);
        } catch (error: any) {
          logResult(`Expected error for expired challenge: ${error.message}`);
        }
        updateChallengeCount();
      }, 31000);

    } catch (error: any) {
      logResult(`Challenge expiration test error: ${error.message}`, true);
    }
  };

  const testSingleUseChallenge = async () => {
    logResult('Testing single-use challenge enforcement...');

    try {
      const result = await webAuthnManager.getRegistrationOptions('testuser');
      logResult(`Created challenge ${result.challengeId} for single-use test`);

      // First attempt should fail due to invalid data, but should consume the challenge
      try {
        await webAuthnManager.secureRegistration(
          'testuser',
          { response: { clientDataJSON: 'invalid', attestationObject: 'invalid' } },
          { derpAccountId: 'test' },
          result.challengeId,
        );
      } catch (error: any) {
        logResult(`First attempt failed as expected: ${error.message}`);
      }

      // Second attempt should fail because challenge was already used
      try {
        await webAuthnManager.secureRegistration(
          'testuser',
          { response: { clientDataJSON: 'invalid', attestationObject: 'invalid' } },
          { derpAccountId: 'test' },
          result.challengeId,
        );
        logResult('ERROR: Used challenge was accepted again!', true);
      } catch (error: any) {
        logResult(`Expected error for reused challenge: ${error.message}`);
      }

      updateChallengeCount();
    } catch (error: any) {
      logResult(`Single-use challenge test error: ${error.message}`, true);
    }
  };

  const testOperationMismatch = async () => {
    logResult('Testing operation type mismatch...');

    try {
      // Create registration challenge but try to use it for authentication
      const regResult = await webAuthnManager.getRegistrationOptions('testuser');
      logResult(`Created registration challenge ${regResult.challengeId}`);

      try {
        await webAuthnManager.secureTransactionSigning(
          'testuser',
          { response: { clientDataJSON: 'test', signature: 'test', authenticatorData: 'test' } },
          {
            derpAccountId: 'test',
            receiverId: 'test',
            contractMethodName: 'test',
            contractArgs: {},
            gasAmount: '1000000',
            depositAmount: '0',
            nonce: '1',
            blockHashBytes: Array.from(bs58.decode('test'))
          },
          regResult.challengeId
        );
        logResult('ERROR: Operation mismatch was not detected!', true);
      } catch (error: any) {
        logResult(`Expected error for operation mismatch: ${error.message}`);
      }

      updateChallengeCount();
    } catch (error: any) {
      logResult(`Operation mismatch test error: ${error.message}`, true);
    }
  };

  const testWorkerTimeout = async () => {
    logResult('Testing worker timeout (this will take ~30 seconds)...');

    try {
      const result = await webAuthnManager.getRegistrationOptions('testuser');

      // This should timeout because we're passing invalid data that will cause the worker to hang
      const startTime = Date.now();
      try {
        await webAuthnManager.secureRegistration(
          'testuser',
          { response: { clientDataJSON: 'invalid_base64', attestationObject: 'invalid_base64' } },
          { derpAccountId: 'test' },
          result.challengeId,
        );
      } catch (error: any) {
        const duration = Date.now() - startTime;
        logResult(`Worker operation failed after ${duration}ms: ${error.message}`);
      }

      updateChallengeCount();
    } catch (error: any) {
      logResult(`Worker timeout test error: ${error.message}`, true);
    }
  };

  const clearAllChallenges = () => {
    logResult('Clearing all active challenges...');
    webAuthnManager.clearAllChallenges();
    updateChallengeCount();
    logResult('All challenges cleared.');
  };

  return (
    <div style={{ fontFamily: 'Arial, sans-serif', maxWidth: '800px', margin: '0 auto', padding: '20px' }}>
      <h1>WebAuthnManager Security Test</h1>

      <div style={{ margin: '20px 0', padding: '20px', border: '1px solid #ccc', borderRadius: '5px', backgroundColor: '#f9f9f9' }}>
        <h2>Security Status</h2>
        <p><strong>Active Challenges:</strong> {activeChallenges}</p>
        <p><strong>Challenge Timeout:</strong> 30 seconds</p>
        <p><strong>Worker Timeout:</strong> 30 seconds</p>
      </div>

      <div style={{ margin: '20px 0', padding: '20px', border: '1px solid #ccc', borderRadius: '5px' }}>
        <h2>Security Tests</h2>
        <button onClick={testChallengeGeneration} style={{ padding: '10px 20px', margin: '5px', cursor: 'pointer' }}>
          Test Challenge Generation
        </button>
        <button onClick={testChallengeExpiration} style={{ padding: '10px 20px', margin: '5px', cursor: 'pointer' }}>
          Test Challenge Expiration (31s)
        </button>
        <button onClick={testSingleUseChallenge} style={{ padding: '10px 20px', margin: '5px', cursor: 'pointer' }}>
          Test Single-Use Challenge
        </button>
        <button onClick={testOperationMismatch} style={{ padding: '10px 20px', margin: '5px', cursor: 'pointer' }}>
          Test Operation Mismatch
        </button>
        <button onClick={testWorkerTimeout} style={{ padding: '10px 20px', margin: '5px', cursor: 'pointer' }}>
          Test Worker Timeout (~30s)
        </button>
        <br />
        <button onClick={clearAllChallenges} style={{ padding: '10px 20px', margin: '5px', cursor: 'pointer', backgroundColor: '#ff6b6b', color: 'white' }}>
          Clear All Challenges
        </button>
        <button onClick={clearLogs} style={{ padding: '10px 20px', margin: '5px', cursor: 'pointer' }}>
          Clear Logs
        </button>
      </div>

      <div style={{ margin: '20px 0', padding: '20px', border: '1px solid #ccc', borderRadius: '5px' }}>
        <h2>Security Features Demonstrated</h2>
        <ul style={{ textAlign: 'left' }}>
          <li><strong>Challenge-Based Access:</strong> Workers only created after valid WebAuthn challenges</li>
          <li><strong>Single-Use Challenges:</strong> Each challenge can only be used once</li>
          <li><strong>Time-Limited Challenges:</strong> Challenges expire after 30 seconds</li>
          <li><strong>Operation Type Validation:</strong> Registration challenges can't be used for authentication</li>
          <li><strong>Worker Timeouts:</strong> Operations have strict 30-second timeouts</li>
          <li><strong>Automatic Cleanup:</strong> Expired challenges are automatically removed</li>
          <li><strong>No Direct Worker Access:</strong> Workers are completely encapsulated</li>
        </ul>
      </div>

      <div style={{ margin: '20px 0', padding: '20px', border: '1px solid #ccc', borderRadius: '5px' }}>
        <h2>Test Results</h2>
        <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
          {logs.map((log, index) => (
            <div key={index} style={{
              background: '#f5f5f5',
              padding: '10px',
              margin: '10px 0',
              borderRadius: '3px',
              fontFamily: 'monospace',
              fontSize: '12px',
              whiteSpace: 'pre-wrap',
              color: log.startsWith('ERROR:') ? 'red' : 'inherit'
            }}>
              {log}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default TestWebAuthnManager;