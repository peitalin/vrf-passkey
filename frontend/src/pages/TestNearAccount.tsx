import React, { useState } from 'react';
import { SERVER_URL } from '../config';

interface CreateAccountResult {
  success: boolean;
  message?: string;
  accountId?: string; // For top-level response structure if API directly returns this
  publicKey?: string; // For top-level response structure
  result?: { // For the nested result from nearClient
    accountId: string;
    publicKey: string;
  };
  error?: string;
  details?: any; // For detailed errors
}

const TestNearAccount: React.FC = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<CreateAccountResult | null>(null);

  const testCreateAccount = async () => {
    setIsLoading(true);
    setResult(null);
    const testAccountId = `test-${Date.now()}.cyan-loong.testnet`;
    // Using a valid, unique public key for testing is important if the key itself is registered or checked.
    // For basic account creation, a correctly formatted key is usually sufficient.
    // This example public key is for illustration. Replace if a specific key is needed for your test setup.
    const testPublicKey = 'ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJTXQYsjXcD4M';

    console.log('Testing NEAR account creation...');
    console.log('Account ID:', testAccountId);
    console.log('Public Key:', testPublicKey);

    try {
      const response = await fetch(`${SERVER_URL}/api/create-account`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          accountId: testAccountId,
          publicKey: testPublicKey,
          // isTestnet: true, // This field is no longer used by the updated backend endpoint
        })
      });
      const data: CreateAccountResult = await response.json();
      console.log('Creation result data:', data);
      setResult(data);
    } catch (error: any) {
      console.error('Error during fetch operation:', error);
      setResult({ success: false, error: error.message || 'Fetch operation failed.' });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ padding: '20px', maxWidth: '800px', margin: '0 auto' }}>
      <h1>Test NEAR Account Creation</h1>

      <div style={{ marginBottom: '20px' }}>
        <p>This page tests the NEAR account creation functionality.</p>
        <p>It will attempt to create a new testnet account with a unique ID using the relayer.</p>
      </div>

      <div style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
        <button
          onClick={testCreateAccount}
          disabled={isLoading}
          style={{
            padding: '10px 20px',
            fontSize: '16px',
            cursor: isLoading ? 'not-allowed' : 'pointer',
            opacity: isLoading ? 0.6 : 1
          }}
        >
          {isLoading ? 'Creating Account...' : 'Test Account Creation'}
        </button>

      </div>

      {result && (
        <div style={{
          marginTop: '20px',
          padding: '20px',
          border: '1px solid #ccc',
          borderRadius: '5px',
          backgroundColor: result.success ? '#e8f5e9' : '#ffebee'
        }}>
          <h3>{result.success ? 'Success!' : 'Failed'}</h3>
          {result.success && result.result ? (
            <>
              <p><strong>Account ID:</strong> {result.result.accountId}</p>
              <p><strong>Public Key:</strong> {result.result.publicKey}</p>
              <p><strong>Message:</strong> {result.message}</p>
              <p>
                <strong>View on Explorer:</strong>{' '}
                <a
                  href={`https://testnet.nearblocks.io/address/${result.result.accountId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: '#1976d2' }}
                >
                  {result.result.accountId}
                </a>
              </p>
            </>
          ) : (
            <>
              <p><strong>Error:</strong> {result.error || 'An unknown error occurred.'}</p>
              {result.details && <pre>{JSON.stringify(result.details, null, 2)}</pre>}
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default TestNearAccount;