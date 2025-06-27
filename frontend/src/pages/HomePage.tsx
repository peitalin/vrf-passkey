import React, { useState } from 'react';
import { PasskeyLoginMenu } from '../components/PasskeyLoginMenu';
import { GreetingMenu } from '../components/GreetingMenu';
import { TransactionDetails } from '../components/TransactionDetails';
import { usePasskeyContext } from '@web3authn/passkey/react';
import type { LastTxDetails } from '../types';

export function HomePage() {
  const [lastTxDetails, setLastTxDetails] = useState<LastTxDetails | null>(null);

  const {
    loginState: {
      isLoggedIn,
      nearPublicKey,
      nearAccountId
    },
  } = usePasskeyContext();

  return (
    <main>
      {isLoggedIn ? (
        <div className="homepage-content">
          <GreetingMenu onTransactionUpdate={setLastTxDetails} />
          <TransactionDetails lastTxDetails={lastTxDetails} />
        </div>
      ) : (
        <PasskeyLoginMenu />
      )}
    </main>
  );
}