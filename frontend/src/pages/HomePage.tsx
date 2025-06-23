import { PasskeyLoginMenu } from '../components/PasskeyLoginMenu';
import { GreetingMenu } from '../components/GreetingMenu';
import { usePasskeyContext } from '@web3authn/passkey/react';

export function HomePage() {

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
        <GreetingMenu />
      ) : (
        <PasskeyLoginMenu />
      )}
    </main>
  );
}