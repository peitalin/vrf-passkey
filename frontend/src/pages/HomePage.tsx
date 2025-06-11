// import { PasskeyLogin } from '../components/PasskeyLogin';
import { PasskeyLogin } from '@web3authn/passkey/react';


export function HomePage(/*{ onLogin, onLogout }: HomePageProps*/) {
  return (
    <main>
      <PasskeyLogin />
    </main>
  );
}