import { PasskeyLogin } from '../components/PasskeyLogin';


export function HomePage(/*{ onLogin, onLogout }: HomePageProps*/) {
  return (
    <main>
      <h2>Passkey WebAuthn</h2>
      <p>Welcome to the Passkey demo.</p>
      <PasskeyLogin />
    </main>
  );
}