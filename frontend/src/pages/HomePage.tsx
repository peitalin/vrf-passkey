import { PasskeyLogin } from '../components/PasskeyLogin';

export function HomePage() {
  return (
    <div>
      <h2>Passkey WebAuthn</h2>
      <p>Welcome to the Passkey demo.</p>
      <PasskeyLogin />
    </div>
  );
}