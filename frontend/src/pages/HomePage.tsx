import { PasskeyLogin } from '../components/PasskeyLogin';
import { Toaster } from 'react-hot-toast';

export function HomePage() {
  return (
    <main>
      <Toaster />
      <PasskeyLogin />
    </main>
  );
}