import { WagmiProvider } from 'wagmi'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { config } from './wagmi'
import { PasskeyLogin } from './components/PasskeyLogin'
import './App.css'

const queryClient = new QueryClient()

function App() {
  return (
    <WagmiProvider config={config}>
      <QueryClientProvider client={queryClient}>
        <div className="app-container">
          <header>
            <h1>My Porto Passkey App</h1>
            <p className="app-description">
              This application demonstrates how to integrate passkey-based login
              for Ethereum accounts using Porto and Wagmi.
            </p>
          </header>
          <main>
            <div className="passkey-login-container">
              <PasskeyLogin />
            </div>
          </main>
          <footer>
            <p>Powered by Porto & Wagmi</p>
          </footer>
        </div>
      </QueryClientProvider>
    </WagmiProvider>
  )
}

export default App
