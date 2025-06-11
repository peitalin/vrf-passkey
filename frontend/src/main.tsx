import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import { HomePage } from './pages/HomePage';
import TestOnetimeWorker from './pages/TestOnetimeWorker';
import { Navbar } from './components/Navbar';
import { PasskeyProvider } from '@web3authn/passkey/react';
import './index.css';
import { Toaster } from 'react-hot-toast';

import '@web3authn/passkey/react/styles';

// Define global for Node.js libraries that expect it (if not already handled by Vite config)
// This might still be needed for near-api-js or its dependencies
if (typeof (window as any).global === 'undefined') {
  (window as any).global = window;
}

// Simple App component to manage layout and potentially shared state later
function App() {
  return (
    <React.StrictMode>
      <BrowserRouter>
        <PasskeyProvider>
          <Toaster
            position="bottom-center"
            reverseOrder={false}
            toastOptions={{
              duration: 5000, // Default longer duration
            }}
            containerStyle={{
              bottom: 40,
            }}
            gutter={8}
            containerClassName=""
          />
          <Navbar />
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/test-onetime-worker" element={<TestOnetimeWorker />} />
          </Routes>
        </PasskeyProvider>
      </BrowserRouter>
    </React.StrictMode>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(<App />);
