import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { HomePage } from './pages/HomePage';
import { Navbar } from './components/Navbar';
import { PasskeyProvider } from '@web3authn/passkey/react';
import { Toaster } from 'react-hot-toast';

import './index.css';
import '@web3authn/passkey/react/styles';

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
          </Routes>
        </PasskeyProvider>
      </BrowserRouter>
    </React.StrictMode>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(<App />);
