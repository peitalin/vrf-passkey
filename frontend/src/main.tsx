import React from 'react';
import ReactDOM from 'react-dom/client';
import { HomePage } from './pages/HomePage';
import './index.css';

// Removed BitteWalletContextProvider and related imports
// Removed @near-wallet-selector/modal-ui styles import as the modal is no longer used

// Define global for Node.js libraries that expect it (if not already handled by Vite config)
// This might still be needed for near-api-js or its dependencies
if (typeof (window as any).global === 'undefined') {
  (window as any).global = window;
}


ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <main>
      <HomePage />
    </main>
  </React.StrictMode>,
)
