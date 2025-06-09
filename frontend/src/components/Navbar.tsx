import React from 'react';
import { Link } from 'react-router-dom';
import { usePasskeyContext } from '../contexts/PasskeyContext';
import toast from 'react-hot-toast';
import { MUTED_GREEN } from '../config';

const shortPK = (pk: string | null | undefined) => {
  if (!pk) return '';

  // Remove the "ed25519:" prefix if present
  const keyPart = pk.includes(':') ? pk.substring(pk.indexOf(':') + 1) : pk;

  if (keyPart.length <= 11) return keyPart; // 4 + 3 ("...") + 4 = 11
  return `${keyPart.substring(0, 4)}...${keyPart.substring(keyPart.length - 4)}`;
};

export const Navbar: React.FC = () => {
  const { isLoggedIn, username, nearPublicKey, logoutPasskey } = usePasskeyContext();

  const handleLogout = () => {
    logoutPasskey();
    toast.success('Logged out successfully!', {
      style: { background: MUTED_GREEN, color: 'white' }
    });
  };

  return (
    <nav className="navbar-container">
      <div className="navbar-title">
        <Link to="/" style={{ textDecoration: 'none', color: 'inherit' }}>
          Passkey NEAR App
        </Link>
      </div>

      <div className="navbar-links" style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
        <Link to="/" style={{ textDecoration: 'none', color: '#666', fontSize: '14px' }}>
          Home
        </Link>
        <Link to="/test-onetime-worker" style={{ textDecoration: 'none', color: '#666', fontSize: '14px' }}>
          Worker Test
        </Link>
      </div>

      {isLoggedIn && (
        <div className="navbar-user-info">
          {username && <span>Welcome, {username}</span>}
          {nearPublicKey && (
            <span className="navbar-pk" title={nearPublicKey}>
              ({shortPK(nearPublicKey)})
            </span>
          )}
          <button
            onClick={handleLogout} // Use the new handler
            className="navbar-logout-button"
          >
            Logout
          </button>
        </div>
      )}
    </nav>
  );
};