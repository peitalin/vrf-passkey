import React from 'react';
import { Link } from 'react-router-dom';
import { usePasskeyContext } from '../contexts/PasskeyContext';
import toast from 'react-hot-toast';


const shortPK = (pk: string | null | undefined, len = 8) => {
  if (!pk) return '';
  if (pk.length <= len * 2 + 3) return pk;
  return `${pk.substring(0, pk.indexOf(':') + 1 + len)}...${pk.substring(pk.length - len)}`;
};

export const Navbar: React.FC = () => {
  const { isLoggedIn, username, serverDerivedNearPK, logoutPasskey } = usePasskeyContext();

  const handleLogout = () => {
    logoutPasskey();
    toast.success('Logged out successfully!', {
      style: { background: '#2196F3', color: 'white' }
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
        <Link to="/test-webauthn-manager" style={{ textDecoration: 'none', color: '#666', fontSize: '14px' }}>
          Security Test
        </Link>
        <Link to="/test-near-account" style={{ textDecoration: 'none', color: '#666', fontSize: '14px' }}>
          NEAR Account Test
        </Link>
      </div>

      {isLoggedIn && (
        <div className="navbar-user-info">
          {username && <span>Welcome, {username}</span>}
          {serverDerivedNearPK && (
            <span className="navbar-pk" title={serverDerivedNearPK}>
              ({shortPK(serverDerivedNearPK)})
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