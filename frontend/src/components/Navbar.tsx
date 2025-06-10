import React from 'react';
import { Link } from 'react-router-dom';
import { usePasskeyContext } from '../contexts/PasskeyContext';
import { ProfileButton } from './Web3AuthUserProfile/ProfileButton';

export const Navbar: React.FC = () => {
  const { isLoggedIn } = usePasskeyContext();

  return (
    <nav className="navbar-container">
      <div className="navbar-title">
        <Link to="/" style={{ textDecoration: 'none', color: 'inherit' }}>
          Web3Authn Passkeys
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

      {isLoggedIn && <ProfileButton />}
    </nav>
  );
};