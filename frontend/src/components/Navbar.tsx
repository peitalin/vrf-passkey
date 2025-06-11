import React from 'react';
import { Link } from 'react-router-dom';
import {
  usePasskeyContext,
  ProfileButton
} from '@web3authn/passkey/react';
import { useWeb3AuthnEventListener } from '../hooks/useWeb3AuthnEventListener';

export const Navbar: React.FC = () => {

  const { isLoggedIn } = usePasskeyContext();
  useWeb3AuthnEventListener();

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
      </div>

      <ProfileButton />
    </nav>
  );
};