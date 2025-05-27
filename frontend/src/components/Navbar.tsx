import React from 'react';
import { usePasskeyContext } from '../contexts/PasskeyContext'; // Import the context hook
import toast from 'react-hot-toast'; // Import toast

// NavbarProps interface can be removed if no props are passed directly anymore
// interface NavbarProps {
//   username?: string | null;
//   serverDerivedNearPK?: string | null;
//   isLoggedIn: boolean;
//   onLogout: () => void;
// }

const shortPK = (pk: string | null | undefined, len = 8) => {
  if (!pk) return '';
  if (pk.length <= len * 2 + 3) return pk;
  return `${pk.substring(0, pk.indexOf(':') + 1 + len)}...${pk.substring(pk.length - len)}`;
};

export const Navbar: React.FC = () => { // No direct props needed
  const { isLoggedIn, username, serverDerivedNearPK, logoutPasskey } = usePasskeyContext();

  const handleLogout = () => {
    logoutPasskey(); // Call context logout function
    toast.success('Logged out successfully!', {
      style: { background: '#2196F3', color: 'white' }
    });
  };

  return (
    <nav className="navbar-container">
      <div className="navbar-title">Passkey NEAR App</div>
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