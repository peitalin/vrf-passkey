import React, { useState, useRef, useEffect } from 'react';
import { usePasskeyContext } from '../contexts/PasskeyContext';
import toast from 'react-hot-toast';
import { MUTED_GREEN, NEAR_EXPLORER_BASE_URL, WEBAUTHN_CONTRACT_ID } from '../config';
import { AccountIcon } from './icons/AccountIcon';
import { PaymentMethodsIcon } from './icons/PaymentMethodsIcon';
import { Toggle } from './Toggle';

const ProfileButton = () => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  const {
    username,
    nearAccountId,
    logoutPasskey,
    optimisticAuth,
    setOptimisticAuth
  } = usePasskeyContext();

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        buttonRef.current &&
        !dropdownRef.current.contains(event.target as Node) &&
        !buttonRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLogout = () => {
    logoutPasskey();
    toast.success('Logged out successfully!', {
      style: { background: MUTED_GREEN, color: 'white' }
    });
    setIsOpen(false);
  };

  const menuItems = [
    {
      icon: <AccountIcon />,
      label: 'Account',
      description: 'Privacy and sharing',
      disabled: true
    },
    {
      icon: <PaymentMethodsIcon />,
      label: 'Payments',
      description: 'Manage payment methods',
      disabled: true
    },
  ];

  return (
    <div className="profile-button-root">
      <button
        ref={buttonRef}
        onClick={() => setIsOpen(!isOpen)}
        className={`profile-button ${isOpen ? 'open' : ''}`}
      >
        <svg width="18" height="18" viewBox="0 0 18 18" className="profile-button-icon">
          <rect x="2" y="4" width="14" height="2" rx="1" fill="currentColor"/>
          <rect x="2" y="8" width="14" height="2" rx="1" fill="currentColor"/>
          <rect x="2" y="12" width="14" height="2" rx="1" fill="currentColor"/>
        </svg>
        <span className={`profile-button-username ${!username ? 'hidden' : ''}`}>
          {username || 'User'}
        </span>
      </button>

      {isOpen && (
        <div ref={dropdownRef} className="profile-dropdown">
          {/* User Info Section */}
          <div className="profile-dropdown-user-info">
            <div className="profile-dropdown-user-content">
              <div className="profile-dropdown-avatar">
                <svg width="18" height="18" viewBox="0 0 16 16" className="profile-dropdown-avatar-icon">
                  <path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM6 10.5a5 5 0 0 0-5 5 1.5 1.5 0 0 0 1.5 1.5h11a1.5 1.5 0 0 0 1.5-1.5 5 5 0 0 0-5-5H6Z" fill="currentColor"/>
                </svg>
              </div>
              <div className="profile-dropdown-user-details">
                <p className="profile-dropdown-username">
                  {username || 'User'}
                </p>
                <p className="profile-dropdown-account-id">
                  {username ? `${username}.${WEBAUTHN_CONTRACT_ID}` : 'user@example.com'}
                </p>
              </div>
            </div>
          </div>

          {/* Menu Items */}
          <div className="profile-dropdown-menu">
            {menuItems.map((item, index) => (
              <button
                key={index}
                disabled={item.disabled}
                className={`profile-dropdown-menu-item ${item.disabled ? 'disabled' : ''}`}
                onClick={() => {
                  if (!item.disabled) {
                    console.log(`Clicked: ${item.label}`);
                    setIsOpen(false);
                  }
                }}
              >
                <div className="profile-dropdown-menu-item-icon">
                  {item.icon}
                </div>
                <div className="profile-dropdown-menu-item-content">
                  <p className="profile-dropdown-menu-item-label">
                    {item.label}
                  </p>
                  <p className="profile-dropdown-menu-item-description">
                    {item.description}
                  </p>
                </div>
              </button>
            ))}

            {/* FastAuth Toggle */}
            <div className="profile-dropdown-toggle-section">
              <div className="profile-dropdown-toggle-content">
                <div className="profile-dropdown-toggle-text">
                  <p className="profile-dropdown-toggle-title">
                    {optimisticAuth ? 'Fast Signing' : 'Contract Signing'}
                  </p>
                  <p className="profile-dropdown-toggle-description">
                    {optimisticAuth
                        ? 'Fast transaction signing with optimistic responses'
                        : 'Contract signed Passkey authentication (slower)'
                    }
                  </p>
                </div>
                <Toggle
                  checked={optimisticAuth}
                  onChange={setOptimisticAuth}
                  showTooltip={false}
                  size="large"
                  textPosition='left'
                />
              </div>
            </div>
          </div>

          {/* Logout Section */}
          <div className="profile-dropdown-logout-section">
            <button className="profile-dropdown-logout-button" onClick={handleLogout}>
              <svg width="16" height="16" viewBox="0 0 16 16" className="profile-dropdown-logout-icon">
                <path d="M3 3a1 1 0 0 1 1-1h8a1 1 0 0 1 1 1v2a.5.5 0 0 1-1 0V3H4v10h8v-2a.5.5 0 0 1 1 0v2a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V3Z" fill="currentColor"/>
                <path d="M11.854 8.854a.5.5 0 0 0 0-.708l-3-3a.5.5 0 1 0-.708.708L10.293 8H1.5a.5.5 0 0 0 0 1h8.793l-2.147 2.146a.5.5 0 0 0 .708.708l3-3Z" fill="currentColor"/>
              </svg>
              <span className="profile-dropdown-logout-text">
                Log out
              </span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ProfileButton;
