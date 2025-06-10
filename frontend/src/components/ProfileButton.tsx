import React, { useState, useRef, useEffect } from 'react';
import { usePasskeyContext } from '../contexts/PasskeyContext';
import toast from 'react-hot-toast';
import { MUTED_GREEN, NEAR_EXPLORER_BASE_URL, WEBAUTHN_CONTRACT_ID } from '../config';
import { AccountIcon } from './icons/AccountIcon';
import { PaymentMethodsIcon } from './icons/PaymentMethodsIcon';
import { Toggle } from './Toggle';
import clsx from 'clsx';
import { animate } from 'animejs';
import { AvatarIcon } from './icons/AvatarIcon';
import { UserDetails } from './icons/UserDetails';

const ProfileButton = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLDivElement>(null);
  const hiddenMenuRef = useRef<HTMLDivElement>(null);
  const menuItemsRef = useRef<(HTMLElement | null)[]>([]);

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
        !buttonRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Animation effect for menu opening/closing
  useEffect(() => {
    if (!buttonRef.current || !dropdownRef.current || !hiddenMenuRef.current) return;

    if (isOpen) {
      // Wait a frame to ensure measurements are accurate
      requestAnimationFrame(() => {
        if (!buttonRef.current || !hiddenMenuRef.current) return;

        // Fixed open dimensions using established formula
        const currentWidth = buttonRef.current.offsetWidth;
        const currentHeight = buttonRef.current.offsetHeight;
        const targetWidth = 300; // Fixed dropdown width

        // Calculate target height using established formula
        const numMenuItems = 2; // Account and Payments items
        const profileButtonHeight = 72
        const menuItemHeight = 52; // profile-dropdown-menu-item height each
        const toggleSectionHeight = 82; // profile-dropdown-toggle-section height
        const logoutSectionHeight = 46; // logout section height
        const bottomBuffer = 4;
        const targetHeight = profileButtonHeight
          + (numMenuItems * menuItemHeight)
          + toggleSectionHeight
          + logoutSectionHeight
          + bottomBuffer;
        console.log('targetHeight', targetHeight);

        // Animate container expansion smoothly without bounce
        animate(buttonRef.current, {
          width: [currentWidth, targetWidth],
          height: [currentHeight, targetHeight],
          duration: 250,
          ease: 'outQuart'
        });

        // Show dropdown content after container starts expanding
        animate(dropdownRef.current, {
          opacity: [0, 1],
          visibility: 'visible',
          duration: 100,
          delay: 0
        });

        // Staggered animation for menu items
        const menuItems = menuItemsRef.current.filter(item => item !== null);
        if (menuItems.length > 0) {
          menuItems.forEach((item, index) => {
            if (item) {
              // Reset initial state
              animate(item, {
                opacity: 0,
                translateY: 20,
                duration: 0
              });

              // Staggered slide-in animation
              animate(item, {
                opacity: [0, 1],
                translateY: [20, 0],
                duration: 200,
                delay: 120 + (index * 40),
                ease: 'outCubic'
              });
            }
          });
        }
      });
    } else {
            // Animate menu items out first
      const menuItems = menuItemsRef.current.filter(item => item !== null);
      if (menuItems.length > 0) {
        menuItems.forEach((item, index) => {
          if (item) {
            animate(item, {
              opacity: 0,
              translateY: -10,
              duration: 100,
              delay: index * 15,
              ease: 'inQuad'
            });
          }
        });
      }

      // Hide dropdown content
      animate(dropdownRef.current, {
        opacity: 0,
        visibility: 'hidden',
        duration: 100
      });

      // Get dimensions for closing animation
      const currentWidth = buttonRef.current.offsetWidth;
      const currentHeight = buttonRef.current.offsetHeight;

      // Calculate closed width based on username length
      const usernameText = username || 'User';
      const closedWidth = 24 + (usernameText.length * 8) + 32; // 24px base + 6px per character + 2rem (32px)
      const closedHeight = 40; // Fixed height for trigger (24px avatar + 16px padding)

      // Animate container back to closed size
      animate(buttonRef.current, {
        width: [currentWidth, closedWidth],
        height: [currentHeight, closedHeight],
        duration: 200,
        delay: 60,
        ease: 'inOutCubic'
      });
    }
  }, [isOpen]);

  const handleToggle = () => {
    setIsOpen(!isOpen);
  };

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

  // Don't render until username is loaded to avoid width measurement issues
  if (!username) {
    return null;
  }

  return (
    <div className="profile-button-container">
      <div
        ref={buttonRef}
        onClick={handleToggle}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        className={`profile-button-morphable ${isOpen ? 'open' : 'closed'}`}
      >
        <div className="profile-button-trigger-wrapper">
          <div className={`profile-button-trigger ${isOpen ? 'open' : 'closed'}`}>
            <div className="profile-dropdown-user-content">
              <AvatarIcon isOpen={isOpen} />
              <UserDetails username={username} isOpen={isOpen} />
            </div>
          </div>
        </div>

        {/* Hidden menu structure for width calculation - always present */}
        <div ref={hiddenMenuRef} className="profile-dropdown-hidden">
          <div className="profile-dropdown-menu">
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
            {menuItems.map((item, index) => (
              <div key={`hidden-${index}`} className="profile-dropdown-menu-item">
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
              </div>
            ))}
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
                <div style={{ width: '44px', height: '24px' }} /> {/* Toggle placeholder */}
              </div>
            </div>
            <div className="profile-dropdown-logout-section">
              <div className="profile-dropdown-logout-button">
                <svg width="16" height="16" viewBox="0 0 16 16" className="profile-dropdown-logout-icon">
                  <path d="M3 3a1 1 0 0 1 1-1h8a1 1 0 0 1 1 1v2a.5.5 0 0 1-1 0V3H4v10h8v-2a.5.5 0 0 1 1 0v2a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V3Z" fill="currentColor"/>
                  <path d="M11.854 8.854a.5.5 0 0 0 0-.708l-3-3a.5.5 0 1 0-.708.708L10.293 8H1.5a.5.5 0 0 0 0 1h8.793l-2.147 2.146a.5.5 0 0 0 .708.708l3-3Z" fill="currentColor"/>
                </svg>
                <span className="profile-dropdown-logout-text">
                  Log out
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Visible menu structure for actual interaction */}
        <div
          ref={dropdownRef}
          className={`profile-dropdown-morphed ${isOpen ? 'visible' : 'hidden'}`}
        >
          <div className="profile-dropdown-menu">
            {menuItems.map((item, index) => (
              <button
                key={index}
                ref={(el) => { menuItemsRef.current[index + 1] = el; }}
                disabled={item.disabled}
                className={`profile-dropdown-menu-item ${item.disabled ? 'disabled' : ''}`}
                onClick={(e) => {
                  e.stopPropagation();
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
            <div
              ref={(el) => { menuItemsRef.current[menuItems.length + 1] = el; }}
              className="profile-dropdown-toggle-section"
              onClick={(e) => e.stopPropagation()}
            >
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

            {/* Logout Section */}
            <div ref={(el) => { menuItemsRef.current[menuItems.length + 2] = el; }}>
              <LogoutButton handleLogout={handleLogout} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const LogoutButton = ({
  handleLogout,
  className
}: {
  handleLogout: () => void;
  className?: string;
}) => {
  return (
    <div className={clsx("profile-dropdown-logout-section", className)}>
      <button
        className="profile-dropdown-logout-button"
        onClick={(e) => {
          e.stopPropagation();
          handleLogout();
        }}
      >
        <svg width="16" height="16" viewBox="0 0 16 16" className="profile-dropdown-logout-icon">
          <path d="M3 3a1 1 0 0 1 1-1h8a1 1 0 0 1 1 1v2a.5.5 0 0 1-1 0V3H4v10h8v-2a.5.5 0 0 1 1 0v2a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V3Z" fill="currentColor"/>
          <path d="M11.854 8.854a.5.5 0 0 0 0-.708l-3-3a.5.5 0 1 0-.708.708L10.293 8H1.5a.5.5 0 0 0 0 1h8.793l-2.147 2.146a.5.5 0 0 0 .708.708l3-3Z" fill="currentColor"/>
        </svg>
        <span className="profile-dropdown-logout-text">
          Log out
        </span>
      </button>
    </div>
  );
};

export default ProfileButton;
