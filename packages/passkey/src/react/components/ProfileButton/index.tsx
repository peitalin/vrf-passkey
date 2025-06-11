import React from 'react';
import { KeyIcon } from '../icons/KeyIcon';
import { PaymentMethodsIcon } from '../icons/PaymentMethodsIcon';
import { ProfileTrigger } from './ProfileTrigger';
import { ProfileDropdown } from './ProfileDropdown';
import { useProfileState } from './hooks/useProfileState';
import { useProfileDimensions } from './hooks/useProfileDimensions';
import { useProfileAnimations } from './hooks/useProfileAnimations';
import { usePasskeyContext } from '../../context';
import type { ProfileMenuItem, ProfileCalculationParams } from './types';
import '../Web3authUserProfile.css';

// Configuration constants
const MENU_CONFIG = {
  numMenuItems: 2,
  profileButtonHeight: 72,
  menuItemHeight: 52,
  toggleSectionHeight: 82,
  logoutSectionHeight: 46,
  bottomBuffer: 4,
} as const;

export interface ProfileButtonProps {
  username?: string | null;
  nearAccountId?: string | null;
  optimisticAuth?: boolean;
  onLogout?: () => void;
  onOptimisticAuthChange?: (value: boolean) => void;
}

export const ProfileButton: React.FC<ProfileButtonProps> = ({
  username: usernameProp,
  nearAccountId: nearAccountIdProp,
  optimisticAuth: optimisticAuthProp,
  onLogout: onLogoutProp,
  onOptimisticAuthChange: onOptimisticAuthChangeProp,
}) => {
  // Get values from context if not provided as props
  const {
    username: contextUsername,
    nearAccountId: contextNearAccountId,
    optimisticAuth: contextOptimisticAuth,
    logoutPasskey,
    setOptimisticAuth,
    exportKeyPair
  } = usePasskeyContext();

  // Use props if provided, otherwise fall back to context
  const username = usernameProp || contextUsername;
  const nearAccountId = nearAccountIdProp || contextNearAccountId;
  const optimisticAuth = optimisticAuthProp !== undefined ? optimisticAuthProp : contextOptimisticAuth;
  const onLogout = onLogoutProp || logoutPasskey;
  const onOptimisticAuthChange = onOptimisticAuthChangeProp || setOptimisticAuth;

  // Menu items configuration with context-aware handlers
  const MENU_ITEMS: ProfileMenuItem[] = [
    {
      icon: <KeyIcon />,
      label: 'Export Keys',
      description: 'Export your NEAR private keys',
      disabled: false,
      onClick: exportKeyPair
    },
    {
      icon: <PaymentMethodsIcon />,
      label: 'Payments',
      description: 'Manage payment methods',
      disabled: true
    },
  ];

  // State management
  const {
    isOpen,
    refs,
    handleToggle,
    handleClose,
  } = useProfileState();

  // Dimension calculations
  const calculationParams: ProfileCalculationParams = {
    username: username || 'User',
    ...MENU_CONFIG,
  };

  const { closedDimensions, openDimensions } = useProfileDimensions(calculationParams);

  // Animations
  useProfileAnimations({
    isOpen,
    refs,
    openDimensions,
    closedDimensions,
  });

  // Handlers
  const handleLogout = () => {
    onLogout?.();
    handleClose();
  };

  const handleOptimisticAuthChange = (value: boolean) => {
    onOptimisticAuthChange?.(value);
  };

  // Show a minimal version if no username is available
  if (!username) {
    return (
      <div className="web3authn-profile-button-container">
        <div className="web3authn-profile-button-placeholder">
          <span style={{ fontSize: '12px', color: '#666' }}>Not logged in</span>
        </div>
      </div>
    );
  }

  return (
    <div className="web3authn-profile-button-container">
      <div
        ref={refs.buttonRef}
        className={`web3authn-profile-button-morphable ${isOpen ? 'open' : 'closed'}`}
      >
        <ProfileTrigger
          username={username}
          isOpen={isOpen}
          onClick={handleToggle}
        />

        {/* Visible menu structure for actual interaction */}
        <ProfileDropdown
          ref={refs.dropdownRef}
          isOpen={isOpen}
          menuItems={MENU_ITEMS}
          optimisticAuth={optimisticAuth}
          onOptimisticAuthChange={handleOptimisticAuthChange}
          onLogout={handleLogout}
          onClose={handleClose}
          menuItemsRef={refs.menuItemsRef}
        />
      </div>
    </div>
  );
};