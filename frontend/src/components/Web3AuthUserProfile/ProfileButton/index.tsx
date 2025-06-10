import React from 'react';
import toast from 'react-hot-toast';
import { usePasskeyContext } from '../../../contexts/PasskeyContext';
import { MUTED_GREEN, WEBAUTHN_CONTRACT_ID } from '../../../config';
import { AccountIcon } from '../../icons/AccountIcon';
import { PaymentMethodsIcon } from '../../icons/PaymentMethodsIcon';
import { ProfileTrigger } from './ProfileTrigger';
import { ProfileDropdown } from './ProfileDropdown';
import { useProfileState } from '../hooks/useProfileState';
import { useProfileDimensions } from '../hooks/useProfileDimensions';
import { useProfileAnimations } from '../hooks/useProfileAnimations';
import type { ProfileMenuItem, ProfileCalculationParams } from '../types';
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

// Menu items configuration
const MENU_ITEMS: ProfileMenuItem[] = [
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

export const ProfileButton: React.FC = () => {
  const {
    username,
    nearAccountId,
    logoutPasskey,
    optimisticAuth,
    setOptimisticAuth
  } = usePasskeyContext();

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
    logoutPasskey();
    toast.success('Logged out successfully!', {
      style: { background: MUTED_GREEN, color: 'white' }
    });
    handleClose();
  };

  // Don't render until username is loaded to avoid width measurement issues
  if (!username) {
    return null;
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
          onOptimisticAuthChange={setOptimisticAuth}
          onLogout={handleLogout}
          onClose={handleClose}
          menuItemsRef={refs.menuItemsRef}
        />
      </div>
    </div>
  );
};