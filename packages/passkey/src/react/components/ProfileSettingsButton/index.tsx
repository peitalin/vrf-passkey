import React from 'react';
import { KeyIcon } from '../icons/KeyIcon';
import { PaymentMethodsIcon } from '../icons/PaymentMethodsIcon';
import { ProfileTrigger } from './ProfileTrigger';
import { ProfileDropdown } from './ProfileDropdown';
import { useProfileState } from './hooks/useProfileState';
import { useProfileDimensions } from './hooks/useProfileDimensions';
import { useProfileAnimations } from './hooks/useProfileAnimations';
import { usePasskeyContext } from '../../context';
import type { ProfileMenuItem, ProfileCalculationParams, ToggleColorProps } from './types';
import './Web3AuthProfileButton.css';

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
  onLogout?: () => void;
  toggleColors?: ToggleColorProps;
}

export const ProfileButton: React.FC<ProfileButtonProps> = ({
  username: usernameProp,
  nearAccountId: nearAccountIdProp,
  onLogout: onLogoutProp,
  toggleColors,
}) => {
  // Get values from context if not provided as props
  const {
    loginState,
    passkeyManager,
    logout,
    useRelayer,
    setUseRelayer,
  } = usePasskeyContext();

  // Use props if provided, otherwise fall back to context
  const accountName = nearAccountIdProp?.split('.')?.[0] || 'User';
  const nearAccountId = nearAccountIdProp || loginState.nearAccountId;
  const onLogout = onLogoutProp || logout;

  // Menu items configuration with context-aware handlers
  const MENU_ITEMS: ProfileMenuItem[] = [
    {
      icon: <KeyIcon />,
      label: 'Export Keys',
      description: 'Export your NEAR private keys',
      disabled: false,
      onClick: async () => {
        try {
          const {
            userAccountId,
            privateKey,
            publicKey
          } = await passkeyManager.exportKeyPair(nearAccountId!);

          // Small delay to allow document to regain focus after WebAuthn
          await new Promise(resolve => setTimeout(resolve, 150));

          const keypair_msg = `Account ID:\n${userAccountId}\n\nPublic key:\n${publicKey}\n\nPrivate key:\n${privateKey}`;

          // Simple clipboard approach with single fallback
          if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(keypair_msg);
            alert(`NEAR keys copied to clipboard!\n${keypair_msg}`);
          } else {
            // Simple fallback: show keys for manual copy
            alert(`Your NEAR Keys (copy manually):\n${keypair_msg}`);
          }
        } catch (error: any) {
          console.error('Key export failed:', error);
          alert(`Key export failed: ${error.message}`);
        }
      }
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
    accountName: accountName,
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

  return (
    <div className="web3authn-profile-button-container">
      <div
        ref={refs.buttonRef}
        className={`web3authn-profile-button-morphable ${isOpen ? 'open' : 'closed'}`}
      >
        <ProfileTrigger
          username={accountName}
          isOpen={isOpen}
          onClick={handleToggle}
        />

        {/* Visible menu structure for actual interaction */}
        <ProfileDropdown
          ref={refs.dropdownRef}
          isOpen={isOpen}
          menuItems={MENU_ITEMS}
          useRelayer={useRelayer}
          onRelayerChange={setUseRelayer}
          onLogout={handleLogout}
          onClose={handleClose}
          menuItemsRef={refs.menuItemsRef}
          toggleColors={toggleColors}
        />
      </div>
    </div>
  );
};