import React from 'react';
import { AvatarGearIcon } from '../icons/AvatarGearIcon';
import { UserDetails } from '../icons/UserDetails';
import type { ProfileTriggerProps } from './types';

export const ProfileTrigger: React.FC<ProfileTriggerProps> = ({
  username,
  isOpen,
  onClick,
  isHovered,
  onMouseEnter,
  onMouseLeave,
}) => {
  return (
    <div className="web3authn-profile-button-trigger-wrapper">
      <div
        className={`web3authn-profile-button-trigger ${isOpen ? 'open' : 'closed'}`}
        onClick={onClick}
        {...(onMouseEnter && { onMouseEnter })}
        {...(onMouseLeave && { onMouseLeave })}
      >
        <div className="web3authn-profile-dropdown-user-content">
          <AvatarGearIcon isOpen={isOpen} />
          <UserDetails username={username} isOpen={isOpen} />
        </div>
      </div>
    </div>
  );
};