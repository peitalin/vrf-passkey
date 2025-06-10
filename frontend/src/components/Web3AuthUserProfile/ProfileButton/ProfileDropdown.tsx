import React, { forwardRef } from 'react';
import { ProfileMenuItem } from './ProfileMenuItem';
import { ProfileToggleSection } from './ProfileToggleSection';
import { ProfileLogoutSection } from './ProfileLogoutSection';
import type { ProfileDropdownProps } from '../types';

interface ProfileDropdownWithRefs extends ProfileDropdownProps {
  menuItemsRef: React.RefObject<(HTMLElement | null)[]>;
}

export const ProfileDropdown = forwardRef<HTMLDivElement, ProfileDropdownWithRefs>(
  ({ isOpen, menuItems, optimisticAuth, onOptimisticAuthChange, onLogout, onClose, menuItemsRef }, ref) => {
    return (
      <div
        ref={ref}
        className={`web3authn-profile-dropdown-morphed ${isOpen ? 'visible' : 'hidden'}`}
      >
        <div className="web3authn-profile-dropdown-menu">
          {/* Menu Items */}
          {menuItems.map((item, index) => (
            <ProfileMenuItem
              key={index}
              ref={(el) => { menuItemsRef.current[index + 1] = el; }}
              item={item}
              index={index}
              onClose={onClose}
            />
          ))}

          {/* Toggle Section */}
          <ProfileToggleSection
            ref={(el) => { menuItemsRef.current[menuItems.length + 1] = el; }}
            optimisticAuth={optimisticAuth}
            onOptimisticAuthChange={onOptimisticAuthChange}
          />

          {/* Logout Section */}
          <ProfileLogoutSection
            ref={(el) => { menuItemsRef.current[menuItems.length + 2] = el; }}
            onLogout={onLogout}
          />
        </div>
      </div>
    );
  }
);

ProfileDropdown.displayName = 'ProfileDropdown';