import { forwardRef } from 'react';
import { ProfileMenuItem } from './ProfileMenuItem';
import { ProfileRelayerToggleSection } from './ProfileRelayerToggleSection';
import { ProfileLogoutSection } from './ProfileLogoutSection';
import type { ProfileDropdownProps } from './types';

interface ProfileDropdownWithRefs extends ProfileDropdownProps {
  menuItemsRef: React.RefObject<(HTMLElement | null)[]>;
}

export const ProfileDropdown = forwardRef<HTMLDivElement, ProfileDropdownWithRefs>(
  ({ isOpen, menuItems, useRelayer, onRelayerChange, onLogout, onClose, menuItemsRef, toggleColors }, ref) => {
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
              ref={(el) => {
                if (menuItemsRef.current) {
                  menuItemsRef.current[index + 1] = el;
                }
              }}
              item={item}
              index={index}
              onClose={onClose}
            />
          ))}

          {/* Relayer Toggle Section */}
          <ProfileRelayerToggleSection
            ref={(el: any) => {
              if (menuItemsRef.current) {
                menuItemsRef.current[menuItems.length + 1] = el;
              }
            }}
            useRelayer={useRelayer}
            onRelayerChange={onRelayerChange}
            toggleColors={toggleColors}
          />

          {/* Logout Section */}
          <ProfileLogoutSection
            ref={(el: any) => {
              if (menuItemsRef.current) {
                menuItemsRef.current[menuItems.length + 2] = el;
              }
            }}
            onLogout={onLogout}
          />
        </div>
      </div>
    );
  }
);

ProfileDropdown.displayName = 'ProfileDropdown';