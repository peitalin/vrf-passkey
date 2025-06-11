import React, { forwardRef } from 'react';
import { Toggle } from '../Toggle';
import type { ProfileToggleSectionProps } from './types';

export const ProfileToggleSection = forwardRef<HTMLDivElement, ProfileToggleSectionProps>(
  ({ optimisticAuth, onOptimisticAuthChange }, ref) => {
    const handleClick = (e: React.MouseEvent) => {
      e.stopPropagation();
    };

    return (
      <div
        ref={ref}
        className="web3authn-profile-dropdown-toggle-section"
        onClick={handleClick}
      >
        <div className="web3authn-profile-dropdown-toggle-content">
          <div className="web3authn-profile-dropdown-toggle-text">
            <p className="web3authn-profile-dropdown-toggle-title">
              {optimisticAuth ? 'Fast Signing' : 'Contract Signing'}
            </p>
            <p className="web3authn-profile-dropdown-toggle-description">
              {optimisticAuth
                ? 'Fast transaction signing with optimistic responses'
                : 'Contract signed Passkey authentication (slower)'
              }
            </p>
          </div>
          <Toggle
            checked={optimisticAuth}
            onChange={onOptimisticAuthChange}
            showTooltip={false}
            size="large"
            textPosition='left'
          />
        </div>
      </div>
    );
  }
);

ProfileToggleSection.displayName = 'ProfileToggleSection';