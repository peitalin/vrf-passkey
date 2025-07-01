import React from 'react';
import type { ToggleColorProps } from './types';
import './Web3AuthProfileButton.css';
export interface ProfileButtonProps {
    username?: string | null;
    nearAccountId?: string | null;
    onLogout?: () => void;
    toggleColors?: ToggleColorProps;
}
export declare const ProfileButton: React.FC<ProfileButtonProps>;
//# sourceMappingURL=index.d.ts.map