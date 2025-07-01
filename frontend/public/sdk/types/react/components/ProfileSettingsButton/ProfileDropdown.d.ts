import React from 'react';
import type { ProfileDropdownProps } from './types';
interface ProfileDropdownWithRefs extends ProfileDropdownProps {
    menuItemsRef: React.RefObject<(HTMLElement | null)[]>;
}
export declare const ProfileDropdown: React.ForwardRefExoticComponent<ProfileDropdownWithRefs & React.RefAttributes<HTMLDivElement>>;
export {};
//# sourceMappingURL=ProfileDropdown.d.ts.map