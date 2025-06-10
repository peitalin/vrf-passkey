// Main component
export { ProfileButton as Web3authUserProfile } from './ProfileButton';
export { ProfileButton } from './ProfileButton'; // Keep for backward compatibility

// Subcomponents (from ProfileButton folder)
export { ProfileTrigger } from './ProfileButton/ProfileTrigger';
export { ProfileDropdown } from './ProfileButton/ProfileDropdown';
export { ProfileMenuItem } from './ProfileButton/ProfileMenuItem';
export { ProfileToggleSection } from './ProfileButton/ProfileToggleSection';
export { ProfileLogoutSection } from './ProfileButton/ProfileLogoutSection';

// Hooks
export { useProfileState } from './hooks/useProfileState';
export { useProfileDimensions } from './hooks/useProfileDimensions';
export { useProfileAnimations } from './hooks/useProfileAnimations';

// Types
export type * from './types';