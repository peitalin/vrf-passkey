export interface ProfileDimensions {
  width: number;
  height: number;
}

export interface ProfileAnimationConfig {
  duration: number;
  delay: number;
  ease: string;
}

export interface ProfileMenuItem {
  icon: React.ReactNode;
  label: string;
  description: string;
  disabled: boolean;
}

export interface ProfileButtonProps {
  username: string;
  nearAccountId?: string;
  optimisticAuth: boolean;
  onOptimisticAuthChange: (value: boolean) => void;
  onLogout: () => void;
}

export interface ProfileTriggerProps {
  username: string;
  isOpen: boolean;
  onClick: () => void;
  isHovered?: boolean;
  onMouseEnter?: () => void;
  onMouseLeave?: () => void;
}

export interface ProfileDropdownProps {
  isOpen: boolean;
  menuItems: ProfileMenuItem[];
  optimisticAuth: boolean;
  onOptimisticAuthChange: (value: boolean) => void;
  onLogout: () => void;
  onClose: () => void;
}

export interface ProfileMenuItemProps {
  item: ProfileMenuItem;
  index: number;
  onClose: () => void;
}

export interface ProfileToggleSectionProps {
  optimisticAuth: boolean;
  onOptimisticAuthChange: (value: boolean) => void;
}

export interface ProfileLogoutSectionProps {
  onLogout: () => void;
}

export interface ProfileStateRefs {
  buttonRef: React.RefObject<HTMLDivElement>;
  dropdownRef: React.RefObject<HTMLDivElement>;
  menuItemsRef: React.MutableRefObject<(HTMLElement | null)[]>;
}

export interface ProfileCalculationParams {
  username: string;
  numMenuItems: number;
  profileButtonHeight: number;
  menuItemHeight: number;
  toggleSectionHeight: number;
  logoutSectionHeight: number;
  bottomBuffer: number;
}