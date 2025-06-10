# Web3authUserProfile Component Architecture

This directory contains the refactored Web3authUserProfile component (originally ProfileButton), broken down into modular, reusable components and isolated logic.

## 📁 Structure

```
Web3authUserProfile/
├── README.md                        # This documentation
├── index.ts                         # Public exports
├── types.ts                         # TypeScript definitions
├── Web3authUserProfile.css          # All component styles (self-contained)
├── ProfileButton/                   # Main ProfileButton component folder
│   ├── index.tsx                    # Main orchestrating component
│   ├── ProfileTrigger.tsx           # Clickable trigger area
│   ├── ProfileDropdown.tsx          # Dropdown container
│   ├── ProfileMenuItem.tsx          # Individual menu items
│   ├── ProfileToggleSection.tsx     # Fast auth toggle
│   └── ProfileLogoutSection.tsx     # Logout button
└── hooks/
    ├── useProfileState.ts           # State management
    ├── useProfileDimensions.ts      # Width/height calculations
    └── useProfileAnimations.ts      # Animation logic
```

## 🎨 Styling

All Web3authUserProfile component styles are self-contained in `Web3authUserProfile.css`. This includes:

### CSS Classes Used (All prefixed with `web3authn-`):
- **Container & Layout**: `web3authn-profile-button-container`, `web3authn-profile-button-morphable`, `web3authn-profile-button-trigger-wrapper`
- **Button Trigger**: `web3authn-profile-button-trigger`, `web3authn-profile-button-icon`, `web3authn-profile-button-username`
- **Avatar States**: `web3authn-profile-dropdown-avatar` (with `.shrunk`/`.expanded` modifiers)
- **User Content**: `web3authn-profile-dropdown-user-content`, `web3authn-profile-dropdown-user-details`
- **Username/Account**: `web3authn-profile-dropdown-username`, `web3authn-profile-dropdown-account-id` (with `.visible`/`.hidden` modifiers)
- **Dropdown Layout**: `web3authn-profile-dropdown`, `web3authn-profile-dropdown-morphed`, `web3authn-profile-dropdown-hidden`, `web3authn-profile-dropdown-user-info`
- **Menu System**: `web3authn-profile-dropdown-menu`, `web3authn-profile-dropdown-menu-item` (with `.disabled` modifier)
- **Menu Item Parts**: `web3authn-profile-dropdown-menu-item-icon`, `web3authn-profile-dropdown-menu-item-content`, `web3authn-profile-dropdown-menu-item-label`, `web3authn-profile-dropdown-menu-item-description`
- **Toggle Section**: `web3authn-profile-dropdown-toggle-section`, `web3authn-profile-dropdown-toggle-content`, `web3authn-profile-dropdown-toggle-text`, `web3authn-profile-dropdown-toggle-title`, `web3authn-profile-dropdown-toggle-description`
- **Logout Section**: `web3authn-profile-dropdown-logout-section`, `web3authn-profile-dropdown-logout-button`, `web3authn-profile-dropdown-logout-icon`, `web3authn-profile-dropdown-logout-text`
- **Avatar Icons**: `web3authn-profile-dropdown-avatar-icon`, `web3authn-profile-dropdown-gear-icon`
- **Animations**: `@keyframes web3authn-gearRotateIn`

### CSS Variables Used:
- `--light-grey`: For borders and dividers
- `--outline-color`: For all icon and container outlines

The CSS is fully self-contained and ready for SDK packaging. The component imports its own styles via `import '../Web3authUserProfile.css'`. All class names are prefixed with `web3authn-` to prevent naming conflicts.

## 🧩 Components

### ProfileButton (Main Component)
- **Location**: `ProfileButton/index.tsx`
- **Purpose**: Orchestrates all subcomponents and hooks
- **Responsibilities**:
  - Context integration (usePasskeyContext)
  - Menu item configuration
  - Event handling coordination
  - CSS import for all component styles

### ProfileTrigger
- **Location**: `ProfileButton/ProfileTrigger.tsx`
- **Purpose**: Renders the clickable avatar + username area
- **Props**: `username`, `isOpen`, `isHovered`, event handlers
- **Dependencies**: `AvatarIcon`, `UserDetails`

### ProfileDropdown
- **Location**: `ProfileButton/ProfileDropdown.tsx`
- **Purpose**: Container for all dropdown menu content
- **Props**: `menuItems`, `optimisticAuth`, event handlers
- **Children**: `ProfileMenuItem`, `ProfileToggleSection`, `ProfileLogoutSection`

### ProfileMenuItem
- **Location**: `ProfileButton/ProfileMenuItem.tsx`
- **Purpose**: Individual interactive menu items
- **Props**: `item`, `index`, `onClose`
- **Features**: Disabled state handling, click interactions

### ProfileToggleSection
- **Location**: `ProfileButton/ProfileToggleSection.tsx`
- **Purpose**: Optimistic auth toggle with labels
- **Props**: `optimisticAuth`, `onOptimisticAuthChange`
- **Dependencies**: `Toggle` component

### ProfileLogoutSection
- **Location**: `ProfileButton/ProfileLogoutSection.tsx`
- **Purpose**: Logout button with icon
- **Props**: `onLogout`
- **Features**: Click handling, logout icon

## 🎯 Hooks

### useProfileState
- **Purpose**: Manages open/closed state and click outside detection
- **Returns**: `isOpen`, `refs`, `handleToggle`, `handleClose`

### useProfileDimensions
- **Purpose**: Calculates container dimensions for animations
- **Params**: `ProfileCalculationParams` (username, menu config)
- **Returns**: `closedDimensions`, `openDimensions`, `constants`

### useProfileAnimations
- **Purpose**: Handles morphing animations between states
- **Dependencies**: anime.js for smooth transitions
- **Features**: Container morphing, staggered menu item animations

## 🔧 Configuration

The component uses a centralized configuration object for consistent sizing:

```typescript
const MENU_CONFIG = {
  numMenuItems: 2,
  profileButtonHeight: 72,
  menuItemHeight: 52,
  toggleSectionHeight: 82,
  logoutSectionHeight: 46,
  bottomBuffer: 4,
} as const;
```

Menu items are also configured at the top level for easy customization.

## 📦 SDK Readiness

This component is architected for easy packaging as an SDK:

1. **Self-contained CSS** - All styles in `Web3authUserProfile.css`
2. **Prefixed CSS classes** - All classes prefixed with `web3authn-` to prevent conflicts
3. **Centralized configuration** - Easy to customize via config objects
4. **Modular structure** - Individual components can be imported separately
5. **Type safety** - Full TypeScript support with exported types
6. **Dependency isolation** - Minimal external dependencies
7. **Clean exports** - Public API through `index.ts`
8. **Renamed exports** - Available as both `Web3authUserProfile` and `ProfileButton`

## 🚀 Usage

### Basic Import (New Name)
```tsx
import { Web3authUserProfile } from '@/components/Web3authUserProfile';

<Web3authUserProfile />
```

### Backward Compatible Import
```tsx
import { ProfileButton } from '@/components/Web3authUserProfile';

<ProfileButton />
```

## ✅ Benefits of Refactoring

1. **No CSS Conflicts** - All classes prefixed with `web3authn-`
2. **SDK Ready** - Self-contained with minimal dependencies
3. **Maintainable** - Clear component boundaries and responsibilities
4. **Performant** - Calculated dimensions eliminate DOM measurements
5. **Customizable** - Centralized configuration for easy theming
6. **Type Safe** - Full TypeScript coverage with exported interfaces
7. **Accessible** - Proper ARIA attributes and keyboard navigation support