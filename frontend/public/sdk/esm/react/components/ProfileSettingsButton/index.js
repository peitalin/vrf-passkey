import { j as jsxRuntimeExports } from '../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js';
import { KeyIcon } from '../icons/KeyIcon.js';
import { PaymentMethodsIcon } from '../icons/PaymentMethodsIcon.js';
import { ProfileTrigger } from './ProfileTrigger.js';
import { ProfileDropdown } from './ProfileDropdown.js';
import { useProfileState } from './hooks/useProfileState.js';
import { useProfileDimensions } from './hooks/useProfileDimensions.js';
import { useProfileAnimations } from './hooks/useProfileAnimations.js';
import { usePasskeyContext } from '../../context/index.js';

// Configuration constants
const MENU_CONFIG = {
    numMenuItems: 2,
    profileButtonHeight: 72,
    menuItemHeight: 52,
    toggleSectionHeight: 82,
    logoutSectionHeight: 46,
    bottomBuffer: 4,
};
const ProfileButton = ({ username: usernameProp, nearAccountId: nearAccountIdProp, onLogout: onLogoutProp, toggleColors, }) => {
    // Get values from context if not provided as props
    const { loginState, passkeyManager, logout, useRelayer, setUseRelayer, } = usePasskeyContext();
    // Use props if provided, otherwise fall back to context
    const accountName = nearAccountIdProp?.split('.')?.[0] || 'User';
    const nearAccountId = nearAccountIdProp || loginState.nearAccountId;
    const onLogout = onLogoutProp || logout;
    // Menu items configuration with context-aware handlers
    const MENU_ITEMS = [
        {
            icon: jsxRuntimeExports.jsx(KeyIcon, {}),
            label: 'Export Keys',
            description: 'Export your NEAR private keys',
            disabled: false,
            onClick: async () => {
                try {
                    const { accountId, privateKey, publicKey } = await passkeyManager.exportNearKeypairWithTouchId(nearAccountId);
                    // Small delay to allow document to regain focus after WebAuthn
                    await new Promise(resolve => setTimeout(resolve, 150));
                    const keypair_msg = `Account ID:\n${accountId}\n\nPublic key:\n${publicKey}\n\nPrivate key:\n${privateKey}`;
                    // Simple clipboard approach with single fallback
                    if (navigator.clipboard && window.isSecureContext) {
                        await navigator.clipboard.writeText(keypair_msg);
                        alert(`NEAR keys copied to clipboard!\n${keypair_msg}`);
                    }
                    else {
                        // Simple fallback: show keys for manual copy
                        alert(`Your NEAR Keys (copy manually):\n${keypair_msg}`);
                    }
                }
                catch (error) {
                    console.error('Key export failed:', error);
                    alert(`Key export failed: ${error.message}`);
                }
            }
        },
        {
            icon: jsxRuntimeExports.jsx(PaymentMethodsIcon, {}),
            label: 'Payments',
            description: 'Manage payment methods',
            disabled: true
        },
    ];
    // State management
    const { isOpen, refs, handleToggle, handleClose, } = useProfileState();
    // Dimension calculations
    const calculationParams = {
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
    return (jsxRuntimeExports.jsx("div", { className: "web3authn-profile-button-container", children: jsxRuntimeExports.jsxs("div", { ref: refs.buttonRef, className: `web3authn-profile-button-morphable ${isOpen ? 'open' : 'closed'}`, children: [jsxRuntimeExports.jsx(ProfileTrigger, { username: accountName, isOpen: isOpen, onClick: handleToggle }), jsxRuntimeExports.jsx(ProfileDropdown, { ref: refs.dropdownRef, isOpen: isOpen, menuItems: MENU_ITEMS, useRelayer: useRelayer, onRelayerChange: setUseRelayer, onLogout: handleLogout, onClose: handleClose, menuItemsRef: refs.menuItemsRef, toggleColors: toggleColors })] }) }));
};

export { ProfileButton };
//# sourceMappingURL=index.js.map
