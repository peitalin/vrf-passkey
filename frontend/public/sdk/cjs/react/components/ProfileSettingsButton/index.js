'use strict';

var jsxRuntime = require('../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js');
var KeyIcon = require('../icons/KeyIcon.js');
var PaymentMethodsIcon = require('../icons/PaymentMethodsIcon.js');
var ProfileTrigger = require('./ProfileTrigger.js');
var ProfileDropdown = require('./ProfileDropdown.js');
var useProfileState = require('./hooks/useProfileState.js');
var useProfileDimensions = require('./hooks/useProfileDimensions.js');
var useProfileAnimations = require('./hooks/useProfileAnimations.js');
var index = require('../../context/index.js');

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
    const { loginState, passkeyManager, logout, useRelayer, setUseRelayer, } = index.usePasskeyContext();
    // Use props if provided, otherwise fall back to context
    const accountName = nearAccountIdProp?.split('.')?.[0] || 'User';
    const nearAccountId = nearAccountIdProp || loginState.nearAccountId;
    const onLogout = onLogoutProp || logout;
    // Menu items configuration with context-aware handlers
    const MENU_ITEMS = [
        {
            icon: jsxRuntime.jsxRuntimeExports.jsx(KeyIcon.KeyIcon, {}),
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
            icon: jsxRuntime.jsxRuntimeExports.jsx(PaymentMethodsIcon.PaymentMethodsIcon, {}),
            label: 'Payments',
            description: 'Manage payment methods',
            disabled: true
        },
    ];
    // State management
    const { isOpen, refs, handleToggle, handleClose, } = useProfileState.useProfileState();
    // Dimension calculations
    const calculationParams = {
        accountName: accountName,
        ...MENU_CONFIG,
    };
    const { closedDimensions, openDimensions } = useProfileDimensions.useProfileDimensions(calculationParams);
    // Animations
    useProfileAnimations.useProfileAnimations({
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
    return (jsxRuntime.jsxRuntimeExports.jsx("div", { className: "web3authn-profile-button-container", children: jsxRuntime.jsxRuntimeExports.jsxs("div", { ref: refs.buttonRef, className: `web3authn-profile-button-morphable ${isOpen ? 'open' : 'closed'}`, children: [jsxRuntime.jsxRuntimeExports.jsx(ProfileTrigger.ProfileTrigger, { username: accountName, isOpen: isOpen, onClick: handleToggle }), jsxRuntime.jsxRuntimeExports.jsx(ProfileDropdown.ProfileDropdown, { ref: refs.dropdownRef, isOpen: isOpen, menuItems: MENU_ITEMS, useRelayer: useRelayer, onRelayerChange: setUseRelayer, onLogout: handleLogout, onClose: handleClose, menuItemsRef: refs.menuItemsRef, toggleColors: toggleColors })] }) }));
};

exports.ProfileButton = ProfileButton;
//# sourceMappingURL=index.js.map
