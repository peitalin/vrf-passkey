'use strict';

var jsxRuntime = require('../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js');
var require$$0 = require('react');

const ProfileMenuItem = require$$0.forwardRef(({ item, index, onClose }, ref) => {
    const handleClick = (e) => {
        e.stopPropagation();
        if (!item.disabled) {
            console.log(`Clicked: ${item.label}`);
            if (item.onClick) {
                item.onClick();
            }
            onClose();
        }
    };
    return (jsxRuntime.jsxRuntimeExports.jsxs("button", { ref: ref, disabled: item.disabled, className: `web3authn-profile-dropdown-menu-item ${item.disabled ? 'disabled' : ''}`, onClick: handleClick, children: [jsxRuntime.jsxRuntimeExports.jsx("div", { className: "web3authn-profile-dropdown-menu-item-icon", children: item.icon }), jsxRuntime.jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-menu-item-content", children: [jsxRuntime.jsxRuntimeExports.jsx("p", { className: "web3authn-profile-dropdown-menu-item-label", children: item.label }), jsxRuntime.jsxRuntimeExports.jsx("p", { className: "web3authn-profile-dropdown-menu-item-description", children: item.description })] })] }));
});
ProfileMenuItem.displayName = 'ProfileMenuItem';

exports.ProfileMenuItem = ProfileMenuItem;
//# sourceMappingURL=ProfileMenuItem.js.map
