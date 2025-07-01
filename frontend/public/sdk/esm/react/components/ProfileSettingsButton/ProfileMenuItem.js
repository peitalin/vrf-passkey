import { j as jsxRuntimeExports } from '../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js';
import { forwardRef } from 'react';

const ProfileMenuItem = forwardRef(({ item, index, onClose }, ref) => {
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
    return (jsxRuntimeExports.jsxs("button", { ref: ref, disabled: item.disabled, className: `web3authn-profile-dropdown-menu-item ${item.disabled ? 'disabled' : ''}`, onClick: handleClick, children: [jsxRuntimeExports.jsx("div", { className: "web3authn-profile-dropdown-menu-item-icon", children: item.icon }), jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-menu-item-content", children: [jsxRuntimeExports.jsx("p", { className: "web3authn-profile-dropdown-menu-item-label", children: item.label }), jsxRuntimeExports.jsx("p", { className: "web3authn-profile-dropdown-menu-item-description", children: item.description })] })] }));
});
ProfileMenuItem.displayName = 'ProfileMenuItem';

export { ProfileMenuItem };
//# sourceMappingURL=ProfileMenuItem.js.map
