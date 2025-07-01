import { j as jsxRuntimeExports } from '../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js';
import { forwardRef } from 'react';
import { ProfileMenuItem } from './ProfileMenuItem.js';
import { ProfileRelayerToggleSection } from './ProfileRelayerToggleSection.js';
import { ProfileLogoutSection } from './ProfileLogoutSection.js';

const ProfileDropdown = forwardRef(({ isOpen, menuItems, useRelayer, onRelayerChange, onLogout, onClose, menuItemsRef, toggleColors }, ref) => {
    return (jsxRuntimeExports.jsx("div", { ref: ref, className: `web3authn-profile-dropdown-morphed ${isOpen ? 'visible' : 'hidden'}`, children: jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-menu", children: [menuItems.map((item, index) => (jsxRuntimeExports.jsx(ProfileMenuItem, { ref: (el) => {
                        if (menuItemsRef.current) {
                            menuItemsRef.current[index + 1] = el;
                        }
                    }, item: item, index: index, onClose: onClose }, index))), jsxRuntimeExports.jsx(ProfileRelayerToggleSection, { ref: (el) => {
                        if (menuItemsRef.current) {
                            menuItemsRef.current[menuItems.length + 1] = el;
                        }
                    }, useRelayer: useRelayer, onRelayerChange: onRelayerChange, toggleColors: toggleColors }), jsxRuntimeExports.jsx(ProfileLogoutSection, { ref: (el) => {
                        if (menuItemsRef.current) {
                            menuItemsRef.current[menuItems.length + 2] = el;
                        }
                    }, onLogout: onLogout })] }) }));
});
ProfileDropdown.displayName = 'ProfileDropdown';

export { ProfileDropdown };
//# sourceMappingURL=ProfileDropdown.js.map
