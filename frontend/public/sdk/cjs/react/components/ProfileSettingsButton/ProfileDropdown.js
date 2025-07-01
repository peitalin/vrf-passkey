'use strict';

var jsxRuntime = require('../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js');
var require$$0 = require('react');
var ProfileMenuItem = require('./ProfileMenuItem.js');
var ProfileRelayerToggleSection = require('./ProfileRelayerToggleSection.js');
var ProfileLogoutSection = require('./ProfileLogoutSection.js');

const ProfileDropdown = require$$0.forwardRef(({ isOpen, menuItems, useRelayer, onRelayerChange, onLogout, onClose, menuItemsRef, toggleColors }, ref) => {
    return (jsxRuntime.jsxRuntimeExports.jsx("div", { ref: ref, className: `web3authn-profile-dropdown-morphed ${isOpen ? 'visible' : 'hidden'}`, children: jsxRuntime.jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-menu", children: [menuItems.map((item, index) => (jsxRuntime.jsxRuntimeExports.jsx(ProfileMenuItem.ProfileMenuItem, { ref: (el) => {
                        if (menuItemsRef.current) {
                            menuItemsRef.current[index + 1] = el;
                        }
                    }, item: item, index: index, onClose: onClose }, index))), jsxRuntime.jsxRuntimeExports.jsx(ProfileRelayerToggleSection.ProfileRelayerToggleSection, { ref: (el) => {
                        if (menuItemsRef.current) {
                            menuItemsRef.current[menuItems.length + 1] = el;
                        }
                    }, useRelayer: useRelayer, onRelayerChange: onRelayerChange, toggleColors: toggleColors }), jsxRuntime.jsxRuntimeExports.jsx(ProfileLogoutSection.ProfileLogoutSection, { ref: (el) => {
                        if (menuItemsRef.current) {
                            menuItemsRef.current[menuItems.length + 2] = el;
                        }
                    }, onLogout: onLogout })] }) }));
});
ProfileDropdown.displayName = 'ProfileDropdown';

exports.ProfileDropdown = ProfileDropdown;
//# sourceMappingURL=ProfileDropdown.js.map
