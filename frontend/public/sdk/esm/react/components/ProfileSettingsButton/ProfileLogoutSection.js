import { j as jsxRuntimeExports } from '../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js';
import { forwardRef } from 'react';

const ProfileLogoutSection = forwardRef(({ onLogout }, ref) => {
    const handleLogout = (e) => {
        e.stopPropagation();
        onLogout();
    };
    return (jsxRuntimeExports.jsx("div", { ref: ref, children: jsxRuntimeExports.jsx("div", { className: "web3authn-profile-dropdown-logout-section", children: jsxRuntimeExports.jsxs("button", { className: "web3authn-profile-dropdown-logout-button", onClick: handleLogout, children: [jsxRuntimeExports.jsxs("svg", { width: "16", height: "16", viewBox: "0 0 16 16", className: "web3authn-profile-dropdown-logout-icon", children: [jsxRuntimeExports.jsx("path", { d: "M3 3a1 1 0 0 1 1-1h8a1 1 0 0 1 1 1v2a.5.5 0 0 1-1 0V3H4v10h8v-2a.5.5 0 0 1 1 0v2a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V3Z", fill: "currentColor" }), jsxRuntimeExports.jsx("path", { d: "M11.854 8.854a.5.5 0 0 0 0-.708l-3-3a.5.5 0 1 0-.708.708L10.293 8H1.5a.5.5 0 0 0 0 1h8.793l-2.147 2.146a.5.5 0 0 0 .708.708l3-3Z", fill: "currentColor" })] }), jsxRuntimeExports.jsx("span", { className: "web3authn-profile-dropdown-logout-text", children: "Log out" })] }) }) }));
});
ProfileLogoutSection.displayName = 'ProfileLogoutSection';

export { ProfileLogoutSection };
//# sourceMappingURL=ProfileLogoutSection.js.map
