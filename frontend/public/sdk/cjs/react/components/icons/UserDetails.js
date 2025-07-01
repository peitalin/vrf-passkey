'use strict';

var jsxRuntime = require('../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js');
var config = require('../../src/config.js');

const UserDetails = ({ username, isOpen }) => {
    return (jsxRuntime.jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-user-details", children: [jsxRuntime.jsxRuntimeExports.jsx("p", { className: "web3authn-profile-dropdown-username", children: username || 'User' }), jsxRuntime.jsxRuntimeExports.jsx("a", { href: username ? `${config.NEAR_EXPLORER_BASE_URL}/accounts/${username}.${config.WEBAUTHN_CONTRACT_ID}` : '#', target: "_blank", rel: "noopener noreferrer", className: `web3authn-profile-dropdown-account-id ${isOpen ? 'visible' : 'hidden'}`, onClick: (e) => e.stopPropagation(), children: username ? `${username}.${config.WEBAUTHN_CONTRACT_ID}` : 'user@example.com' })] }));
};

exports.UserDetails = UserDetails;
//# sourceMappingURL=UserDetails.js.map
