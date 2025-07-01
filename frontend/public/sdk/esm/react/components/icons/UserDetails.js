import { j as jsxRuntimeExports } from '../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js';
import { WEBAUTHN_CONTRACT_ID, NEAR_EXPLORER_BASE_URL } from '../../src/config.js';

const UserDetails = ({ username, isOpen }) => {
    return (jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-user-details", children: [jsxRuntimeExports.jsx("p", { className: "web3authn-profile-dropdown-username", children: username || 'User' }), jsxRuntimeExports.jsx("a", { href: username ? `${NEAR_EXPLORER_BASE_URL}/accounts/${username}.${WEBAUTHN_CONTRACT_ID}` : '#', target: "_blank", rel: "noopener noreferrer", className: `web3authn-profile-dropdown-account-id ${isOpen ? 'visible' : 'hidden'}`, onClick: (e) => e.stopPropagation(), children: username ? `${username}.${WEBAUTHN_CONTRACT_ID}` : 'user@example.com' })] }));
};

export { UserDetails };
//# sourceMappingURL=UserDetails.js.map
