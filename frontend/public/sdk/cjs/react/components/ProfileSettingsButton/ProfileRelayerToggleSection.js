'use strict';

var jsxRuntime = require('../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js');
var require$$0 = require('react');
var Toggle = require('./Toggle.js');

const ProfileRelayerToggleSection = require$$0.forwardRef(({ useRelayer, onRelayerChange, toggleColors }, ref) => {
    const handleClick = (e) => {
        e.stopPropagation();
    };
    return (jsxRuntime.jsxRuntimeExports.jsx("div", { ref: ref, className: "web3authn-profile-dropdown-toggle-section", onClick: handleClick, children: jsxRuntime.jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-toggle-content", children: [jsxRuntime.jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-toggle-text", children: [jsxRuntime.jsxRuntimeExports.jsx("p", { className: "web3authn-profile-dropdown-toggle-title", children: useRelayer ? 'Use Relayer' : 'Use Faucet' }), jsxRuntime.jsxRuntimeExports.jsx("p", { className: "web3authn-profile-dropdown-toggle-description", children: useRelayer
                                ? 'Using relayer for account creation'
                                : 'Direct testnet account creation' })] }), jsxRuntime.jsxRuntimeExports.jsx(Toggle.Toggle, { checked: useRelayer, onChange: onRelayerChange, showTooltip: false, size: "large", textPosition: 'left', colors: toggleColors })] }) }));
});
ProfileRelayerToggleSection.displayName = 'ProfileRelayerToggleSection';

exports.ProfileRelayerToggleSection = ProfileRelayerToggleSection;
//# sourceMappingURL=ProfileRelayerToggleSection.js.map
