import { j as jsxRuntimeExports } from '../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js';
import { forwardRef } from 'react';
import { Toggle } from './Toggle.js';

const ProfileRelayerToggleSection = forwardRef(({ useRelayer, onRelayerChange, toggleColors }, ref) => {
    const handleClick = (e) => {
        e.stopPropagation();
    };
    return (jsxRuntimeExports.jsx("div", { ref: ref, className: "web3authn-profile-dropdown-toggle-section", onClick: handleClick, children: jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-toggle-content", children: [jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-toggle-text", children: [jsxRuntimeExports.jsx("p", { className: "web3authn-profile-dropdown-toggle-title", children: useRelayer ? 'Use Relayer' : 'Use Faucet' }), jsxRuntimeExports.jsx("p", { className: "web3authn-profile-dropdown-toggle-description", children: useRelayer
                                ? 'Using relayer for account creation'
                                : 'Direct testnet account creation' })] }), jsxRuntimeExports.jsx(Toggle, { checked: useRelayer, onChange: onRelayerChange, showTooltip: false, size: "large", textPosition: 'left', colors: toggleColors })] }) }));
});
ProfileRelayerToggleSection.displayName = 'ProfileRelayerToggleSection';

export { ProfileRelayerToggleSection };
//# sourceMappingURL=ProfileRelayerToggleSection.js.map
