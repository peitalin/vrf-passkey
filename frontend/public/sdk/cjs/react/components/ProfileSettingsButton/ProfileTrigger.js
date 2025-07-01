'use strict';

var jsxRuntime = require('../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js');
var AvatarGearIcon = require('../icons/AvatarGearIcon.js');
var UserDetails = require('../icons/UserDetails.js');

const ProfileTrigger = ({ username, isOpen, onClick, isHovered, onMouseEnter, onMouseLeave, }) => {
    return (jsxRuntime.jsxRuntimeExports.jsx("div", { className: "web3authn-profile-button-trigger-wrapper", children: jsxRuntime.jsxRuntimeExports.jsx("div", { className: `web3authn-profile-button-trigger ${isOpen ? 'open' : 'closed'}`, onClick: onClick, ...(onMouseEnter && { onMouseEnter }), ...(onMouseLeave && { onMouseLeave }), children: jsxRuntime.jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-user-content", children: [jsxRuntime.jsxRuntimeExports.jsx(AvatarGearIcon.AvatarGearIcon, { isOpen: isOpen }), jsxRuntime.jsxRuntimeExports.jsx(UserDetails.UserDetails, { username: username, isOpen: isOpen })] }) }) }));
};

exports.ProfileTrigger = ProfileTrigger;
//# sourceMappingURL=ProfileTrigger.js.map
