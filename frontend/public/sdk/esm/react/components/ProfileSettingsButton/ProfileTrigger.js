import { j as jsxRuntimeExports } from '../../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js';
import { AvatarGearIcon } from '../icons/AvatarGearIcon.js';
import { UserDetails } from '../icons/UserDetails.js';

const ProfileTrigger = ({ username, isOpen, onClick, isHovered, onMouseEnter, onMouseLeave, }) => {
    return (jsxRuntimeExports.jsx("div", { className: "web3authn-profile-button-trigger-wrapper", children: jsxRuntimeExports.jsx("div", { className: `web3authn-profile-button-trigger ${isOpen ? 'open' : 'closed'}`, onClick: onClick, ...(onMouseEnter && { onMouseEnter }), ...(onMouseLeave && { onMouseLeave }), children: jsxRuntimeExports.jsxs("div", { className: "web3authn-profile-dropdown-user-content", children: [jsxRuntimeExports.jsx(AvatarGearIcon, { isOpen: isOpen }), jsxRuntimeExports.jsx(UserDetails, { username: username, isOpen: isOpen })] }) }) }));
};

export { ProfileTrigger };
//# sourceMappingURL=ProfileTrigger.js.map
