'use strict';

var require$$0 = require('react');

const useProfileState = () => {
    const [isOpen, setIsOpen] = require$$0.useState(false);
    // Refs
    const buttonRef = require$$0.useRef(null);
    const dropdownRef = require$$0.useRef(null);
    const menuItemsRef = require$$0.useRef([]);
    const refs = {
        buttonRef,
        dropdownRef,
        menuItemsRef,
    };
    // Handle click outside to close
    require$$0.useEffect(() => {
        const handleClickOutside = (event) => {
            if (dropdownRef.current &&
                buttonRef.current &&
                !buttonRef.current.contains(event.target)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);
    const handleToggle = () => {
        setIsOpen(!isOpen);
    };
    const handleClose = () => {
        setIsOpen(false);
    };
    return {
        // State
        isOpen,
        // Refs
        refs,
        // Handlers
        handleToggle,
        handleClose,
    };
};

exports.useProfileState = useProfileState;
//# sourceMappingURL=useProfileState.js.map
