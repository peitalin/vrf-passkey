import { useState, useRef, useEffect } from 'react';

const useProfileState = () => {
    const [isOpen, setIsOpen] = useState(false);
    // Refs
    const buttonRef = useRef(null);
    const dropdownRef = useRef(null);
    const menuItemsRef = useRef([]);
    const refs = {
        buttonRef,
        dropdownRef,
        menuItemsRef,
    };
    // Handle click outside to close
    useEffect(() => {
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

export { useProfileState };
//# sourceMappingURL=useProfileState.js.map
