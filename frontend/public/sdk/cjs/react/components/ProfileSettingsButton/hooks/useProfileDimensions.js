'use strict';

var require$$0 = require('react');

// Constants for calculations
const PROFILE_CONSTANTS = {
    BASE_WIDTH: 24,
    CHAR_WIDTH: 8,
    REM_BUFFER: 32, // 2rem: 32px, one 1rem each side (left/right)
    CLOSED_HEIGHT: 40,
    OPEN_WIDTH: 300,
};
const useProfileDimensions = (params) => {
    const { accountName, numMenuItems, profileButtonHeight, menuItemHeight, toggleSectionHeight, logoutSectionHeight, bottomBuffer, } = params;
    const closedDimensions = require$$0.useMemo(() => {
        const width = PROFILE_CONSTANTS.BASE_WIDTH +
            (accountName.length * PROFILE_CONSTANTS.CHAR_WIDTH) +
            PROFILE_CONSTANTS.REM_BUFFER;
        return {
            width,
            height: PROFILE_CONSTANTS.CLOSED_HEIGHT,
        };
    }, [accountName]);
    const openDimensions = require$$0.useMemo(() => {
        const height = profileButtonHeight +
            (numMenuItems * menuItemHeight) +
            toggleSectionHeight +
            logoutSectionHeight +
            bottomBuffer;
        return {
            width: PROFILE_CONSTANTS.OPEN_WIDTH,
            height,
        };
    }, [numMenuItems, profileButtonHeight, menuItemHeight, toggleSectionHeight, logoutSectionHeight, bottomBuffer]);
    return {
        closedDimensions,
        openDimensions,
        constants: PROFILE_CONSTANTS,
    };
};

exports.useProfileDimensions = useProfileDimensions;
//# sourceMappingURL=useProfileDimensions.js.map
