import type { ProfileDimensions, ProfileCalculationParams } from '../types';
export declare const useProfileDimensions: (params: ProfileCalculationParams) => {
    closedDimensions: ProfileDimensions;
    openDimensions: ProfileDimensions;
    constants: {
        readonly BASE_WIDTH: 24;
        readonly CHAR_WIDTH: 8;
        readonly REM_BUFFER: 32;
        readonly CLOSED_HEIGHT: 40;
        readonly OPEN_WIDTH: 300;
    };
};
//# sourceMappingURL=useProfileDimensions.d.ts.map