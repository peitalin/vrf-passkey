import type { ProfileStateRefs, ProfileDimensions } from '../types';
interface UseProfileAnimationsProps {
    isOpen: boolean;
    refs: ProfileStateRefs;
    openDimensions: ProfileDimensions;
    closedDimensions: ProfileDimensions;
}
export declare const useProfileAnimations: ({ isOpen, refs, openDimensions, closedDimensions, }: UseProfileAnimationsProps) => {
    animationConfigs: {
        readonly container: {
            readonly open: {
                readonly duration: 100;
                readonly easing: "outElastic(0.5, .4)";
            };
            readonly close: {
                readonly duration: 100;
                readonly delay: 0;
                readonly easing: "inOutBack(0.8)";
            };
        };
        readonly dropdown: {
            readonly show: {
                readonly duration: 100;
                readonly delay: 0;
            };
            readonly hide: {
                readonly duration: 100;
                readonly delay: 0;
            };
        };
        readonly menuItems: {
            readonly in: {
                readonly duration: 150;
                readonly easing: "outBack(0.8)";
                readonly staggerDelay: 0;
            };
            readonly out: {
                readonly duration: 150;
                readonly easing: "inBack(0.8)";
                readonly staggerDelay: 0;
            };
        };
    };
};
export {};
//# sourceMappingURL=useProfileAnimations.d.ts.map