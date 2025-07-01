import React from 'react';
export interface ToggleColorProps {
    activeBackground?: string;
    activeShadow?: string;
    inactiveBackground?: string;
    inactiveShadow?: string;
}
interface ToggleProps {
    checked: boolean;
    onChange: (checked: boolean) => void;
    label?: string;
    tooltip?: string;
    showTooltip?: boolean;
    className?: string;
    size?: 'small' | 'large';
    textPosition?: 'left' | 'right';
    colors?: ToggleColorProps;
}
export declare const Toggle: React.FC<ToggleProps>;
export default Toggle;
//# sourceMappingURL=Toggle.d.ts.map