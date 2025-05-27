import React from 'react';

interface RefreshIconProps {
  size?: number;
  color?: string;
  className?: string; // Allow passing a class for additional styling if needed
}

export const RefreshIcon: React.FC<RefreshIconProps> = ({size = 20, color = 'currentColor', className}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke={color}
    strokeWidth="2.5"
    strokeLinecap="round"
    strokeLinejoin="round"
    className={className} // Apply className prop
    style={{ display: 'inline-block', verticalAlign: 'middle' }} // Keep essential inline styles
  >
    <path d="M20 11A8.1 8.1 0 0 0 4.5 9M4 5v4h4"/>
    <path d="M4 13a8.1 8.1 0 0 0 15.5 2M20 19v-4h-4"/>
  </svg>
);