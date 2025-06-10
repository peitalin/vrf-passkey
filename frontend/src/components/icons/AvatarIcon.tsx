import { OUTLINE_COLOR } from '../../config';

export const AvatarIcon = ({ isOpen }: { isOpen: boolean }) => {
  return (
    <div className={`web3authn-profile-dropdown-avatar ${isOpen ? 'expanded' : 'shrunk'}`}>
      {isOpen ? (
        // Avatar SVG when open
        <svg width="18" height="18" viewBox="0 0 16 16" className="web3authn-profile-dropdown-avatar-icon">
          {/* Head circle */}
          <circle cx="8" cy="5" r="3"
            fill={OUTLINE_COLOR}
            stroke={OUTLINE_COLOR}
            strokeWidth="1"
          />
          {/* Body shape - semicircle */}
          <path d="M1.5 16 A 6.25 6.25 0 0 1 14.5 16 L 14.5 16 L 1.5 16 Z"
            fill={OUTLINE_COLOR}
            stroke={OUTLINE_COLOR}
            strokeWidth="0"
          />
        </svg>
      ) : (
        // Gear SVG when closed with rotation and fade animation
        <svg
          width="24"
          height="24"
          viewBox="0 0 24 24"
          fill="none"
          stroke={OUTLINE_COLOR}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="web3authn-profile-dropdown-gear-icon"
          style={{
            animation: 'web3authn-gearRotateIn 1s ease-out',
            transformOrigin: 'center',
            transition: 'transform 0.5s ease',
          }}
        >
          <circle cx="12" cy="12" r="3"/>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
        </svg>
      )}
    </div>
  );
};