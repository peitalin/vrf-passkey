export const AvatarIcon = ({ isOpen }: { isOpen: boolean }) => {
  return (
    <div className={`profile-dropdown-avatar ${isOpen ? 'expanded' : 'shrunk'}`}>
        <svg width="18" height="18" viewBox="0 0 16 16" className="profile-dropdown-avatar-icon">
            <path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM6 10.5a5 5 0 0 0-5 5 1.5 1.5 0 0 0 1.5 1.5h11a1.5 1.5 0 0 0 1.5-1.5 5 5 0 0 0-5-5H6Z" fill="currentColor"/>
        </svg>
    </div>
  );
};