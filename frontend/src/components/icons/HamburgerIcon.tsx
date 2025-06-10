import React, { useRef, useEffect } from 'react';
import { animate } from 'animejs';

interface HamburgerIconProps {
	username: string | null;
	className?: string;
	isOpen?: boolean;
	color?: string;
}

export const HamburgerIcon: React.FC<HamburgerIconProps> = ({ username, className, isOpen = false, color }) => {
	const topBarRef = useRef<SVGRectElement>(null);
	const middleBarRef = useRef<SVGRectElement>(null);
	const bottomBarRef = useRef<SVGRectElement>(null);
	const usernameRef = useRef<HTMLSpanElement>(null);

	useEffect(() => {
		if (!topBarRef.current || !middleBarRef.current || !bottomBarRef.current || !usernameRef.current) return;

		if (isOpen) {
			// Transform to X
			animate(topBarRef.current, {
				rotate: 45,
				translateY: 4,
				duration: 300,
				ease: 'outCubic'
			});

			animate(middleBarRef.current, {
				opacity: 0,
				scale: 0,
				duration: 200,
				ease: 'outQuad'
			});

			animate(bottomBarRef.current, {
				rotate: -45,
				translateY: -4,
				duration: 300,
				ease: 'outCubic'
			});

			// Hide username
			animate(usernameRef.current, {
				opacity: 0,
				scale: 0.9,
				width: 0,
				marginLeft: 0,
				duration: 200,
				ease: 'outQuad'
			});
		} else {
			// Transform back to hamburger
			animate(topBarRef.current, {
				rotate: 0,
				translateY: 0,
				duration: 300,
				ease: 'outCubic'
			});

			animate(middleBarRef.current, {
				opacity: 1,
				scale: 1,
				duration: 200,
				delay: 100,
				ease: 'outQuad'
			});

			animate(bottomBarRef.current, {
				rotate: 0,
				translateY: 0,
				duration: 300,
				ease: 'outCubic'
			});

			// Show username
			animate(usernameRef.current, {
				opacity: 1,
				scale: 1,
				width: 'auto',
				marginLeft: 12,
				duration: 200,
				delay: 150,
				ease: 'outBack(1.2)'
			});
		}
	}, [isOpen]);

	return (
		<div className="profile-button-trigger" style={{ color: color }}>
			<svg
				width="18"
				height="18"
				viewBox="0 0 18 18"
				className="profile-button-icon"
			>
				<rect
					ref={topBarRef}
					x="2"
					y="4"
					width="14"
					height="2"
					rx="1"
					fill={color}
					style={{ transformOrigin: 'center', transition: 'fill 0.2s ease' }}
				/>
				<rect
					ref={middleBarRef}
					x="2"
					y="8"
					width="14"
					height="2"
					rx="1"
					fill={color}
					style={{ transformOrigin: 'center', transition: 'fill 0.2s ease' }}
				/>
				<rect
					ref={bottomBarRef}
					x="2"
					y="12"
					width="14"
					height="2"
					rx="1"
					fill={color}
					style={{ transformOrigin: 'center', transition: 'fill 0.2s ease' }}
				/>
			</svg>

			<span
				ref={usernameRef}
				className={`profile-button-username ${!username ? 'hidden' : ''}`}
				style={{ color: color, transition: 'color 0.2s ease' }}
			>
				{username || 'User'}
			</span>
		</div>
	);
};