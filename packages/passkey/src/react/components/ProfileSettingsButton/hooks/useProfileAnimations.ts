import { useEffect, useRef } from 'react';
import { animate, stagger } from 'animejs';
import type { ProfileStateRefs, ProfileDimensions, ProfileAnimationConfig } from '../types';

const ANIMATION_CONFIGS = {
  container: {
    // Match .web3authn-profile-dropdown-avatar.shrunk CSS animiation timings
    open: { duration: 100, easing: 'outElastic(0.5, .4)' },
    close: { duration: 100, delay: 0, easing: 'inOutBack(0.8)' },
  },
  dropdown: {
    show: { duration: 100, delay: 0 },
    hide: { duration: 100, delay: 0 },
  },
  menuItems: {
    in: { duration: 150, easing: 'outBack(0.8)', staggerDelay: 0 },
    out: { duration: 150, easing: 'inBack(0.8)', staggerDelay: 0 },
  },
} as const;

interface UseProfileAnimationsProps {
  isOpen: boolean;
  refs: ProfileStateRefs;
  openDimensions: ProfileDimensions;
  closedDimensions: ProfileDimensions;
}

export const useProfileAnimations = ({
  isOpen,
  refs,
  openDimensions,
  closedDimensions,
}: UseProfileAnimationsProps) => {
  // Store latest dimensions in refs to avoid re-triggering animations
  const dimensionsRef = useRef({ openDimensions, closedDimensions });
  dimensionsRef.current = { openDimensions, closedDimensions };

  // Track the current animation state to prevent re-applying on re-renders
  const animationStateRef = useRef<boolean | null>(null);

    useEffect(() => {
    // Only animate if isOpen state has actually changed
    if (animationStateRef.current === isOpen) {
      return;
    }

    animationStateRef.current = isOpen;

    const { buttonRef, dropdownRef, menuItemsRef } = refs;

    if (!buttonRef.current || !dropdownRef.current) return;

    // Get current dimensions from ref to avoid stale closures
    const { openDimensions: currentOpenDimensions, closedDimensions: currentClosedDimensions } = dimensionsRef.current;

    if (isOpen) {
      // Opening animation sequence
      requestAnimationFrame(() => {
        if (!buttonRef.current) return;

        const currentWidth = buttonRef.current.offsetWidth;
        const currentHeight = buttonRef.current.offsetHeight;

        // Morph container size with elastic bounce
        animate(buttonRef.current, {
          width: [currentWidth, currentOpenDimensions.width],
          height: [currentHeight, currentOpenDimensions.height],
          duration: ANIMATION_CONFIGS.container.open.duration,
          easing: ANIMATION_CONFIGS.container.open.easing,
        });

        // Show dropdown content
        if (dropdownRef.current) {
          animate(dropdownRef.current, {
            opacity: [0, 1],
            visibility: 'visible',
            duration: ANIMATION_CONFIGS.dropdown.show.duration,
            delay: ANIMATION_CONFIGS.dropdown.show.delay,
          });
        }

        // Staggered menu items animation with bounce
        const menuItems = menuItemsRef.current.filter(item => item !== null);
        if (menuItems.length > 0) {
          // Reset initial state for all items
          menuItems.forEach(item => {
            if (item) {
              animate(item, {
                opacity: 0,
                translateY: 20,
                scale: 0.8,
                duration: 0,
              });
            }
              });

              // Staggered slide-in animation
          animate(menuItems, {
                opacity: [0, 1],
                translateY: [20, 0],
            scale: [0.8, 1],
                duration: ANIMATION_CONFIGS.menuItems.in.duration,
            easing: ANIMATION_CONFIGS.menuItems.in.easing,
            delay: stagger(ANIMATION_CONFIGS.menuItems.in.staggerDelay, { from: 'first' }),
          });
        }
      });
    } else {
      // Closing animation sequence
      const menuItems = menuItemsRef.current.filter(item => item !== null);

      // Animate menu items out first with stagger
      if (menuItems.length > 0) {
        animate(menuItems, {
          opacity: [1, 0],
          translateY: [0, -20],
          scale: [1, 0.8],
              duration: ANIMATION_CONFIGS.menuItems.out.duration,
          easing: ANIMATION_CONFIGS.menuItems.out.easing,
          delay: stagger(ANIMATION_CONFIGS.menuItems.out.staggerDelay, { from: 'last' }),
        });
      }

      // Hide dropdown content
      if (dropdownRef.current) {
        animate(dropdownRef.current, {
          opacity: [1, 0],
          visibility: 'hidden',
          duration: ANIMATION_CONFIGS.dropdown.hide.duration,
          delay: ANIMATION_CONFIGS.dropdown.hide.delay,
        });
      }

      // Shrink container back to closed size
      const currentWidth = buttonRef.current.offsetWidth;
      const currentHeight = buttonRef.current.offsetHeight;

      animate(buttonRef.current, {
        width: [currentWidth, currentClosedDimensions.width],
        height: [currentHeight, currentClosedDimensions.height],
        duration: ANIMATION_CONFIGS.container.close.duration,
        delay: ANIMATION_CONFIGS.container.close.delay,
        easing: ANIMATION_CONFIGS.container.close.easing,
      });
    }
  }, [isOpen, refs]); // Only trigger on isOpen or refs changes, not dimensions

  return {
    animationConfigs: ANIMATION_CONFIGS,
  };
};