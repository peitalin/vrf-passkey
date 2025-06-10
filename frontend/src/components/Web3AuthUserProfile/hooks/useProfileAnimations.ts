import { useEffect } from 'react';
import { animate } from 'animejs';
import type { ProfileStateRefs, ProfileDimensions, ProfileAnimationConfig } from '../types';

const ANIMATION_CONFIGS = {
  container: {
    open: { duration: 250, ease: 'outQuart' },
    close: { duration: 200, delay: 60, ease: 'inOutCubic' },
  },
  dropdown: {
    show: { duration: 100, delay: 0 },
    hide: { duration: 100 },
  },
  menuItems: {
    in: { duration: 200, ease: 'outCubic', staggerDelay: 40, baseDelay: 120 },
    out: { duration: 100, ease: 'inQuad', staggerDelay: 15 },
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

    useEffect(() => {
    const { buttonRef, dropdownRef, menuItemsRef } = refs;

    if (!buttonRef.current || !dropdownRef.current) return;

    if (isOpen) {
      // Opening animation
      requestAnimationFrame(() => {
        if (!buttonRef.current) return;

        const currentWidth = buttonRef.current.offsetWidth;
        const currentHeight = buttonRef.current.offsetHeight;

        // Animate container expansion
        animate(buttonRef.current, {
          width: [currentWidth, openDimensions.width],
          height: [currentHeight, openDimensions.height],
          ...ANIMATION_CONFIGS.container.open,
        });

        // Show dropdown content
        animate(dropdownRef.current, {
          opacity: [0, 1],
          visibility: 'visible',
          ...ANIMATION_CONFIGS.dropdown.show,
        });

        // Staggered animation for menu items
        const menuItems = menuItemsRef.current.filter(item => item !== null);
        if (menuItems.length > 0) {
          menuItems.forEach((item, index) => {
            if (item) {
              // Reset initial state
              animate(item, {
                opacity: 0,
                translateY: 20,
                duration: 0,
              });

              // Staggered slide-in animation
              animate(item, {
                opacity: [0, 1],
                translateY: [20, 0],
                duration: ANIMATION_CONFIGS.menuItems.in.duration,
                delay: ANIMATION_CONFIGS.menuItems.in.baseDelay + (index * ANIMATION_CONFIGS.menuItems.in.staggerDelay),
                ease: ANIMATION_CONFIGS.menuItems.in.ease,
              });
            }
          });
        }
      });
    } else {
      // Closing animation
      const menuItems = menuItemsRef.current.filter(item => item !== null);

      // Animate menu items out first
      if (menuItems.length > 0) {
        menuItems.forEach((item, index) => {
          if (item) {
            animate(item, {
              opacity: 0,
              translateY: -10,
              duration: ANIMATION_CONFIGS.menuItems.out.duration,
              delay: index * ANIMATION_CONFIGS.menuItems.out.staggerDelay,
              ease: ANIMATION_CONFIGS.menuItems.out.ease,
            });
          }
        });
      }

      // Hide dropdown content
      animate(dropdownRef.current, {
        opacity: 0,
        visibility: 'hidden',
        ...ANIMATION_CONFIGS.dropdown.hide,
      });

      // Animate container back to closed size
      const currentWidth = buttonRef.current.offsetWidth;
      const currentHeight = buttonRef.current.offsetHeight;

      animate(buttonRef.current, {
        width: [currentWidth, closedDimensions.width],
        height: [currentHeight, closedDimensions.height],
        ...ANIMATION_CONFIGS.container.close,
      });
    }
  }, [isOpen, refs, openDimensions, closedDimensions]);

  return {
    animationConfigs: ANIMATION_CONFIGS,
  };
};