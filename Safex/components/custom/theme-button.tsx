import React, { useState, useEffect } from 'react';
import ClickLight from './click-light';
import ClickDarkNew from './click-dark-new';

const ThemeButton = () => {
  const [mounted, setMounted] = useState(false);
  const [isDarkTheme, setIsDarkTheme] = useState(false);

  useEffect(() => {
    setMounted(true);
    
    // Check if dark theme is active
    const isDark = document.documentElement.classList.contains('dark');
    setIsDarkTheme(isDark);

    // Set up observer to detect theme changes
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (
          mutation.attributeName === 'class' &&
          mutation.target === document.documentElement
        ) {
          const isDark = document.documentElement.classList.contains('dark');
          setIsDarkTheme(isDark);
        }
      });
    });

    observer.observe(document.documentElement, { attributes: true });

    return () => {
      observer.disconnect();
    };
  }, []);

  // Don't render anything during SSR or before mounting
  if (!mounted) return null;

  // Only render the appropriate button after mounting (client-side only)
  return isDarkTheme ? <ClickDarkNew /> : <ClickLight />;
};

export default ThemeButton; 