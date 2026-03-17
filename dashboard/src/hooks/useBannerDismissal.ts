import { useState, useEffect, useCallback } from 'react';

interface UseBannerDismissalResult {
  isDismissed: boolean;
  dismissBanner: () => void;
}

export default function useBannerDismissal(bannerId: string): UseBannerDismissalResult {
  const [isDismissed, setIsDismissed] = useState(true); // Start with true to avoid flash
  
  const cookieName = `banner_dismissed_${bannerId}`;

  useEffect(() => {
    // Check if banner was previously dismissed
    const dismissed = getCookie(cookieName);
    setIsDismissed(dismissed === 'true');
  }, [cookieName]);

  const dismissBanner = useCallback(() => {
    setIsDismissed(true);
    setCookie(cookieName, 'true', 30); // Remember for 30 days
  }, [cookieName]);

  return {
    isDismissed,
    dismissBanner,
  };
}

// Cookie helper functions
function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop()?.split(';').shift() || null;
  return null;
}

function setCookie(name: string, value: string, days: number): void {
  if (typeof document === 'undefined') return;
  
  const expires = new Date();
  expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
  document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/`;
}