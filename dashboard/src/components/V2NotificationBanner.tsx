"use client";

import { useEffect } from 'react';
import useBannerDismissal from '@/hooks/useBannerDismissal';

export default function V2NotificationBanner() {
  const { isDismissed, dismissBanner } = useBannerDismissal('scanner_v2');

  // Don't render if dismissed
  if (isDismissed) {
    return null;
  }

  return (
    <div className="bg-gradient-to-r from-green-500/10 via-green-400/10 to-emerald-500/10 border-b border-green-500/20">
      <div className="max-w-7xl mx-auto px-4 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-start gap-3">
            {/* Enhancement icon */}
            <div className="flex-shrink-0 mt-0.5">
              <svg 
                className="w-5 h-5 text-green-400" 
                fill="none" 
                stroke="currentColor" 
                viewBox="0 0 24 24"
              >
                <path 
                  strokeLinecap="round" 
                  strokeLinejoin="round" 
                  strokeWidth={2} 
                  d="M13 10V3L4 14h7v7l9-11h-7z" 
                />
              </svg>
            </div>
            
            {/* Banner content */}
            <div className="flex-1">
              <h3 className="text-sm font-semibold text-green-400 mb-1">
                Enhanced Scanner Now Available!
              </h3>
              <p className="text-xs text-gray-300 leading-relaxed">
                Our new scanner reduces false positives by 85% with context-aware analysis, 
                confidence scoring, and improved threat detection. All new scans automatically use the enhanced scanner.
              </p>
              
              {/* Links */}
              <div className="flex items-center gap-4 mt-2">
                <a 
                  href="/docs/scanner-v2" 
                  className="text-xs text-green-400 hover:text-green-300 underline font-medium transition-colors"
                >
                  Learn about improvements →
                </a>
                <a 
                  href="/docs/changelog" 
                  className="text-xs text-gray-400 hover:text-gray-300 underline transition-colors"
                >
                  View changelog
                </a>
              </div>
            </div>
          </div>
          
          {/* Dismiss button */}
          <button
            onClick={dismissBanner}
            className="flex-shrink-0 ml-4 p-1.5 rounded-lg hover:bg-gray-800/50 transition-colors group"
            aria-label="Dismiss banner"
          >
            <svg 
              className="w-4 h-4 text-gray-500 group-hover:text-gray-300 transition-colors" 
              fill="none" 
              stroke="currentColor" 
              viewBox="0 0 24 24"
            >
              <path 
                strokeLinecap="round" 
                strokeLinejoin="round" 
                strokeWidth={2} 
                d="M6 18L18 6M6 6l12 12" 
              />
            </svg>
          </button>
        </div>
      </div>
    </div>
  );
}