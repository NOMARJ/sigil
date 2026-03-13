"use client";

import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { launchConfig } from "@/lib/launch-config";
import Link from "next/link";

interface UpgradeCTAProps {
  variant?: "banner" | "card" | "modal" | "inline";
  feature?: string;
  creditsNeeded?: number;
  currentBalance?: number;
  onClose?: () => void;
}

export default function UpgradeCTA({ 
  variant = "banner",
  feature = "interactive AI analysis",
  creditsNeeded,
  currentBalance = 0,
  onClose 
}: UpgradeCTAProps): JSX.Element {
  const [isDismissed, setIsDismissed] = useState(false);
  const constrainedFeatures = launchConfig.getConstrainedLaunchFeatures();

  const handleDismiss = (): void => {
    setIsDismissed(true);
    onClose?.();
  };

  if (isDismissed) return <></>;

  const coreProFeatures = [
    "AI-powered finding investigation",
    "False positive verification", 
    "Interactive security guidance",
    "5,000 monthly credits",
    "Smart model routing",
    "Expert explanations"
  ];

  if (variant === "modal") {
    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
        <div className="bg-gray-900 border border-gray-700 rounded-lg max-w-lg w-full p-6">
          <div className="text-center">
            <div className="w-12 h-12 mx-auto mb-4 bg-brand-600/20 rounded-full flex items-center justify-center">
              <svg className="w-6 h-6 text-brand-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                      d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <h3 className="text-xl font-semibold text-gray-200 mb-2">
              Transform Sigil into Your Security Consultant
            </h3>
            <p className="text-sm text-gray-400 mb-4">
              Turn scan results into actionable intelligence with AI-powered investigation and guidance.
              {creditsNeeded && ` You need ${creditsNeeded} credits, but only have ${currentBalance}.`}
            </p>
            
            <div className="space-y-3 mb-6">
              <div className="text-sm text-gray-300 font-medium">Core Pro Features:</div>
              <div className="grid grid-cols-1 gap-2 text-left">
                {coreProFeatures.map((feature, index) => (
                  <div key={index} className="flex items-start gap-2 text-sm">
                    <svg className="w-4 h-4 text-green-400 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                    <span className="text-gray-300">{feature}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex gap-3">
              <Button variant="ghost" onClick={handleDismiss} className="flex-1 text-gray-400">
                Maybe Later
              </Button>
              <Link href="/upgrade" className="flex-1">
                <Button className="w-full bg-brand-600 hover:bg-brand-700">
                  Upgrade to Pro
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (variant === "card") {
    return (
      <div className="card bg-gradient-to-br from-purple-500/5 to-pink-500/5 border-purple-500/20">
        <div className="card-body">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-gray-200 mb-2">
                Upgrade to Pro for Advanced AI Detection
              </h3>
              <p className="text-sm text-gray-400 mb-4">
                Get zero-day detection, threat correlation, and natural language explanations
                powered by Claude AI.
              </p>
              <div className="flex flex-wrap gap-2 mb-4">
                {coreProFeatures.slice(0, 3).map((feature, index) => (
                  <span key={index} className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
                    {feature}
                  </span>
                ))}
              </div>
              <div className="flex items-center gap-3">
                <button className="btn-primary">
                  Start 14-Day Trial
                </button>
                <span className="text-sm text-gray-400">
                  $29/month after trial
                </span>
              </div>
            </div>

            <button
              onClick={handleDismiss}
              className="text-gray-500 hover:text-gray-300 transition-colors flex-shrink-0"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Banner variant (default)
  return (
    <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/20 rounded-lg p-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          {/* Pro icon */}
          <div className="flex-shrink-0 w-10 h-10 bg-gradient-to-r from-purple-500 to-pink-500 rounded-full flex items-center justify-center">
            <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
              <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
            </svg>
          </div>

          {/* Text content */}
          <div className="flex-1">
            <h3 className="text-sm font-semibold text-purple-400 mb-1">
              Unlock AI-Powered Security Analysis
            </h3>
            <p className="text-xs text-gray-400">
              Get zero-day detection, threat correlation, and natural language explanations. 
              <strong className="text-purple-300"> 14-day free trial</strong>
            </p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3">
          <button className="btn-primary text-sm">
            Upgrade to Pro
          </button>
          <button
            onClick={handleDismiss}
            className="text-gray-500 hover:text-gray-300 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  );
}

// Specialized CTA for specific use cases
interface FeatureLockedCTAProps {
  featureName: string;
  description: string;
}

export function FeatureLockedCTA({ 
  featureName, 
  description 
}: FeatureLockedCTAProps): JSX.Element {
  return (
    <div className="text-center py-12 px-6">
      {/* Lock icon */}
      <div className="w-16 h-16 bg-purple-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
        <svg className="w-8 h-8 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>

      <h3 className="text-lg font-semibold text-gray-200 mb-2">
        {featureName}
      </h3>
      
      <p className="text-sm text-gray-400 mb-6 max-w-md mx-auto">
        {description}
      </p>

      <div className="space-y-3">
        <button className="btn-primary">
          Upgrade to Pro - $29/month
        </button>
        <p className="text-xs text-gray-500">
          14-day free trial • Full access to AI detection
        </p>
      </div>
    </div>
  );
}