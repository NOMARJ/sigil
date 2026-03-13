"use client";

import React, { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Finding, CreditInfo } from "@/lib/types";

interface FirstInvestigationGuideProps {
  finding: Finding;
  creditInfo: CreditInfo;
  onStartInvestigation: () => void;
  onDismiss: () => void;
}

export default function FirstInvestigationGuide({
  finding,
  creditInfo,
  onStartInvestigation,
  onDismiss
}: FirstInvestigationGuideProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    // Check if user has seen this guide before
    const hasSeenGuide = localStorage.getItem('sigil-first-investigation-guide');
    if (!hasSeenGuide) {
      setIsVisible(true);
    }
  }, []);

  const handleComplete = () => {
    localStorage.setItem('sigil-first-investigation-guide', 'true');
    setIsVisible(false);
    onStartInvestigation();
  };

  const handleSkip = () => {
    localStorage.setItem('sigil-first-investigation-guide', 'true');
    setIsVisible(false);
    onDismiss();
  };

  if (!isVisible) return null;

  const steps = [
    {
      title: "Welcome to AI-Powered Security Analysis",
      description: "You're about to transform Sigil from a scanner into your personal security consultant.",
      icon: (
        <svg className="w-8 h-8 text-brand-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      )
    },
    {
      title: "Investigate Security Findings",
      description: "Instead of cryptic alerts, get detailed explanations of what each threat means and how serious it is.",
      icon: (
        <svg className="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      )
    },
    {
      title: "Verify False Positives Fast",
      description: "Quickly determine if findings are real threats or harmless code patterns in your specific context.",
      icon: (
        <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      )
    },
    {
      title: "Start Your First Investigation",
      description: `Let's investigate "${finding.title}" to see how AI analysis works. This will cost ${creditInfo.costs.quick_investigation} credits.`,
      icon: (
        <svg className="w-8 h-8 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
        </svg>
      )
    }
  ];

  const currentStepData = steps[currentStep];

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-lg max-w-md w-full p-6">
        <div className="text-center">
          {/* Step indicator */}
          <div className="flex justify-center mb-6">
            {steps.map((_, index) => (
              <div key={index} className="flex items-center">
                <div className={`w-3 h-3 rounded-full ${
                  index === currentStep 
                    ? 'bg-brand-500' 
                    : index < currentStep 
                    ? 'bg-green-500' 
                    : 'bg-gray-600'
                }`} />
                {index < steps.length - 1 && (
                  <div className={`w-8 h-px ${
                    index < currentStep ? 'bg-green-500' : 'bg-gray-600'
                  }`} />
                )}
              </div>
            ))}
          </div>

          {/* Step content */}
          <div className="mb-6">
            <div className="w-16 h-16 mx-auto mb-4 bg-gray-800/50 rounded-full flex items-center justify-center">
              {currentStepData.icon}
            </div>
            
            <h3 className="text-lg font-semibold text-gray-200 mb-3">
              {currentStepData.title}
            </h3>
            
            <p className="text-sm text-gray-400 leading-relaxed">
              {currentStepData.description}
            </p>
          </div>

          {/* Trust disclaimer on first step */}
          {currentStep === 0 && (
            <div className="mb-6 p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
              <div className="flex items-start gap-2">
                <svg className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                        d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div className="text-xs text-blue-300 text-left">
                  <div className="font-medium mb-1">AI Analysis for Guidance Only</div>
                  <div className="text-blue-400">
                    AI responses supplement, not replace, security review. Always verify findings independently.
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Navigation buttons */}
          <div className="flex gap-3">
            {currentStep === steps.length - 1 ? (
              <>
                <Button variant="ghost" onClick={handleSkip} className="flex-1 text-gray-400">
                  Skip Tutorial
                </Button>
                <Button 
                  onClick={handleComplete}
                  className="flex-1 bg-brand-600 hover:bg-brand-700"
                  disabled={creditInfo.balance < creditInfo.costs.quick_investigation}
                >
                  Start Investigation
                </Button>
              </>
            ) : (
              <>
                <Button variant="ghost" onClick={handleSkip} className="flex-1 text-gray-400">
                  Skip
                </Button>
                <Button 
                  onClick={() => setCurrentStep(currentStep + 1)}
                  className="flex-1"
                >
                  {currentStep === 0 ? "Get Started" : "Next"}
                </Button>
              </>
            )}
          </div>

          {/* Credits info on last step */}
          {currentStep === steps.length - 1 && (
            <div className="mt-4 text-xs text-gray-500">
              Balance: {creditInfo.balance} credits • Investigation costs {creditInfo.costs.quick_investigation} credits
            </div>
          )}
        </div>
      </div>
    </div>
  );
}