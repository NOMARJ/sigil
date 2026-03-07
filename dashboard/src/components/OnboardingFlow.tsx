"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useUser } from "@auth0/nextjs-auth0/client";
import OnboardingStep from "./OnboardingStep";
import ProgressIndicator from "./ProgressIndicator";

// Define onboarding steps
export interface OnboardingStepData {
  id: string;
  title: string;
  description: string;
  component: string;
  optional?: boolean;
  completed?: boolean;
}

const ONBOARDING_STEPS: OnboardingStepData[] = [
  {
    id: "welcome",
    title: "Welcome to Sigil Pro",
    description: "AI-powered security scanning for your code",
    component: "Welcome"
  },
  {
    id: "api-key",
    title: "Setup API Key",
    description: "Connect CLI to your Pro account",
    component: "ApiKeySetup"
  },
  {
    id: "first-scan",
    title: "First AI Scan",
    description: "Run LLM-powered threat analysis",
    component: "FirstScan"
  },
  {
    id: "insights",
    title: "Understanding AI Insights",
    description: "Interpret AI threat analysis results",
    component: "InsightsGuide"
  },
  {
    id: "integrations",
    title: "Optional Integrations",
    description: "Connect tools and notifications",
    component: "Integrations",
    optional: true
  },
  {
    id: "complete",
    title: "You're All Set!",
    description: "Start scanning with confidence",
    component: "Completion"
  }
];

// Local storage key for persisting progress
const ONBOARDING_STORAGE_KEY = "sigil_pro_onboarding_progress";

export default function OnboardingFlow(): JSX.Element {
  const { user } = useUser();
  const router = useRouter();
  const [currentStep, setCurrentStep] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<string[]>([]);
  const [onboardingData, setOnboardingData] = useState<Record<string, any>>({});
  const [isLoading, setIsLoading] = useState(true);

  // Load progress from localStorage on mount
  useEffect(() => {
    const savedProgress = localStorage.getItem(ONBOARDING_STORAGE_KEY);
    if (savedProgress) {
      try {
        const { currentStep: savedStep, completedSteps: savedCompleted, data } = JSON.parse(savedProgress);
        setCurrentStep(savedStep || 0);
        setCompletedSteps(savedCompleted || []);
        setOnboardingData(data || {});
      } catch (error) {
        console.error("Error loading onboarding progress:", error);
      }
    }
    setIsLoading(false);
  }, []);

  // Save progress to localStorage whenever state changes
  useEffect(() => {
    if (!isLoading) {
      const progressData = {
        currentStep,
        completedSteps,
        data: onboardingData,
        lastUpdated: new Date().toISOString()
      };
      localStorage.setItem(ONBOARDING_STORAGE_KEY, JSON.stringify(progressData));
    }
  }, [currentStep, completedSteps, onboardingData, isLoading]);

  // Track onboarding progress with backend
  const trackStepCompletion = async (stepId: string, data: any): Promise<void> => {
    try {
      // This would call the backend onboarding service
      await fetch("/api/onboarding/complete-step", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          step_id: stepId,
          user_id: user?.sub,
          data: data
        })
      });
    } catch (error) {
      console.error("Error tracking step completion:", error);
    }
  };

  // Handle step completion
  const handleStepComplete = async (stepId: string, data: any = {}): Promise<void> => {
    // Update completed steps
    if (!completedSteps.includes(stepId)) {
      setCompletedSteps([...completedSteps, stepId]);
    }

    // Merge step data
    setOnboardingData(prevData => ({
      ...prevData,
      [stepId]: data
    }));

    // Track with backend
    await trackStepCompletion(stepId, data);

    // Move to next step or complete onboarding
    if (currentStep < ONBOARDING_STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      // Complete onboarding
      await completeOnboarding();
    }
  };

  // Skip optional step
  const handleSkipStep = (): void => {
    const currentStepData = ONBOARDING_STEPS[currentStep];
    if (currentStepData.optional) {
      if (currentStep < ONBOARDING_STEPS.length - 1) {
        setCurrentStep(currentStep + 1);
      } else {
        completeOnboarding();
      }
    }
  };

  // Go to previous step
  const handlePreviousStep = (): void => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  // Complete the entire onboarding flow
  const completeOnboarding = async (): Promise<void> => {
    try {
      // Mark onboarding as complete in backend
      await fetch("/api/onboarding/complete", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          user_id: user?.sub,
          completion_data: onboardingData
        })
      });

      // Clear localStorage
      localStorage.removeItem(ONBOARDING_STORAGE_KEY);

      // Redirect to Pro dashboard
      router.push("/pro?onboarded=true");
    } catch (error) {
      console.error("Error completing onboarding:", error);
      // Still redirect on error
      router.push("/pro");
    }
  };

  // Calculate progress percentage
  const progressPercentage = Math.round((completedSteps.length / ONBOARDING_STEPS.length) * 100);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-purple-600"></div>
      </div>
    );
  }

  const currentStepData = ONBOARDING_STEPS[currentStep];

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <div className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-4xl mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="w-8 h-8 bg-purple-600 rounded-lg flex items-center justify-center">
                <span className="text-white font-bold text-sm">S</span>
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">Sigil Pro Onboarding</h1>
                <p className="text-sm text-gray-400">Get started with AI-powered threat detection</p>
              </div>
            </div>
            <div className="text-right">
              <div className="text-2xl font-bold text-purple-400">{progressPercentage}%</div>
              <div className="text-xs text-gray-500">Complete</div>
            </div>
          </div>
        </div>
      </div>

      {/* Progress Indicator */}
      <div className="max-w-4xl mx-auto px-4 py-8">
        <ProgressIndicator 
          steps={ONBOARDING_STEPS}
          currentStep={currentStep}
          completedSteps={completedSteps}
        />
      </div>

      {/* Current Step */}
      <div className="max-w-4xl mx-auto px-4 pb-8">
        <OnboardingStep
          step={currentStepData}
          stepNumber={currentStep + 1}
          totalSteps={ONBOARDING_STEPS.length}
          onComplete={handleStepComplete}
          onSkip={handleSkipStep}
          onPrevious={handlePreviousStep}
          data={onboardingData[currentStepData.id] || {}}
          canGoPrevious={currentStep > 0}
          isLastStep={currentStep === ONBOARDING_STEPS.length - 1}
        />
      </div>
    </div>
  );
}