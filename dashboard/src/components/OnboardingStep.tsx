"use client";

import { OnboardingStepData } from "./OnboardingFlow";
import WelcomeStep from "./onboarding/WelcomeStep";
import ApiKeySetupStep from "./onboarding/ApiKeySetupStep";
import FirstScanStep from "./onboarding/FirstScanStep";
import InsightsGuideStep from "./onboarding/InsightsGuideStep";
import IntegrationsStep from "./onboarding/IntegrationsStep";
import CompletionStep from "./onboarding/CompletionStep";

export interface OnboardingStepProps {
  step: OnboardingStepData;
  stepNumber: number;
  totalSteps: number;
  onComplete: (stepId: string, data?: any) => void;
  onSkip: () => void;
  onPrevious: () => void;
  data: Record<string, any>;
  canGoPrevious: boolean;
  isLastStep: boolean;
}

// Step components map
const STEP_COMPONENTS: Record<string, React.ComponentType<OnboardingStepProps>> = {
  Welcome: WelcomeStep,
  ApiKeySetup: ApiKeySetupStep,
  FirstScan: FirstScanStep,
  InsightsGuide: InsightsGuideStep,
  Integrations: IntegrationsStep,
  Completion: CompletionStep,
};

export default function OnboardingStep(props: OnboardingStepProps): JSX.Element {
  const { step } = props;
  
  // Get the appropriate component for this step
  const StepComponent = STEP_COMPONENTS[step.component];
  
  if (!StepComponent) {
    return (
      <div className="max-w-2xl mx-auto">
        <div className="bg-red-900 border border-red-700 rounded-lg p-6">
          <h3 className="text-lg font-medium text-red-300 mb-2">
            Step Component Not Found
          </h3>
          <p className="text-red-400">
            The component "{step.component}" for step "{step.id}" was not found.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* Step Header */}
      <div className="mb-8 text-center">
        <div className="inline-flex items-center px-3 py-1 bg-purple-900 border border-purple-700 rounded-full text-sm text-purple-300 mb-3">
          Step {props.stepNumber} of {props.totalSteps}
          {step.optional && (
            <span className="ml-2 px-2 py-0.5 bg-purple-800 rounded text-xs">Optional</span>
          )}
        </div>
        <h2 className="text-3xl font-bold text-white mb-2">{step.title}</h2>
        <p className="text-lg text-gray-400">{step.description}</p>
      </div>

      {/* Step Content */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
        <StepComponent {...props} />
      </div>

      {/* Navigation */}
      <div className="mt-8 flex justify-between">
        <button
          onClick={props.onPrevious}
          disabled={!props.canGoPrevious}
          className={`px-6 py-2 rounded-lg font-medium transition-colors ${
            props.canGoPrevious
              ? "bg-gray-700 hover:bg-gray-600 text-gray-300"
              : "bg-gray-800 text-gray-500 cursor-not-allowed"
          }`}
        >
          Previous
        </button>

        <div className="flex space-x-3">
          {step.optional && (
            <button
              onClick={props.onSkip}
              className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg font-medium transition-colors"
            >
              Skip This Step
            </button>
          )}
        </div>
      </div>
    </div>
  );
}