"use client";

import { OnboardingStepData } from "./OnboardingFlow";

interface ProgressIndicatorProps {
  steps: OnboardingStepData[];
  currentStep: number;
  completedSteps: string[];
}

export default function ProgressIndicator({ 
  steps, 
  currentStep, 
  completedSteps 
}: ProgressIndicatorProps): JSX.Element {
  
  const getStepStatus = (stepIndex: number, stepId: string): 'completed' | 'current' | 'upcoming' => {
    if (completedSteps.includes(stepId)) return 'completed';
    if (stepIndex === currentStep) return 'current';
    return 'upcoming';
  };

  const getStepIcon = (status: 'completed' | 'current' | 'upcoming', stepIndex: number): JSX.Element => {
    switch (status) {
      case 'completed':
        return (
          <div className="w-10 h-10 bg-green-600 rounded-full flex items-center justify-center">
            <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
            </svg>
          </div>
        );
      case 'current':
        return (
          <div className="w-10 h-10 bg-purple-600 rounded-full flex items-center justify-center ring-4 ring-purple-600 ring-opacity-30">
            <span className="text-white font-semibold text-sm">{stepIndex + 1}</span>
          </div>
        );
      case 'upcoming':
        return (
          <div className="w-10 h-10 bg-gray-700 border-2 border-gray-600 rounded-full flex items-center justify-center">
            <span className="text-gray-400 font-semibold text-sm">{stepIndex + 1}</span>
          </div>
        );
    }
  };

  const getConnectorClass = (stepIndex: number): string => {
    if (stepIndex === steps.length - 1) return "hidden"; // Hide connector after last step
    
    const nextStepCompleted = completedSteps.includes(steps[stepIndex + 1].id);
    const currentStepCompleted = completedSteps.includes(steps[stepIndex].id);
    
    if (currentStepCompleted) {
      return "bg-green-600";
    } else if (stepIndex < currentStep) {
      return "bg-purple-600";
    } else {
      return "bg-gray-700";
    }
  };

  return (
    <div className="relative">
      {/* Progress bar background */}
      <div className="absolute top-5 left-5 right-5 h-0.5 bg-gray-700"></div>
      
      {/* Progress bar fill */}
      <div 
        className="absolute top-5 left-5 h-0.5 bg-purple-600 transition-all duration-500"
        style={{ 
          width: `calc(${(currentStep / (steps.length - 1)) * 100}% - 20px)`
        }}
      ></div>

      {/* Steps */}
      <ol className="flex items-center justify-between">
        {steps.map((step, index) => {
          const status = getStepStatus(index, step.id);
          
          return (
            <li key={step.id} className="flex flex-col items-center relative">
              {/* Step icon */}
              {getStepIcon(status, index)}
              
              {/* Step label */}
              <div className="mt-3 text-center max-w-32">
                <div className={`text-sm font-medium ${
                  status === 'current' ? 'text-purple-400' :
                  status === 'completed' ? 'text-green-400' :
                  'text-gray-500'
                }`}>
                  {step.title}
                </div>
                {step.optional && (
                  <span className="text-xs text-gray-500 mt-1">(Optional)</span>
                )}
              </div>
            </li>
          );
        })}
      </ol>

      {/* Completion message */}
      {completedSteps.length === steps.length && (
        <div className="mt-6 text-center">
          <div className="inline-flex items-center px-4 py-2 bg-green-900 border border-green-700 rounded-lg">
            <svg className="w-5 h-5 text-green-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <span className="text-green-300 text-sm font-medium">
              Onboarding Complete!
            </span>
          </div>
        </div>
      )}
    </div>
  );
}