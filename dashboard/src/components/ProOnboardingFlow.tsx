"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";

interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  content: React.ReactNode;
  action?: {
    label: string;
    href?: string;
    onClick?: () => void;
  };
}

interface CreditBalance {
  current_balance: number;
  monthly_allocation: number;
}

export function ProOnboardingFlow(): JSX.Element {
  const router = useRouter();
  const [currentStep, setCurrentStep] = useState(0);
  const [creditBalance, setCreditBalance] = useState<CreditBalance | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCreditBalance();
  }, []);

  const fetchCreditBalance = async (): Promise<void> => {
    try {
      const response = await fetch('/api/v1/billing/credits/usage');
      if (response.ok) {
        const data = await response.json();
        setCreditBalance({
          current_balance: data.current_balance,
          monthly_allocation: data.monthly_allocation,
        });
      }
    } catch (err) {
      console.error('Failed to fetch credit balance:', err);
    } finally {
      setLoading(false);
    }
  };

  const completeOnboarding = (): void => {
    router.push('/pro?onboarded=true');
  };

  const steps: OnboardingStep[] = [
    {
      id: 'welcome',
      title: 'Welcome to Sigil Pro!',
      description: 'Transform your security scanner into an AI-powered consultant',
      content: (
        <div className="text-center space-y-6">
          <div className="w-20 h-20 mx-auto bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center">
            <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <div>
            <h2 className="text-2xl font-bold mb-3" style={{ color: 'var(--color-text-primary)' }}>
              You&apos;re now a Pro user!
            </h2>
            <p className="text-lg mb-4" style={{ color: 'var(--color-text-secondary)' }}>
              Get ready to experience AI-powered security analysis that goes beyond basic scanning.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-2xl mx-auto">
              <div className="p-4 rounded-lg bg-blue-500/10 border border-blue-500/20">
                <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center mb-2 mx-auto">
                  <svg className="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>Investigation</h3>
                <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>Deep threat analysis</p>
              </div>
              <div className="p-4 rounded-lg bg-green-500/10 border border-green-500/20">
                <div className="w-8 h-8 bg-green-500/20 rounded-lg flex items-center justify-center mb-2 mx-auto">
                  <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>Verification</h3>
                <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>False positive detection</p>
              </div>
              <div className="p-4 rounded-lg bg-purple-500/10 border border-purple-500/20">
                <div className="w-8 h-8 bg-purple-500/20 rounded-lg flex items-center justify-center mb-2 mx-auto">
                  <svg className="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                  </svg>
                </div>
                <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>Chat</h3>
                <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>Interactive assistant</p>
              </div>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'credits',
      title: 'Understanding AI Credits',
      description: 'Learn how the credit system works and track your usage',
      content: (
        <div className="space-y-6">
          <div className="text-center">
            <div className="w-16 h-16 mx-auto bg-gradient-to-br from-green-500 to-emerald-600 rounded-2xl flex items-center justify-center mb-4">
              <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1" />
              </svg>
            </div>
            <h2 className="text-xl font-bold mb-2" style={{ color: 'var(--color-text-primary)' }}>
              Your Monthly Allocation
            </h2>
            {loading ? (
              <div className="h-8 bg-gray-800 rounded w-32 mx-auto animate-pulse" />
            ) : creditBalance ? (
              <div className="text-center">
                <div className="text-3xl font-bold mb-1" style={{ color: 'var(--color-accent)' }}>
                  {creditBalance.current_balance.toLocaleString()}
                </div>
                <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
                  credits available of {creditBalance.monthly_allocation.toLocaleString()} monthly
                </p>
              </div>
            ) : (
              <div className="text-3xl font-bold mb-1" style={{ color: 'var(--color-accent)' }}>
                5,000
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-lg border border-gray-800">
              <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
                How Credits Work
              </h3>
              <ul className="space-y-2 text-sm" style={{ color: 'var(--color-text-secondary)' }}>
                <li className="flex items-start gap-2">
                  <span className="text-blue-400 mt-0.5">•</span>
                  Each AI operation uses credits
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-blue-400 mt-0.5">•</span>
                  Credits reset monthly
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-blue-400 mt-0.5">•</span>
                  Simple tasks use fewer credits
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-blue-400 mt-0.5">•</span>
                  Complex analysis uses more
                </li>
              </ul>
            </div>
            <div className="p-4 rounded-lg border border-gray-800">
              <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
                Credit Usage Examples
              </h3>
              <ul className="space-y-2 text-sm" style={{ color: 'var(--color-text-secondary)' }}>
                <li className="flex items-center justify-between">
                  <span>Quick investigation</span>
                  <span className="text-yellow-400 font-mono">2-5 credits</span>
                </li>
                <li className="flex items-center justify-between">
                  <span>False positive check</span>
                  <span className="text-yellow-400 font-mono">1-3 credits</span>
                </li>
                <li className="flex items-center justify-between">
                  <span>Attack chain trace</span>
                  <span className="text-yellow-400 font-mono">8-12 credits</span>
                </li>
                <li className="flex items-center justify-between">
                  <span>Interactive chat</span>
                  <span className="text-yellow-400 font-mono">1-2 credits</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'features',
      title: 'AI Features Overview',
      description: 'Discover how each AI feature can enhance your security analysis',
      content: (
        <div className="space-y-6">
          <div className="text-center mb-6">
            <h2 className="text-xl font-bold mb-2" style={{ color: 'var(--color-text-primary)' }}>
              Your New AI Toolkit
            </h2>
            <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
              These features are now available on all your scan results
            </p>
          </div>

          <div className="space-y-4">
            <div className="p-4 rounded-lg border border-blue-500/30 bg-blue-500/5">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center shrink-0">
                  <svg className="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <div className="flex-1">
                  <h3 className="text-base font-semibold mb-1" style={{ color: 'var(--color-text-primary)' }}>
                    Investigation Assistant
                  </h3>
                  <p className="text-sm mb-2" style={{ color: 'var(--color-text-secondary)' }}>
                    Get deep insights into security findings with AI-powered analysis that explains threats, 
                    traces attack chains, and provides actionable remediation steps.
                  </p>
                  <span className="text-xs px-2 py-1 bg-blue-500/10 text-blue-400 rounded">
                    Available on scan results
                  </span>
                </div>
              </div>
            </div>

            <div className="p-4 rounded-lg border border-green-500/30 bg-green-500/5">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center shrink-0">
                  <svg className="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <div className="flex-1">
                  <h3 className="text-base font-semibold mb-1" style={{ color: 'var(--color-text-primary)' }}>
                    False Positive Verification
                  </h3>
                  <p className="text-sm mb-2" style={{ color: 'var(--color-text-secondary)' }}>
                    Quickly determine if security findings are false positives using AI analysis of code context, 
                    reducing noise and helping you focus on real threats.
                  </p>
                  <span className="text-xs px-2 py-1 bg-green-500/10 text-green-400 rounded">
                    Click &quot;Verify&quot; on findings
                  </span>
                </div>
              </div>
            </div>

            <div className="p-4 rounded-lg border border-purple-500/30 bg-purple-500/5">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center shrink-0">
                  <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                  </svg>
                </div>
                <div className="flex-1">
                  <h3 className="text-base font-semibold mb-1" style={{ color: 'var(--color-text-primary)' }}>
                    Interactive Security Chat
                  </h3>
                  <p className="text-sm mb-2" style={{ color: 'var(--color-text-secondary)' }}>
                    Ask questions about your security findings and get instant answers. Chat with AI about 
                    specific vulnerabilities, remediation strategies, or general security concepts.
                  </p>
                  <span className="text-xs px-2 py-1 bg-purple-500/10 text-purple-400 rounded">
                    Available in scan details
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'first-scan',
      title: 'Ready for Your First AI Investigation',
      description: 'Let&apos;s set up your first scan to test the AI features',
      content: (
        <div className="text-center space-y-6">
          <div className="w-16 h-16 mx-auto bg-gradient-to-br from-orange-500 to-red-600 rounded-2xl flex items-center justify-center">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.103m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
          </div>
          <div>
            <h2 className="text-xl font-bold mb-3" style={{ color: 'var(--color-text-primary)' }}>
              You&apos;re All Set!
            </h2>
            <p className="text-lg mb-6" style={{ color: 'var(--color-text-secondary)' }}>
              Your AI features are active and ready to use. Run a scan to see the AI investigation tools in action.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-lg mx-auto">
              <div className="p-4 rounded-lg border border-gray-800 text-left">
                <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
                  Quick Start Options
                </h3>
                <ul className="space-y-1 text-sm" style={{ color: 'var(--color-text-secondary)' }}>
                  <li>• Scan an npm package</li>
                  <li>• Upload a code repository</li>
                  <li>• Check a GitHub repository</li>
                </ul>
              </div>
              <div className="p-4 rounded-lg border border-gray-800 text-left">
                <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
                  What to Look For
                </h3>
                <ul className="space-y-1 text-sm" style={{ color: 'var(--color-text-secondary)' }}>
                  <li>• &quot;Investigate&quot; buttons</li>
                  <li>• &quot;Verify&quot; false positive options</li>
                  <li>• Chat icon in scan details</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      ),
      action: {
        label: 'Start First Scan',
        href: '/scans?new=true'
      }
    }
  ];

  const currentStepData = steps[currentStep];

  return (
    <div className="min-h-screen bg-gray-900 py-8">
      <div className="max-w-4xl mx-auto px-4">
        {/* Progress */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
              Step {currentStep + 1} of {steps.length}
            </span>
            <span className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
              {Math.round(((currentStep + 1) / steps.length) * 100)}% complete
            </span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2">
            <div 
              className="h-2 rounded-full transition-all duration-300"
              style={{
                width: `${((currentStep + 1) / steps.length) * 100}%`,
                backgroundColor: 'var(--color-accent)',
              }}
            />
          </div>
        </div>

        {/* Step indicators */}
        <div className="flex justify-center mb-8">
          <div className="flex items-center space-x-4">
            {steps.map((step, index) => (
              <div key={step.id} className="flex items-center">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                  index <= currentStep 
                    ? 'bg-blue-600 text-white' 
                    : 'bg-gray-800 text-gray-400'
                }`}>
                  {index < currentStep ? (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    index + 1
                  )}
                </div>
                {index < steps.length - 1 && (
                  <div className={`w-8 h-0.5 ml-4 ${
                    index < currentStep ? 'bg-blue-600' : 'bg-gray-800'
                  }`} />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Current step */}
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-8">
            <h1 className="text-2xl md:text-3xl font-bold mb-3" style={{ color: 'var(--color-text-primary)' }}>
              {currentStepData.title}
            </h1>
            <p className="text-lg" style={{ color: 'var(--color-text-secondary)' }}>
              {currentStepData.description}
            </p>
          </div>

          <div className="card">
            <div className="card-body">
              {currentStepData.content}
            </div>
          </div>

          {/* Navigation */}
          <div className="flex justify-between mt-8">
            <button
              onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
              disabled={currentStep === 0}
              className={`btn-outline ${
                currentStep === 0 ? 'opacity-50 cursor-not-allowed' : ''
              }`}
            >
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
              Back
            </button>

            {currentStep === steps.length - 1 ? (
              <div className="space-x-3">
                <button
                  onClick={completeOnboarding}
                  className="btn-outline"
                >
                  Skip for Now
                </button>
                {currentStepData.action && (
                  <a
                    href={currentStepData.action.href}
                    className="btn-primary"
                    onClick={currentStepData.action.onClick}
                  >
                    {currentStepData.action.label}
                  </a>
                )}
              </div>
            ) : (
              <button
                onClick={() => setCurrentStep(Math.min(steps.length - 1, currentStep + 1))}
                className="btn-primary"
              >
                Next
                <svg className="w-4 h-4 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}