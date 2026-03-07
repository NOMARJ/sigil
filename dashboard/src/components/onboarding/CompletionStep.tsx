"use client";

import { useState, useEffect } from "react";
import { OnboardingStepProps } from "../OnboardingStep";

export default function CompletionStep({ step, onComplete, data }: OnboardingStepProps): JSX.Element {
  const [showConfetti, setShowConfetti] = useState(false);

  useEffect(() => {
    setShowConfetti(true);
    const timer = setTimeout(() => setShowConfetti(false), 3000);
    return () => clearTimeout(timer);
  }, []);

  const handleGoToDashboard = (): void => {
    onComplete(step.id, {
      completedOnboarding: true,
      completionTimestamp: new Date().toISOString(),
      totalStepsCompleted: Object.keys(data).length
    });
  };

  // Calculate completion stats
  const apiKeyGenerated = !!data["api-key"]?.apiKey;
  const scanCompleted = !!data["first-scan"]?.scanCompleted;
  const insightsLearned = !!data["insights"]?.quizScore;
  const integrationsConfigured = data["integrations"]?.integrationsConfigured || 0;

  const completionStats = [
    { 
      label: "API Key Generated", 
      completed: apiKeyGenerated,
      icon: "🔑"
    },
    { 
      label: "First AI Scan", 
      completed: scanCompleted,
      icon: "🔍"
    },
    { 
      label: "Insights Training", 
      completed: insightsLearned,
      icon: "🧠"
    },
    { 
      label: "Integrations Setup", 
      completed: integrationsConfigured > 0,
      icon: "🔗",
      detail: integrationsConfigured > 0 ? `${integrationsConfigured} configured` : "None"
    }
  ];

  const nextSteps = [
    {
      title: "Run Your First Production Scan",
      description: "Scan your actual codebase with AI-powered threat detection",
      command: "sigil scan /path/to/your/project --pro",
      priority: "high"
    },
    {
      title: "Set Up Continuous Monitoring",
      description: "Configure automatic scanning for new dependencies",
      command: "sigil watch --enable",
      priority: "medium"
    },
    {
      title: "Review Security Policies",
      description: "Customize threat response and approval workflows",
      action: "dashboard-settings",
      priority: "medium"
    },
    {
      title: "Join the Community",
      description: "Get help and share insights with other Pro users",
      action: "community-link",
      priority: "low"
    }
  ];

  const resources = [
    {
      title: "Pro User Documentation",
      description: "Complete guide to AI-powered threat detection",
      url: "/docs/pro-features",
      icon: "📚"
    },
    {
      title: "CLI Reference",
      description: "All commands and options for the Sigil CLI",
      url: "/docs/cli-reference",
      icon: "⚡"
    },
    {
      title: "API Documentation",
      description: "Integrate Sigil Pro into your custom workflows",
      url: "/docs/api",
      icon: "🔧"
    },
    {
      title: "Community Support",
      description: "Get help from our team and community",
      url: "/support",
      icon: "💬"
    }
  ];

  return (
    <div className="p-8 relative overflow-hidden">
      {/* Confetti Effect */}
      {showConfetti && (
        <div className="absolute inset-0 pointer-events-none">
          {[...Array(20)].map((_, i) => (
            <div
              key={i}
              className="absolute animate-bounce"
              style={{
                left: `${Math.random() * 100}%`,
                animationDelay: `${Math.random() * 2}s`,
                animationDuration: `${2 + Math.random() * 2}s`
              }}
            >
              🎉
            </div>
          ))}
        </div>
      )}

      <div className="max-w-4xl mx-auto relative">
        {/* Celebration Header */}
        <div className="text-center mb-12">
          <div className="w-20 h-20 bg-gradient-to-r from-purple-600 to-purple-700 rounded-full flex items-center justify-center mx-auto mb-6">
            <svg className="w-10 h-10 text-white" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M6.267 3.455a3.066 3.066 0 001.745-.723 3.066 3.066 0 013.976 0 3.066 3.066 0 001.745.723 3.066 3.066 0 012.812 2.812c.051.643.304 1.254.723 1.745a3.066 3.066 0 010 3.976 3.066 3.066 0 00-.723 1.745 3.066 3.066 0 01-2.812 2.812 3.066 3.066 0 00-1.745.723 3.066 3.066 0 01-3.976 0 3.066 3.066 0 00-1.745-.723 3.066 3.066 0 01-2.812-2.812 3.066 3.066 0 00-.723-1.745 3.066 3.066 0 010-3.976 3.066 3.066 0 00.723-1.745 3.066 3.066 0 012.812-2.812zm7.44 5.252a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
          </div>
          
          <h2 className="text-3xl font-bold text-white mb-4">
            🎉 Welcome to Sigil Pro!
          </h2>
          <p className="text-xl text-gray-400 mb-2">
            You've successfully completed the onboarding and are ready to use AI-powered threat detection.
          </p>
          <div className="inline-flex items-center px-4 py-2 bg-green-900 border border-green-700 rounded-lg text-green-300 text-sm">
            <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            Onboarding Complete
          </div>
        </div>

        {/* Completion Summary */}
        <div className="grid md:grid-cols-2 gap-8 mb-12">
          {/* What You Accomplished */}
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">What You Accomplished</h3>
            <div className="space-y-3">
              {completionStats.map((stat, index) => (
                <div key={index} className="flex items-center">
                  <span className="text-2xl mr-3">{stat.icon}</span>
                  <div className="flex-1">
                    <span className={`font-medium ${
                      stat.completed ? "text-green-400" : "text-gray-400"
                    }`}>
                      {stat.label}
                    </span>
                    {stat.detail && (
                      <span className="text-sm text-gray-500 ml-2">({stat.detail})</span>
                    )}
                  </div>
                  {stat.completed ? (
                    <svg className="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                    </svg>
                  ) : (
                    <div className="w-5 h-5 rounded-full border border-gray-600"></div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Pro Features Unlocked */}
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Pro Features Unlocked</h3>
            <div className="space-y-3">
              <div className="flex items-center">
                <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center mr-3">
                  <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                  </svg>
                </div>
                <div>
                  <p className="text-white font-medium">Claude AI Analysis</p>
                  <p className="text-gray-400 text-sm">Advanced threat detection beyond rules</p>
                </div>
              </div>
              <div className="flex items-center">
                <div className="w-8 h-8 bg-green-600 rounded-lg flex items-center justify-center mr-3">
                  <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M12.316 3.051a1 1 0 01.633 1.265l-4 12a1 1 0 11-1.898-.632l4-12a1 1 0 011.265-.633zM5.707 6.293a1 1 0 010 1.414L3.414 10l2.293 2.293a1 1 0 11-1.414 1.414l-3-3a1 1 0 010-1.414l3-3a1 1 0 011.414 0zm8.586 0a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 11-1.414-1.414L16.586 10l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd" />
                  </svg>
                </div>
                <div>
                  <p className="text-white font-medium">Zero-Day Detection</p>
                  <p className="text-gray-400 text-sm">Catch novel attack patterns</p>
                </div>
              </div>
              <div className="flex items-center">
                <div className="w-8 h-8 bg-purple-600 rounded-lg flex items-center justify-center mr-3">
                  <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clipRule="evenodd" />
                  </svg>
                </div>
                <div>
                  <p className="text-white font-medium">Natural Language Insights</p>
                  <p className="text-gray-400 text-sm">AI explains threats in plain English</p>
                </div>
              </div>
              <div className="flex items-center">
                <div className="w-8 h-8 bg-yellow-600 rounded-lg flex items-center justify-center mr-3">
                  <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M18 8a6 6 0 01-7.743 5.743L10 14l-1 1-1 1H6v2H2v-4l4.257-4.257A6 6 0 1118 8zm-6-4a1 1 0 100 2 2 2 0 012 2 1 1 0 102 0 4 4 0 00-4-4z" clipRule="evenodd" />
                  </svg>
                </div>
                <div>
                  <p className="text-white font-medium">Obfuscation Detection</p>
                  <p className="text-gray-400 text-sm">Uncover hidden malicious code</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Next Steps */}
        <div className="mb-12">
          <h3 className="text-2xl font-bold text-white mb-6">Recommended Next Steps</h3>
          <div className="grid md:grid-cols-2 gap-4">
            {nextSteps.map((step, index) => (
              <div key={index} className={`border rounded-lg p-4 ${
                step.priority === "high" ? "border-red-500 bg-red-900 bg-opacity-20" :
                step.priority === "medium" ? "border-yellow-500 bg-yellow-900 bg-opacity-20" :
                "border-gray-600 bg-gray-800"
              }`}>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <h4 className="text-white font-semibold mb-2">{step.title}</h4>
                    <p className="text-gray-400 text-sm mb-3">{step.description}</p>
                    {step.command && (
                      <div className="bg-gray-800 border border-gray-600 rounded p-2">
                        <code className="text-green-400 font-mono text-sm">{step.command}</code>
                      </div>
                    )}
                  </div>
                  <span className={`text-xs font-medium px-2 py-1 rounded ${
                    step.priority === "high" ? "bg-red-600 text-white" :
                    step.priority === "medium" ? "bg-yellow-600 text-white" :
                    "bg-gray-600 text-gray-300"
                  }`}>
                    {step.priority.toUpperCase()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Quick Resources */}
        <div className="mb-12">
          <h3 className="text-2xl font-bold text-white mb-6">Quick Resources</h3>
          <div className="grid md:grid-cols-4 gap-4">
            {resources.map((resource, index) => (
              <a
                key={index}
                href={resource.url}
                className="block p-4 bg-gray-800 border border-gray-700 rounded-lg hover:border-purple-500 transition-colors group"
              >
                <div className="text-center">
                  <span className="text-2xl mb-2 block">{resource.icon}</span>
                  <h4 className="text-white font-medium mb-2 group-hover:text-purple-400">
                    {resource.title}
                  </h4>
                  <p className="text-gray-400 text-xs">{resource.description}</p>
                </div>
              </a>
            ))}
          </div>
        </div>

        {/* CTA */}
        <div className="text-center">
          <div className="bg-purple-900 bg-opacity-30 border border-purple-700 rounded-lg p-6 mb-6">
            <h4 className="text-lg font-semibold text-white mb-2">Ready to Start Protecting Your Code?</h4>
            <p className="text-purple-300 mb-4">
              Head to your Pro dashboard to start running AI-powered scans on your actual projects.
            </p>
          </div>
          
          <button
            onClick={handleGoToDashboard}
            className="px-8 py-4 bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white rounded-lg font-semibold text-lg transition-all hover:scale-105"
          >
            Go to Pro Dashboard
          </button>
        </div>
      </div>
    </div>
  );
}