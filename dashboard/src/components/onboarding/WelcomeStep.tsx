"use client";

import { useState } from "react";
import { useUser } from "@auth0/nextjs-auth0/client";
import { OnboardingStepProps } from "../OnboardingStep";

export default function WelcomeStep({ step, onComplete }: OnboardingStepProps): JSX.Element {
  const { user } = useUser();
  const [isReady, setIsReady] = useState(false);

  const handleGetStarted = (): void => {
    onComplete(step.id, {
      welcomeCompleted: true,
      timestamp: new Date().toISOString(),
    });
  };

  return (
    <div className="p-8">
      <div className="text-center mb-8">
        {/* Pro Badge */}
        <div className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-purple-600 to-purple-700 rounded-lg mb-6">
          <svg className="w-5 h-5 text-white mr-2" fill="currentColor" viewBox="0 0 20 20">
            <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
          </svg>
          <span className="text-white font-semibold">Pro Member</span>
        </div>

        <h3 className="text-2xl font-bold text-white mb-4">
          Welcome to Sigil Pro, {user?.name || 'there'}!
        </h3>
        <p className="text-lg text-gray-400 mb-8">
          You now have access to AI-powered threat detection that goes beyond traditional rule-based scanning.
        </p>
      </div>

      {/* Pro Features Overview */}
      <div className="grid md:grid-cols-2 gap-6 mb-8">
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center mb-4">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center mr-3">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
            </div>
            <h4 className="text-lg font-semibold text-white">Claude AI Analysis</h4>
          </div>
          <p className="text-gray-400">
            Advanced threat detection using large language models to identify novel attack patterns that traditional scanners miss.
          </p>
        </div>

        <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center mb-4">
            <div className="w-10 h-10 bg-green-600 rounded-lg flex items-center justify-center mr-3">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h4 className="text-lg font-semibold text-white">Zero-Day Discovery</h4>
          </div>
          <p className="text-gray-400">
            Catch sophisticated attacks like supply chain compromises, time bombs, and obfuscated malware before they execute.
          </p>
        </div>

        <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center mb-4">
            <div className="w-10 h-10 bg-purple-600 rounded-lg flex items-center justify-center mr-3">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              </svg>
            </div>
            <h4 className="text-lg font-semibold text-white">Obfuscation Detection</h4>
          </div>
          <p className="text-gray-400">
            Uncover hidden malicious code using base64, hex encoding, or other obfuscation techniques designed to evade detection.
          </p>
        </div>

        <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center mb-4">
            <div className="w-10 h-10 bg-yellow-600 rounded-lg flex items-center justify-center mr-3">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
            </div>
            <h4 className="text-lg font-semibold text-white">Natural Language Insights</h4>
          </div>
          <p className="text-gray-400">
            AI explains threats in plain English, with confidence scores, remediation suggestions, and false positive likelihood.
          </p>
        </div>
      </div>

      {/* Expectations */}
      <div className="bg-blue-900 bg-opacity-30 border border-blue-700 rounded-lg p-6 mb-8">
        <h4 className="text-lg font-semibold text-blue-300 mb-3">What to Expect</h4>
        <div className="flex items-center text-blue-200">
          <svg className="w-5 h-5 mr-2 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clipRule="evenodd" />
          </svg>
          <span>This onboarding will take approximately <strong>5 minutes</strong> to complete</span>
        </div>
        <p className="text-blue-200 mt-2">
          You&apos;ll learn how to set up the CLI, run your first AI-powered scan, and interpret the advanced insights that only Pro members receive.
        </p>
      </div>

      {/* Ready Confirmation */}
      <div className="text-center">
        <label className="inline-flex items-center mb-6">
          <input
            type="checkbox"
            checked={isReady}
            onChange={(e) => setIsReady(e.target.checked)}
            className="w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 rounded focus:ring-purple-500"
          />
          <span className="ml-2 text-gray-300">
            I&apos;m ready to get started with AI-powered threat detection
          </span>
        </label>

        <div>
          <button
            onClick={handleGetStarted}
            disabled={!isReady}
            className={`px-8 py-3 rounded-lg font-semibold text-white transition-all ${
              isReady
                ? "bg-purple-600 hover:bg-purple-700 hover:scale-105"
                : "bg-gray-600 cursor-not-allowed"
            }`}
          >
            Let&apos;s Get Started
          </button>
        </div>
      </div>
    </div>
  );
}