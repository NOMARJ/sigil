"use client";

import { useState } from "react";
import { OnboardingStepProps } from "../OnboardingStep";

export default function ApiKeySetupStep({ step, onComplete }: OnboardingStepProps) {
  const [apiKey, setApiKey] = useState("");
  const [apiKeyError, setApiKeyError] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [copied, setCopied] = useState(false);

  const generateApiKey = async (): Promise<void> => {
    setIsGenerating(true);
    setApiKeyError(null);
    try {
      const response = await fetch("/api/onboarding/generate-key", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      });
      const body = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          typeof body.error === "string"
            ? body.error
            : "API key generation is unavailable.",
        );
      }

      if (typeof body.api_key !== "string" || body.api_key.length === 0) {
        throw new Error("API key generation returned an invalid response.");
      }

      setApiKey(body.api_key);
    } catch (error) {
      setApiKeyError(
        error instanceof Error ? error.message : "API key generation failed.",
      );
    } finally {
      setIsGenerating(false);
    }
  };

  const copyToClipboard = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(apiKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error("Failed to copy API key:", error);
    }
  };

  const continueWithKey = (): void => {
    onComplete(step.id, {
      apiKey,
      authenticationMethod: apiKey ? "api_key" : "device_flow",
      connectionTested: false,
      testTimestamp: new Date().toISOString(),
    });
  };

  return (
    <div className="p-8">
      <div className="max-w-3xl mx-auto">
        {/* Step Description */}
        <div className="mb-8 text-center">
          <div className="w-16 h-16 bg-purple-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
            </svg>
          </div>
          <h3 className="text-xl font-bold text-white mb-2">Connect the Sigil CLI</h3>
          <p className="text-gray-400">
            Authenticate the CLI with your Sigil account to access Pro analysis features.
          </p>
        </div>

        {/* API Key Generation */}
        {!apiKey ? (
          <div className="text-center">
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-6 mb-6">
              <h4 className="text-lg font-semibold text-white mb-4">Use Device Login</h4>
              <p className="text-gray-400 mb-6">
                Run the CLI login command and complete the browser prompt. API key issuance remains disabled until server-side key management is available.
              </p>
              <div className="bg-gray-800 border border-gray-600 rounded p-3 mb-6 text-left">
                <code className="text-green-400 font-mono text-sm">sigil login</code>
              </div>
              
              <button
                onClick={generateApiKey}
                disabled={isGenerating}
                className={`px-6 py-3 rounded-lg font-semibold text-white transition-all ${
                  isGenerating
                    ? "bg-purple-500 cursor-not-allowed"
                    : "bg-purple-600 hover:bg-purple-700"
                }`}
              >
                {isGenerating ? (
                  <div className="flex items-center">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Generating...
                  </div>
                ) : (
                  "Generate API Key"
                )}
              </button>
              <button
                onClick={continueWithKey}
                className="ml-3 px-6 py-3 rounded-lg font-semibold text-white transition-all bg-gray-700 hover:bg-gray-600"
              >
                Continue
              </button>
              {apiKeyError && (
                <p className="mt-4 text-sm text-red-300">{apiKeyError}</p>
              )}
            </div>

            {/* Security Notice */}
            <div className="bg-yellow-900 bg-opacity-30 border border-yellow-700 rounded-lg p-4">
              <div className="flex items-start">
                <svg className="w-5 h-5 text-yellow-400 mt-0.5 mr-3 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                <div className="text-yellow-300">
                  <h5 className="font-medium mb-1">Keep Your API Key Secure</h5>
                  <p className="text-sm text-yellow-400">
                    Store your API key securely and never commit it to version control. It provides access to your Pro account and billing.
                  </p>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div>
            {/* Generated API Key */}
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-6 mb-6">
              <h4 className="text-lg font-semibold text-white mb-4">Your Pro API Key</h4>
              <div className="bg-gray-800 border border-gray-600 rounded-lg p-4 mb-4">
                <div className="flex items-center justify-between">
                  <code className="text-green-400 font-mono break-all">{apiKey}</code>
                  <button
                    onClick={copyToClipboard}
                    className={`ml-4 px-3 py-1 rounded text-sm font-medium transition-colors ${
                      copied
                        ? "bg-green-600 text-white"
                        : "bg-gray-700 hover:bg-gray-600 text-gray-300"
                    }`}
                  >
                    {copied ? "Copied!" : "Copy"}
                  </button>
                </div>
              </div>
              
              {/* CLI Setup Instructions */}
              <div className="mb-6">
                <h5 className="text-white font-semibold mb-3">Setup Instructions</h5>
                <div className="space-y-3">
                  <div>
                    <p className="text-sm text-gray-400 mb-2">1. Install the Sigil CLI:</p>
                    <div className="bg-gray-800 border border-gray-600 rounded p-3">
                      <code className="text-green-400 font-mono text-sm">
                        curl -sSL https://get.sigil.sh | sh
                      </code>
                    </div>
                  </div>
                  
                  <div>
                    <p className="text-sm text-gray-400 mb-2">2. Configure your API key:</p>
                    <div className="bg-gray-800 border border-gray-600 rounded p-3">
                      <code className="text-green-400 font-mono text-sm">
                        export SIGIL_API_KEY=&quot;{apiKey}&quot;
                      </code>
                    </div>
                  </div>
                  
                  <div>
                    <p className="text-sm text-gray-400 mb-2">3. Test your connection:</p>
                    <div className="bg-gray-800 border border-gray-600 rounded p-3">
                      <code className="text-green-400 font-mono text-sm">
                        sigil --version --pro
                      </code>
                    </div>
                  </div>
                </div>
              </div>

              {/* Continue */}
              <div className="text-center">
                <button
                  onClick={continueWithKey}
                  className="px-6 py-3 rounded-lg font-semibold text-white transition-all bg-purple-600 hover:bg-purple-700"
                >
                  Continue
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
