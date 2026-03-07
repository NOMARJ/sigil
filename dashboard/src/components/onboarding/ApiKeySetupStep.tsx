"use client";

import { useState } from "react";
import { OnboardingStepProps } from "../OnboardingStep";

export default function ApiKeySetupStep({ step, onComplete }: OnboardingStepProps): JSX.Element {
  const [apiKey, setApiKey] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<"success" | "error" | null>(null);
  const [copied, setCopied] = useState(false);

  const generateApiKey = async (): Promise<void> => {
    setIsGenerating(true);
    try {
      // In a real implementation, this would call the backend API
      // For now, we'll simulate with a timeout and mock key
      await new Promise(resolve => setTimeout(resolve, 2000));
      const mockKey = `sp_${Date.now()}_${Math.random().toString(36).substring(7)}`;
      setApiKey(mockKey);
    } catch (error) {
      console.error("Error generating API key:", error);
      // Show error state
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

  const testConnection = async (): Promise<void> => {
    setIsTesting(true);
    try {
      // Simulate API test
      await new Promise(resolve => setTimeout(resolve, 1500));
      setTestResult("success");
      // Auto-proceed after successful test
      setTimeout(() => {
        onComplete(step.id, { 
          apiKey,
          connectionTested: true,
          testTimestamp: new Date().toISOString()
        });
      }, 1000);
    } catch (error) {
      console.error("Connection test failed:", error);
      setTestResult("error");
    } finally {
      setIsTesting(false);
    }
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
          <h3 className="text-xl font-bold text-white mb-2">Generate Your Pro API Key</h3>
          <p className="text-gray-400">
            Create a secure API key to connect the Sigil CLI to your Pro account and access AI-powered features.
          </p>
        </div>

        {/* API Key Generation */}
        {!apiKey ? (
          <div className="text-center">
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-6 mb-6">
              <h4 className="text-lg font-semibold text-white mb-4">Ready to Generate</h4>
              <p className="text-gray-400 mb-6">
                Your API key will have Pro-tier permissions and access to LLM analysis features.
              </p>
              
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

              {/* Test Connection */}
              <div className="text-center">
                {testResult === "success" ? (
                  <div className="bg-green-900 border border-green-700 rounded-lg p-4 mb-4">
                    <div className="flex items-center justify-center text-green-300">
                      <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                      </svg>
                      Connection successful! Proceeding to next step...
                    </div>
                  </div>
                ) : testResult === "error" ? (
                  <div className="bg-red-900 border border-red-700 rounded-lg p-4 mb-4">
                    <div className="text-red-300">
                      <p className="font-medium">Connection Failed</p>
                      <p className="text-sm mt-1">Please check your CLI installation and try again.</p>
                    </div>
                  </div>
                ) : null}

                <button
                  onClick={testConnection}
                  disabled={isTesting}
                  className={`px-6 py-3 rounded-lg font-semibold text-white transition-all ${
                    isTesting
                      ? "bg-purple-500 cursor-not-allowed"
                      : "bg-purple-600 hover:bg-purple-700"
                  }`}
                >
                  {isTesting ? (
                    <div className="flex items-center">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Testing Connection...
                    </div>
                  ) : (
                    "Test Connection"
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}