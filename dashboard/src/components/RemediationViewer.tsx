"use client";

import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { 
  Finding, 
  RemediationResult, 
  CreditInfo 
} from "@/lib/types";

interface RemediationViewerProps {
  finding: Finding;
  onRemediationComplete: (result: RemediationResult) => void;
  creditInfo: CreditInfo;
}

export default function RemediationViewer({ 
  finding, 
  onRemediationComplete,
  creditInfo 
}: RemediationViewerProps) {
  const [isGenerating, setIsGenerating] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [remediation, setRemediation] = useState<RemediationResult | null>(null);
  const [selectedFixIndex, setSelectedFixIndex] = useState(0);
  const [copiedFix, setCopiedFix] = useState<string | null>(null);

  const cost = creditInfo.costs.remediation;
  const canAfford = creditInfo.balance >= cost;

  const handleGenerateFix = async (): Promise<void> => {
    if (!canAfford) return;

    setIsGenerating(true);
    try {
      const response = await fetch("/api/v1/interactive/remediate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          finding_id: finding.id
        })
      });

      if (!response.ok) {
        throw new Error("Remediation generation failed");
      }

      const result: RemediationResult = await response.json();
      setRemediation(result);
      setShowResults(true);
      setSelectedFixIndex(0);
      onRemediationComplete(result);
    } catch (error) {
      console.error("Remediation generation error:", error);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleCopyCode = async (code: string, fixId: string): Promise<void> => {
    try {
      await navigator.clipboard.writeText(code);
      setCopiedFix(fixId);
      setTimeout(() => setCopiedFix(null), 2000);
    } catch (error) {
      console.error("Copy failed:", error);
    }
  };

  const getLanguageColor = (language: string): string => {
    const colors = {
      javascript: "text-yellow-400",
      typescript: "text-blue-400", 
      python: "text-green-400",
      java: "text-orange-400",
      go: "text-cyan-400",
      rust: "text-orange-500",
      php: "text-purple-400",
      ruby: "text-red-400",
    };
    return colors[language.toLowerCase() as keyof typeof colors] || "text-gray-400";
  };

  return (
    <div className="border border-gray-800 rounded-lg p-4 bg-gray-900/30">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                  d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
          </svg>
          Secure Fix Generation
        </h3>
        <span className="text-xs text-gray-500">
          Balance: {creditInfo.balance} credits
        </span>
      </div>

      {!showResults ? (
        <div className="space-y-4">
          <div className="bg-gray-800/50 border border-gray-700 rounded p-3">
            <h4 className="text-sm font-medium text-gray-200 mb-2">
              AI-Generated Remediation
            </h4>
            <p className="text-xs text-gray-400 leading-relaxed">
              Generate secure code fixes for this vulnerability. The AI will provide 
              working code that resolves the security issue while maintaining 
              functionality, plus unit tests to verify the fix works correctly.
            </p>
          </div>

          <div className="flex items-center justify-between p-3 border border-gray-700 rounded bg-gray-800/30">
            <div>
              <div className="text-sm font-medium text-gray-200">
                Secure Code Generation
              </div>
              <div className="text-xs text-gray-400">
                Generates multiple fix options with explanations
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm font-medium text-gray-300">
                {cost} credits
              </div>
              <div className={`text-xs ${canAfford ? "text-success-400" : "text-danger-400"}`}>
                {canAfford ? "Available" : "Insufficient"}
              </div>
            </div>
          </div>

          <Button
            onClick={handleGenerateFix}
            disabled={isGenerating || !canAfford}
            className="w-full"
          >
            {isGenerating ? (
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                Generating Fix...
              </div>
            ) : (
              `Generate Fix (${cost} credits)`
            )}
          </Button>
        </div>
      ) : remediation && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-success-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                      d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span className="text-sm font-medium text-success-500">
                {remediation.fixes.length} Fix{remediation.fixes.length !== 1 ? "es" : ""} Generated
              </span>
            </div>
            <span className="text-xs text-gray-500">
              {remediation.credits_used} credits used
            </span>
          </div>

          {/* Fix tabs */}
          {remediation.fixes.length > 1 && (
            <div className="flex gap-1 border-b border-gray-700/50">
              {remediation.fixes.map((fix, index) => (
                <button
                  key={fix.id}
                  onClick={() => setSelectedFixIndex(index)}
                  className={`px-3 py-2 text-sm font-medium rounded-t transition-colors ${
                    selectedFixIndex === index
                      ? "bg-gray-800 text-gray-200 border-b-2 border-brand-500"
                      : "text-gray-400 hover:text-gray-300 hover:bg-gray-800/50"
                  }`}
                >
                  {fix.title}
                </button>
              ))}
            </div>
          )}

          {/* Selected fix content */}
          {remediation.fixes[selectedFixIndex] && (
            <div className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-medium text-gray-200">
                    {remediation.fixes[selectedFixIndex].title}
                  </h4>
                  <span className={`text-xs px-2 py-1 rounded font-mono ${
                    getLanguageColor(remediation.fixes[selectedFixIndex].language)
                  } bg-gray-800`}>
                    {remediation.fixes[selectedFixIndex].language}
                  </span>
                </div>
                <p className="text-sm text-gray-400 mb-3">
                  {remediation.fixes[selectedFixIndex].description}
                </p>
              </div>

              {/* Code editor view */}
              <div className="border border-gray-700 rounded-lg overflow-hidden">
                <div className="flex items-center justify-between bg-gray-800 px-4 py-2">
                  <span className="text-xs font-medium text-gray-300">
                    Secure Implementation
                  </span>
                  <Button
                    onClick={() => handleCopyCode(
                      remediation.fixes[selectedFixIndex].code,
                      remediation.fixes[selectedFixIndex].id
                    )}
                    variant="ghost"
                    size="sm"
                    className="h-6 px-2 text-xs"
                  >
                    {copiedFix === remediation.fixes[selectedFixIndex].id ? (
                      <div className="flex items-center gap-1">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                                d="M5 13l4 4L19 7" />
                        </svg>
                        Copied
                      </div>
                    ) : (
                      <div className="flex items-center gap-1">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                                d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                        Copy
                      </div>
                    )}
                  </Button>
                </div>
                <div className="p-4 bg-gray-900/50 overflow-x-auto">
                  <pre className="text-sm font-mono text-gray-300 whitespace-pre">
                    <code>{remediation.fixes[selectedFixIndex].code}</code>
                  </pre>
                </div>
              </div>

              {/* Explanation */}
              <div>
                <h4 className="text-sm font-medium text-gray-200 mb-1">
                  How This Fix Works
                </h4>
                <div className="bg-gray-800/50 border border-gray-700 rounded p-3">
                  <p className="text-sm text-gray-300 leading-relaxed">
                    {remediation.fixes[selectedFixIndex].explanation}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Unit test */}
          {remediation.unit_test && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-medium text-gray-200">
                  Unit Test
                </h4>
                <Button
                  onClick={() => handleCopyCode(remediation.unit_test!, "unit_test")}
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-xs"
                >
                  {copiedFix === "unit_test" ? (
                    <div className="flex items-center gap-1">
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                              d="M5 13l4 4L19 7" />
                      </svg>
                      Copied
                    </div>
                  ) : (
                    <div className="flex items-center gap-1">
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                      Copy
                    </div>
                  )}
                </Button>
              </div>
              <div className="border border-gray-700 rounded-lg overflow-hidden">
                <div className="p-4 bg-gray-900/50 overflow-x-auto">
                  <pre className="text-sm font-mono text-gray-300 whitespace-pre">
                    <code>{remediation.unit_test}</code>
                  </pre>
                </div>
              </div>
            </div>
          )}

          <div className="flex items-center justify-between text-xs text-gray-500 pt-2 border-t border-gray-700/50">
            <span>
              Generated: {new Date(remediation.created_at).toLocaleTimeString()}
            </span>
            <span className="px-2 py-1 bg-success-500/20 text-success-400 rounded text-xs font-medium">
              Ready to Apply
            </span>
          </div>

          <Button 
            onClick={() => setShowResults(false)}
            variant="ghost"
            size="sm"
            className="w-full"
          >
            Generate New Fix
          </Button>
        </div>
      )}
    </div>
  );
}