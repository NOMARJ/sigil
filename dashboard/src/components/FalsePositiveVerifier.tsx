"use client";

import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { 
  Finding, 
  FalsePositiveAnalysis, 
  CreditInfo 
} from "@/lib/types";

interface FalsePositiveVerifierProps {
  finding: Finding;
  onAnalysisComplete: (analysis: FalsePositiveAnalysis) => void;
  creditInfo: CreditInfo;
}

export default function FalsePositiveVerifier({ 
  finding, 
  onAnalysisComplete,
  creditInfo 
}: FalsePositiveVerifierProps) {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [analysis, setAnalysis] = useState<FalsePositiveAnalysis | null>(null);

  const cost = creditInfo.costs.false_positive_check;
  const canAfford = creditInfo.balance >= cost;

  const handleAnalyze = async (): Promise<void> => {
    if (!canAfford) return;

    setIsAnalyzing(true);
    try {
      const response = await fetch("/api/v1/interactive/false-positive", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          finding_id: finding.id
        })
      });

      if (!response.ok) {
        throw new Error("False positive analysis failed");
      }

      const result: FalsePositiveAnalysis = await response.json();
      setAnalysis(result);
      setShowResults(true);
      onAnalysisComplete(result);
    } catch (error) {
      console.error("False positive analysis error:", error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getAssessmentIcon = (isSafe: boolean): JSX.Element => {
    if (isSafe) {
      return (
        <svg className="w-5 h-5 text-success-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      );
    } else {
      return (
        <svg className="w-5 h-5 text-danger-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
      );
    }
  };

  const getConfidenceColor = (confidence: number): string => {
    if (confidence >= 90) return "text-success-500";
    if (confidence >= 70) return "text-info-500";
    if (confidence >= 50) return "text-warning-500";
    return "text-danger-500";
  };

  return (
    <div className="border border-gray-800 rounded-lg p-4 bg-gray-900/30">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                  d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
          </svg>
          False Positive Check
        </h3>
        <span className="text-xs text-gray-500">
          Balance: {creditInfo.balance} credits
        </span>
      </div>

      {!showResults ? (
        <div className="space-y-4">
          <div className="bg-gray-800/50 border border-gray-700 rounded p-3">
            <h4 className="text-sm font-medium text-gray-200 mb-2">
              Context Analysis
            </h4>
            <p className="text-xs text-gray-400 leading-relaxed">
              AI will analyze the surrounding code, data flow, and inputs to determine 
              if this finding is a false positive in your specific context. This considers 
              factors like sanitization, validation, and execution environment.
            </p>
          </div>

          <div className="flex items-center justify-between p-3 border border-gray-700 rounded bg-gray-800/30">
            <div>
              <div className="text-sm font-medium text-gray-200">
                Smart Context Analysis
              </div>
              <div className="text-xs text-gray-400">
                Analyzes code flow and execution context
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
            onClick={handleAnalyze}
            disabled={isAnalyzing || !canAfford}
            className="w-full"
          >
            {isAnalyzing ? (
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                Analyzing Context...
              </div>
            ) : (
              `Check if False Positive (${cost} credits)`
            )}
          </Button>
        </div>
      ) : analysis && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            {getAssessmentIcon(analysis.is_safe)}
            <div>
              <div className={`text-sm font-semibold ${
                analysis.is_safe ? "text-success-500" : "text-danger-500"
              }`}>
                {analysis.is_safe ? "Likely Safe (False Positive)" : "Genuine Security Risk"}
              </div>
              <div className={`text-xs ${getConfidenceColor(analysis.confidence_percentage)}`}>
                {analysis.confidence_percentage}% confidence
              </div>
            </div>
            <div className="ml-auto text-xs text-gray-500">
              {analysis.credits_used} credits used
            </div>
          </div>

          <div className="space-y-3">
            <div>
              <h4 className="text-sm font-medium text-gray-200 mb-1">
                AI Explanation
              </h4>
              <div className="bg-gray-800/50 border border-gray-700 rounded p-3">
                <p className="text-sm text-gray-300 leading-relaxed">
                  {analysis.explanation}
                </p>
              </div>
            </div>

            <div>
              <h4 className="text-sm font-medium text-gray-200 mb-1">
                Context Analysis
              </h4>
              <div className="bg-gray-800/50 border border-gray-700 rounded p-3">
                <p className="text-sm text-gray-300 leading-relaxed">
                  {analysis.context_analysis}
                </p>
              </div>
            </div>

            {analysis.defense_suggestions.length > 0 && (
              <div>
                <h4 className="text-sm font-medium text-gray-200 mb-1">
                  Defense-in-Depth Suggestions
                </h4>
                <div className="bg-blue-500/10 border border-blue-500/20 rounded p-3">
                  <ul className="space-y-2">
                    {analysis.defense_suggestions.map((suggestion, index) => (
                      <li key={index} className="text-sm text-blue-300 flex items-start gap-2">
                        <svg className="w-3 h-3 mt-1 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                        {suggestion}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            <div className="flex items-center justify-between text-xs text-gray-500 pt-2 border-t border-gray-700/50">
              <span>
                Analysis completed: {new Date(analysis.created_at).toLocaleTimeString()}
              </span>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-1 rounded text-xs font-medium ${
                  analysis.is_safe 
                    ? "bg-success-500/20 text-success-400" 
                    : "bg-danger-500/20 text-danger-400"
                }`}>
                  {analysis.is_safe ? "Safe" : "Dangerous"}
                </span>
              </div>
            </div>
          </div>

          <Button 
            onClick={() => setShowResults(false)}
            variant="ghost"
            size="sm"
            className="w-full"
          >
            New Analysis
          </Button>
        </div>
      )}
    </div>
  );
}