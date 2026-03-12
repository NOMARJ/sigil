"use client";

import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { 
  Finding, 
  InvestigationDepth, 
  InvestigationResult, 
  CreditInfo 
} from "@/lib/types";

interface FindingInvestigatorProps {
  finding: Finding;
  onInvestigationComplete: (result: InvestigationResult) => void;
  creditInfo: CreditInfo;
}

export default function FindingInvestigator({ 
  finding, 
  onInvestigationComplete,
  creditInfo 
}: FindingInvestigatorProps) {
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [selectedDepth, setSelectedDepth] = useState<InvestigationDepth>("quick");
  const [showResults, setShowResults] = useState(false);
  const [results, setResults] = useState<InvestigationResult | null>(null);

  const depthOptions = [
    {
      value: "quick" as InvestigationDepth,
      label: "Quick Analysis",
      description: "Fast overview using Haiku",
      cost: creditInfo.costs.quick_investigation,
      time: "~5 seconds"
    },
    {
      value: "thorough" as InvestigationDepth,
      label: "Thorough Investigation", 
      description: "Detailed analysis using Sonnet",
      cost: creditInfo.costs.thorough_investigation,
      time: "~15 seconds"
    },
    {
      value: "exhaustive" as InvestigationDepth,
      label: "Exhaustive Analysis",
      description: "Complete investigation using Opus",
      cost: creditInfo.costs.exhaustive_investigation,
      time: "~30 seconds"
    }
  ];

  const selectedOption = depthOptions.find(opt => opt.value === selectedDepth);

  const handleInvestigate = async (): Promise<void> => {
    if (!selectedOption || creditInfo.balance < selectedOption.cost) return;

    setIsInvestigating(true);
    try {
      const response = await fetch("/api/v1/interactive/investigate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          finding_id: finding.id,
          depth: selectedDepth
        })
      });

      if (!response.ok) {
        throw new Error("Investigation failed");
      }

      const result: InvestigationResult = await response.json();
      setResults(result);
      setShowResults(true);
      onInvestigationComplete(result);
    } catch (error) {
      console.error("Investigation error:", error);
    } finally {
      setIsInvestigating(false);
    }
  };

  const getConfidenceColor = (confidence: number): string => {
    if (confidence >= 90) return "text-danger-500";
    if (confidence >= 70) return "text-warning-500";
    if (confidence >= 50) return "text-info-500";
    return "text-success-500";
  };

  const getConfidenceLabel = (confidence: number): string => {
    if (confidence >= 90) return "Very High Threat";
    if (confidence >= 70) return "High Threat";
    if (confidence >= 50) return "Moderate Threat";
    return "Low Threat";
  };

  return (
    <div className="border border-gray-800 rounded-lg p-4 bg-gray-900/30">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                  d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          AI Investigation
        </h3>
        <span className="text-xs text-gray-500">
          Balance: {creditInfo.balance} credits
        </span>
      </div>

      {!showResults ? (
        <div className="space-y-4">
          <div className="space-y-2">
            <label className="text-xs font-medium text-gray-300">
              Investigation Depth
            </label>
            <div className="space-y-2">
              {depthOptions.map((option) => (
                <label 
                  key={option.value}
                  className={`flex items-center justify-between p-3 rounded border cursor-pointer transition-colors ${
                    selectedDepth === option.value
                      ? "border-brand-500 bg-brand-500/10"
                      : "border-gray-700 hover:border-gray-600 bg-gray-800/50"
                  }`}
                >
                  <input
                    type="radio"
                    name="depth"
                    value={option.value}
                    checked={selectedDepth === option.value}
                    onChange={(e) => setSelectedDepth(e.target.value as InvestigationDepth)}
                    className="sr-only"
                  />
                  <div>
                    <div className="text-sm font-medium text-gray-200">
                      {option.label}
                    </div>
                    <div className="text-xs text-gray-400">
                      {option.description} • {option.time}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium text-gray-300">
                      {option.cost} credits
                    </div>
                    <div className={`text-xs ${
                      creditInfo.balance >= option.cost 
                        ? "text-success-400" 
                        : "text-danger-400"
                    }`}>
                      {creditInfo.balance >= option.cost ? "Available" : "Insufficient"}
                    </div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          <div className="flex gap-2">
            <Button
              onClick={handleInvestigate}
              disabled={
                isInvestigating || 
                !selectedOption || 
                creditInfo.balance < selectedOption.cost
              }
              className="flex-1"
            >
              {isInvestigating ? (
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                  Analyzing...
                </div>
              ) : (
                `Investigate (${selectedOption?.cost || 0} credits)`
              )}
            </Button>
          </div>
        </div>
      ) : results && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${
                results.confidence_score >= 70 ? "bg-danger-500" : 
                results.confidence_score >= 40 ? "bg-warning-500" : "bg-success-500"
              }`} />
              <span className={`text-sm font-medium ${getConfidenceColor(results.confidence_score)}`}>
                {getConfidenceLabel(results.confidence_score)}
              </span>
              <span className="text-xs text-gray-500">
                ({results.confidence_score}% confidence)
              </span>
            </div>
            <span className="text-xs text-gray-500">
              {results.credits_used} credits used • {results.model_used}
            </span>
          </div>

          <div className="space-y-3">
            <div>
              <h4 className="text-sm font-medium text-gray-200 mb-1">
                Threat Assessment
              </h4>
              <p className="text-sm text-gray-300 leading-relaxed">
                {results.threat_assessment}
              </p>
            </div>

            {results.evidence.length > 0 && (
              <div>
                <h4 className="text-sm font-medium text-gray-200 mb-1">
                  Evidence Found
                </h4>
                <ul className="space-y-1">
                  {results.evidence.map((evidence, index) => (
                    <li key={index} className="text-sm text-gray-400 flex items-start gap-2">
                      <span className="text-brand-400 mt-1.5 w-1 h-1 rounded-full bg-current shrink-0" />
                      {evidence}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div>
              <h4 className="text-sm font-medium text-gray-200 mb-1">
                Code Flow Analysis
              </h4>
              <div className="bg-gray-800/50 border border-gray-700 rounded p-3">
                <pre className="text-xs text-gray-300 whitespace-pre-wrap font-mono">
                  {results.code_flow_analysis}
                </pre>
              </div>
            </div>

            <div className="flex items-center gap-4 text-xs text-gray-500">
              <span>
                False Positive Likelihood: 
                <span className={`ml-1 font-medium ${
                  results.false_positive_likelihood > 70 
                    ? "text-success-400" 
                    : results.false_positive_likelihood > 30
                    ? "text-warning-400"
                    : "text-danger-400"
                }`}>
                  {results.false_positive_likelihood}%
                </span>
              </span>
              <span>•</span>
              <span>
                Analyzed: {new Date(results.created_at).toLocaleTimeString()}
              </span>
            </div>
          </div>

          <Button 
            onClick={() => setShowResults(false)}
            variant="ghost"
            size="sm"
            className="w-full"
          >
            New Investigation
          </Button>
        </div>
      )}
    </div>
  );
}