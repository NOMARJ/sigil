"use client";

import React, { useState, useEffect } from "react";
import FindingInvestigator from "./FindingInvestigator";
import FalsePositiveVerifier from "./FalsePositiveVerifier";
import RemediationViewer from "./RemediationViewer";
import InteractiveChat from "./InteractiveChat";
import { Button } from "@/components/ui/button";
import { launchConfig, ProFeature } from "@/lib/launch-config";
import {
  Finding,
  Scan,
  CreditInfo,
  InvestigationResult,
  FalsePositiveAnalysis,
  RemediationResult,
  ChatSession
} from "@/lib/types";

interface InteractiveFindingsPanelProps {
  scan: Scan;
  findings: Finding[];
  selectedFinding: Finding | null;
  onFindingSelect: (finding: Finding) => void;
}

export default function InteractiveFindingsPanel({
  scan,
  findings,
  selectedFinding,
  onFindingSelect
}: InteractiveFindingsPanelProps) {
  const [creditInfo, setCreditInfo] = useState<CreditInfo | null>(null);
  const [activeTab, setActiveTab] = useState<"investigate" | "false-positive" | "remediate">(
    launchConfig.isFeatureVisible(ProFeature.FINDING_INVESTIGATION) ? "investigate" : "false-positive"
  );
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatSession, setChatSession] = useState<ChatSession | null>(null);
  const [results, setResults] = useState<{
    investigation?: InvestigationResult;
    falsePositive?: FalsePositiveAnalysis;
    remediation?: RemediationResult;
  }>({});

  // Filter tabs based on launch configuration
  const availableTabs = [
    {
      id: "investigate" as const,
      label: "Investigate", 
      feature: ProFeature.FINDING_INVESTIGATION,
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      ),
      description: "Deep-dive analysis of the security threat"
    },
    {
      id: "false-positive" as const,
      label: "Check False Positive",
      feature: ProFeature.FALSE_POSITIVE_VERIFICATION,
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
        </svg>
      ),
      description: "Verify if this is actually safe in your context"
    },
    {
      id: "remediate" as const,
      label: "Get Fix",
      feature: ProFeature.REMEDIATION_GENERATION,
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      ),
      description: "Generate secure code to fix this issue"
    }
  ].filter(tab => launchConfig.isFeatureVisible(tab.feature));

  const tabs = availableTabs;

  // Fetch credit info on component mount
  useEffect(() => {
    fetchCreditInfo();
  }, []);

  // Ensure activeTab is valid for current launch configuration
  useEffect(() => {
    const validTabIds = tabs.map(tab => tab.id);
    if (!validTabIds.includes(activeTab) && validTabIds.length > 0) {
      setActiveTab(validTabIds[0] as "investigate" | "false-positive" | "remediate");
    }
  }, [activeTab, tabs]);

  const fetchCreditInfo = async (): Promise<void> => {
    try {
      const response = await fetch("/api/v1/interactive/credits");
      if (response.ok) {
        const credits: CreditInfo = await response.json();
        setCreditInfo(credits);
      }
    } catch (error) {
      console.error("Failed to fetch credit info:", error);
    }
  };

  const handleInvestigationComplete = (result: InvestigationResult): void => {
    setResults(prev => ({ ...prev, investigation: result }));
    fetchCreditInfo(); // Refresh balance
  };

  const handleFalsePositiveComplete = (analysis: FalsePositiveAnalysis): void => {
    setResults(prev => ({ ...prev, falsePositive: analysis }));
    fetchCreditInfo(); // Refresh balance
  };

  const handleRemediationComplete = (result: RemediationResult): void => {
    setResults(prev => ({ ...prev, remediation: result }));
    fetchCreditInfo(); // Refresh balance
  };

  const handleChatSessionUpdate = (session: ChatSession): void => {
    setChatSession(session);
    fetchCreditInfo(); // Refresh balance
  };

  if (!creditInfo) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="flex items-center gap-2 text-gray-400">
          <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
          Loading interactive features...
        </div>
      </div>
    );
  }

  if (!selectedFinding) {
    return (
      <div className="p-6 text-center">
        <svg className="w-12 h-12 mx-auto mb-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} 
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <h3 className="text-lg font-semibold text-gray-200 mb-2">
          Interactive AI Analysis
        </h3>
        <p className="text-gray-400 mb-4">
          Select a finding to investigate with AI assistance
        </p>
        <div className="space-y-2">
          {findings.slice(0, 3).map((finding) => (
            <button
              key={finding.id}
              onClick={() => onFindingSelect(finding)}
              className="block w-full text-left p-3 rounded border border-gray-700 hover:border-gray-600 hover:bg-gray-800/50 transition-colors"
            >
              <div className="text-sm font-medium text-gray-200">
                {finding.title}
              </div>
              <div className="text-xs text-gray-500 mt-1">
                {finding.file_path}:{finding.line_number}
              </div>
            </button>
          ))}
        </div>
        
        {/* Chat is always available */}
        <div className="mt-6 pt-6 border-t border-gray-700">
          <Button
            onClick={() => setIsChatOpen(true)}
            variant="outline"
            className="w-full"
          >
            Ask questions about this scan
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Selected finding header */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <div className="min-w-0 flex-1">
            <h3 className="text-sm font-semibold text-gray-200 truncate">
              {selectedFinding.title}
            </h3>
            <p className="text-xs text-gray-500 mt-1">
              {selectedFinding.file_path}:{selectedFinding.line_number}
            </p>
          </div>
          <Button
            onClick={() => onFindingSelect(null as any)}
            variant="ghost"
            size="sm"
            className="ml-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                    d="M6 18L18 6M6 6l12 12" />
            </svg>
          </Button>
        </div>
      </div>

      {/* Tab navigation */}
      <div className="border-b border-gray-700">
        <div className="flex">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? "text-brand-400 border-b-2 border-brand-500 bg-brand-500/10"
                  : "text-gray-400 hover:text-gray-300 hover:bg-gray-800/50"
              }`}
              title={tab.description}
            >
              {tab.icon}
              <span className="hidden sm:inline">{tab.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto p-4">
        {activeTab === "investigate" && (
          <FindingInvestigator
            finding={selectedFinding}
            onInvestigationComplete={handleInvestigationComplete}
            creditInfo={creditInfo}
          />
        )}
        
        {activeTab === "false-positive" && (
          <FalsePositiveVerifier
            finding={selectedFinding}
            onAnalysisComplete={handleFalsePositiveComplete}
            creditInfo={creditInfo}
          />
        )}
        
        {activeTab === "remediate" && (
          <RemediationViewer
            finding={selectedFinding}
            onRemediationComplete={handleRemediationComplete}
            creditInfo={creditInfo}
          />
        )}
      </div>

      {/* Chat component */}
      <InteractiveChat
        scan={scan}
        creditInfo={creditInfo}
        onChatSessionUpdate={handleChatSessionUpdate}
        isOpen={isChatOpen}
        onToggle={() => setIsChatOpen(!isChatOpen)}
      />
    </div>
  );
}