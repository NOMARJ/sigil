import { useState } from "react";
import ConfidenceScore from "@/components/ConfidenceScore";
import type { LLMInsight } from "@/lib/types";

interface ThreatExplanationProps {
  insight: LLMInsight;
  isZeroDay?: boolean;
}

export default function ThreatExplanation({ 
  insight, 
  isZeroDay = false 
}: ThreatExplanationProps): JSX.Element {
  const [showDetails, setShowDetails] = useState(false);
  const [showEvidence, setShowEvidence] = useState(false);
  const [showRemediation, setShowRemediation] = useState(false);

  // Category colors for visual distinction
  const categoryColors: Record<string, string> = {
    code_injection: "bg-red-500/10 text-red-400 border-red-500/20",
    data_exfiltration: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    credential_theft: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    supply_chain_attack: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    prompt_injection: "bg-pink-500/10 text-pink-400 border-pink-500/20",
    privilege_escalation: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    obfuscated_malware: "bg-indigo-500/10 text-indigo-400 border-indigo-500/20",
    time_bomb: "bg-red-600/10 text-red-300 border-red-600/20",
    backdoor: "bg-gray-500/10 text-gray-400 border-gray-500/20",
    unknown_pattern: "bg-gray-600/10 text-gray-300 border-gray-600/20"
  };

  const threatColor = categoryColors[insight.threat_category] || categoryColors.unknown_pattern;

  return (
    <div className={`card hover:border-gray-700 transition-colors ${isZeroDay ? 'ring-2 ring-red-500/50' : ''}`}>
      <div className="card-body">
        {/* Header */}
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-2">
              <h3 className="text-lg font-semibold text-gray-100 truncate">
                {insight.title}
              </h3>
              {isZeroDay && (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-bold bg-red-500/20 text-red-300 border border-red-500/30 animate-pulse">
                  🚨 ZERO-DAY
                </span>
              )}
            </div>

            <div className="flex items-center gap-2 mb-3">
              <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${threatColor}`}>
                {insight.threat_category.replace(/_/g, ' ').toUpperCase()}
              </span>
              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700">
                {insight.analysis_type.replace(/_/g, ' ')}
              </span>
            </div>

            {/* Confidence Score */}
            <div className="mb-4">
              <ConfidenceScore 
                confidence={insight.confidence}
                confidenceLevel={insight.confidence_level}
                size="sm"
              />
            </div>
          </div>

          {/* Severity adjustment indicator */}
          {insight.severity_adjustment !== 0 && (
            <div className="text-right">
              <div className={`text-sm font-medium ${
                insight.severity_adjustment > 0 ? 'text-red-400' : 'text-green-400'
              }`}>
                {insight.severity_adjustment > 0 ? '+' : ''}{insight.severity_adjustment.toFixed(1)}
              </div>
              <div className="text-xs text-gray-500">severity</div>
            </div>
          )}
        </div>

        {/* Description */}
        <p className="text-sm text-gray-400 mb-4 leading-relaxed">
          {insight.description}
        </p>

        {/* AI Reasoning - Always visible for Pro users */}
        <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3 mb-4">
          <div className="flex items-center gap-2 mb-2">
            <svg className="w-4 h-4 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
            <span className="text-sm font-medium text-blue-400">AI Analysis</span>
          </div>
          <p className="text-sm text-blue-200/80 italic">
            {insight.reasoning}
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap gap-2 mb-4">
          <button
            onClick={() => setShowEvidence(!showEvidence)}
            className="btn-secondary text-xs"
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Evidence ({insight.evidence_snippets.length})
          </button>

          <button
            onClick={() => setShowRemediation(!showRemediation)}
            className="btn-secondary text-xs"
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
            </svg>
            Remediation ({insight.remediation_suggestions.length})
          </button>

          <button
            onClick={() => setShowDetails(!showDetails)}
            className="btn-secondary text-xs"
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Details
          </button>
        </div>

        {/* Expandable sections */}
        {showEvidence && (
          <div className="border-t border-gray-800 pt-4 mb-4">
            <h4 className="text-sm font-medium text-gray-300 mb-3">Code Evidence</h4>
            <div className="space-y-2">
              {insight.evidence_snippets.map((snippet, index) => (
                <div key={index} className="bg-gray-900/50 border border-gray-800 rounded p-3">
                  <code className="text-xs text-gray-300 font-mono break-all">
                    {snippet}
                  </code>
                </div>
              ))}
            </div>
            {insight.affected_files.length > 0 && (
              <div className="mt-3">
                <p className="text-xs text-gray-500 mb-1">Affected files:</p>
                <div className="flex flex-wrap gap-1">
                  {insight.affected_files.map((file, index) => (
                    <span key={index} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-gray-800/50 text-gray-400 border border-gray-700/50">
                      {file}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {showRemediation && (
          <div className="border-t border-gray-800 pt-4 mb-4">
            <div className="grid md:grid-cols-2 gap-4">
              {/* Immediate steps */}
              <div>
                <h4 className="text-sm font-medium text-gray-300 mb-2">Immediate Actions</h4>
                <ul className="space-y-1.5">
                  {insight.mitigation_steps.map((step, index) => (
                    <li key={index} className="text-sm text-gray-400 flex items-start gap-2">
                      <span className="text-orange-400 font-bold text-xs mt-0.5">•</span>
                      {step}
                    </li>
                  ))}
                </ul>
              </div>

              {/* Long-term fixes */}
              <div>
                <h4 className="text-sm font-medium text-gray-300 mb-2">Remediation Steps</h4>
                <ul className="space-y-1.5">
                  {insight.remediation_suggestions.map((suggestion, index) => (
                    <li key={index} className="text-sm text-gray-400 flex items-start gap-2">
                      <span className="text-green-400 font-bold text-xs mt-0.5">•</span>
                      {suggestion}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}

        {showDetails && (
          <div className="border-t border-gray-800 pt-4">
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <span className="text-gray-500">False Positive Likelihood:</span>
                <div className="mt-1">
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                      <div 
                        className="h-1.5 bg-yellow-500 rounded-full transition-all duration-300"
                        style={{ width: `${insight.false_positive_likelihood * 100}%` }}
                      />
                    </div>
                    <span className="text-gray-400">
                      {Math.round(insight.false_positive_likelihood * 100)}%
                    </span>
                  </div>
                </div>
              </div>
              
              <div>
                <span className="text-gray-500">Severity Adjustment:</span>
                <div className={`mt-1 font-medium ${
                  insight.severity_adjustment > 0 ? 'text-red-400' : 
                  insight.severity_adjustment < 0 ? 'text-green-400' : 'text-gray-400'
                }`}>
                  {insight.severity_adjustment > 0 ? '+' : ''}{insight.severity_adjustment.toFixed(1)}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}