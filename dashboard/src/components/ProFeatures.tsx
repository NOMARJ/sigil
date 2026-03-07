import { useState } from "react";
import type { LLMAnalysisResponse } from "@/lib/types";

interface ProFeaturesProps {
  analysisResponse: LLMAnalysisResponse;
}

export default function ProFeatures({ analysisResponse }: ProFeaturesProps): JSX.Element {
  const [showMetrics, setShowMetrics] = useState(false);
  
  const { insights, context_analysis, tokens_used, model_used, processing_time_ms, confidence_summary, threat_summary } = analysisResponse;

  // Calculate key metrics
  const zeroDay = insights.filter(i => i.analysis_type === "zero_day_detection");
  const highConfidence = insights.filter(i => i.confidence >= 0.7);
  const criticalThreats = insights.filter(i => i.severity_adjustment > 2.0);
  const avgConfidence = insights.length > 0 ? insights.reduce((sum, i) => sum + i.confidence, 0) / insights.length : 0;

  return (
    <div className="space-y-6">
      {/* Pro Features Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Zero-day Detection */}
        <div className="card bg-gradient-to-br from-red-500/5 to-red-600/5 border-red-500/20">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-red-400">{zeroDay.length}</div>
                <div className="text-sm text-gray-400">Zero-day Patterns</div>
              </div>
              <div className="w-10 h-10 bg-red-500/20 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </div>
            </div>
            {zeroDay.length > 0 && (
              <div className="mt-2 text-xs text-red-400">
                🚨 Novel threats detected
              </div>
            )}
          </div>
        </div>

        {/* High Confidence Insights */}
        <div className="card bg-gradient-to-br from-orange-500/5 to-orange-600/5 border-orange-500/20">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-orange-400">{highConfidence.length}</div>
                <div className="text-sm text-gray-400">High Confidence</div>
              </div>
              <div className="w-10 h-10 bg-orange-500/20 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-orange-400" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
              </div>
            </div>
            <div className="mt-2 text-xs text-orange-400">
              {Math.round(avgConfidence * 100)}% avg confidence
            </div>
          </div>
        </div>

        {/* Attack Chain Detection */}
        <div className="card bg-gradient-to-br from-purple-500/5 to-purple-600/5 border-purple-500/20">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-purple-400">
                  {context_analysis?.attack_chain_detected ? 1 : 0}
                </div>
                <div className="text-sm text-gray-400">Attack Chains</div>
              </div>
              <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
              </div>
            </div>
            {context_analysis?.attack_chain_detected && (
              <div className="mt-2 text-xs text-purple-400">
                Multi-step attack detected
              </div>
            )}
          </div>
        </div>

        {/* Critical Threats */}
        <div className="card bg-gradient-to-br from-blue-500/5 to-blue-600/5 border-blue-500/20">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-blue-400">{criticalThreats.length}</div>
                <div className="text-sm text-gray-400">Critical Threats</div>
              </div>
              <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M3 6a3 3 0 013-3h10a1 1 0 01.8 1.6L14.25 8l2.55 3.4A1 1 0 0116 13H6a1 1 0 00-1 1v3a1 1 0 11-2 0V6z" clipRule="evenodd" />
                </svg>
              </div>
            </div>
            <div className="mt-2 text-xs text-blue-400">
              High severity adjustments
            </div>
          </div>
        </div>
      </div>

      {/* AI Model Performance Metrics */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="section-header">AI Analysis Performance</h3>
              <p className="section-description">
                Model performance and resource usage for this analysis
              </p>
            </div>
            <button
              onClick={() => setShowMetrics(!showMetrics)}
              className="btn-secondary text-xs"
            >
              {showMetrics ? 'Hide' : 'Show'} Details
            </button>
          </div>
        </div>

        <div className="card-body">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="text-center">
              <div className="text-lg font-semibold text-gray-300">{model_used}</div>
              <div className="text-xs text-gray-500">AI Model</div>
            </div>
            
            <div className="text-center">
              <div className="text-lg font-semibold text-gray-300">
                {(processing_time_ms / 1000).toFixed(1)}s
              </div>
              <div className="text-xs text-gray-500">Processing Time</div>
            </div>
            
            <div className="text-center">
              <div className="text-lg font-semibold text-gray-300">
                {tokens_used.toLocaleString()}
              </div>
              <div className="text-xs text-gray-500">Tokens Used</div>
            </div>
          </div>

          {showMetrics && (
            <div className="mt-6 pt-6 border-t border-gray-800">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Confidence breakdown */}
                <div>
                  <h4 className="text-sm font-medium text-gray-300 mb-3">Confidence Distribution</h4>
                  <div className="space-y-2">
                    {Object.entries(confidence_summary).map(([level, count]) => (
                      <div key={level} className="flex items-center justify-between">
                        <span className="text-sm text-gray-400 capitalize">
                          {level.replace('_', ' ')}
                        </span>
                        <span className="text-sm font-medium text-gray-300">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Threat category breakdown */}
                <div>
                  <h4 className="text-sm font-medium text-gray-300 mb-3">Threat Categories</h4>
                  <div className="space-y-2">
                    {Object.entries(threat_summary).map(([category, count]) => (
                      <div key={category} className="flex items-center justify-between">
                        <span className="text-sm text-gray-400 capitalize">
                          {category.replace('_', ' ')}
                        </span>
                        <span className="text-sm font-medium text-gray-300">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Additional context */}
              {context_analysis && (
                <div className="mt-6">
                  <h4 className="text-sm font-medium text-gray-300 mb-2">Context Analysis</h4>
                  <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3">
                    <p className="text-sm text-blue-200">
                      <strong>Overall Intent:</strong> {context_analysis.overall_intent}
                    </p>
                    <div className="mt-2 flex items-center gap-4">
                      <span className="text-xs text-blue-300">
                        Sophistication: <span className="capitalize font-medium">{context_analysis.sophistication_level}</span>
                      </span>
                      {context_analysis.coordinated_threat && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-500/20 text-blue-300 border border-blue-500/30">
                          Coordinated threat
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}