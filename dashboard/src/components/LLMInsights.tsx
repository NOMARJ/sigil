import { useState } from "react";
import ThreatExplanation from "@/components/ThreatExplanation";
import ConfidenceScore, { ConfidenceDistribution } from "@/components/ConfidenceScore";
import type { LLMInsight, LLMContextAnalysis, LLMThreatCategory, LLMConfidenceLevel } from "@/lib/types";

interface LLMInsightsProps {
  insights: LLMInsight[];
  contextAnalysis: LLMContextAnalysis | null;
}

type ViewMode = "cards" | "table";
type FilterCategory = LLMThreatCategory | "all";
type FilterConfidence = LLMConfidenceLevel | "all";

export default function LLMInsights({ 
  insights, 
  contextAnalysis 
}: LLMInsightsProps): JSX.Element {
  const [viewMode, setViewMode] = useState<ViewMode>("cards");
  const [categoryFilter, setCategoryFilter] = useState<FilterCategory>("all");
  const [confidenceFilter, setConfidenceFilter] = useState<FilterConfidence>("all");
  const [searchQuery, setSearchQuery] = useState("");

  // Filter insights based on selected filters and search
  const filteredInsights = insights.filter(insight => {
    const matchesCategory = categoryFilter === "all" || insight.threat_category === categoryFilter;
    const matchesConfidence = confidenceFilter === "all" || insight.confidence_level === confidenceFilter;
    const matchesSearch = searchQuery === "" || 
      insight.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      insight.description.toLowerCase().includes(searchQuery.toLowerCase());
    
    return matchesCategory && matchesConfidence && matchesSearch;
  });

  // Calculate confidence distribution for filtered insights
  const confidenceSummary = filteredInsights.reduce((acc, insight) => {
    acc[insight.confidence_level] = (acc[insight.confidence_level] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // Get unique categories for filter dropdown
  const uniqueCategories = Array.from(new Set(insights.map(i => i.threat_category)));
  const zeroDay = insights.filter(i => i.analysis_type === "zero_day_detection");

  return (
    <div className="space-y-6">
      {/* Context Analysis Alert (if attack chain detected) */}
      {contextAnalysis?.attack_chain_detected && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-red-400 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <div className="flex-1">
              <h3 className="text-sm font-semibold text-red-400 mb-2">
                🚨 Coordinated Attack Chain Detected
              </h3>
              <p className="text-sm text-red-300 mb-3">
                {contextAnalysis.overall_intent}
              </p>
              
              <div className="space-y-2">
                <p className="text-xs font-medium text-red-400">Attack Chain Steps:</p>
                <ol className="list-decimal list-inside space-y-1 text-xs text-red-300/80">
                  {contextAnalysis.attack_chain_steps.map((step, index) => (
                    <li key={index}>{step}</li>
                  ))}
                </ol>
              </div>

              <div className="mt-3 flex items-center gap-4">
                <span className="text-xs text-red-400">
                  Sophistication: <span className="font-semibold capitalize">{contextAnalysis.sophistication_level}</span>
                </span>
                {contextAnalysis.coordinated_threat && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-500/20 text-red-300 border border-red-500/30">
                    Multi-file coordination
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Header & Controls */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-100 tracking-tight">
            LLM Security Insights
          </h2>
          <p className="text-sm text-gray-500 mt-1">
            AI-powered threat analysis and zero-day detection
          </p>
        </div>

        {/* View toggle */}
        <div className="flex items-center gap-1 bg-gray-800 rounded-lg p-1">
          <button
            onClick={() => setViewMode("cards")}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
              viewMode === "cards" 
                ? "bg-brand-600 text-white" 
                : "text-gray-400 hover:text-gray-200"
            }`}
          >
            Cards
          </button>
          <button
            onClick={() => setViewMode("table")}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
              viewMode === "table" 
                ? "bg-brand-600 text-white" 
                : "text-gray-400 hover:text-gray-200"
            }`}
          >
            Table
          </button>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Search */}
        <div>
          <input
            type="text"
            placeholder="Search insights..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input w-full"
          />
        </div>

        {/* Category Filter */}
        <div>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value as FilterCategory)}
            className="input w-full"
          >
            <option value="all">All Categories</option>
            {uniqueCategories.map(category => (
              <option key={category} value={category}>
                {category.replace(/_/g, ' ').toUpperCase()}
              </option>
            ))}
          </select>
        </div>

        {/* Confidence Filter */}
        <div>
          <select
            value={confidenceFilter}
            onChange={(e) => setConfidenceFilter(e.target.value as FilterConfidence)}
            className="input w-full"
          >
            <option value="all">All Confidence</option>
            <option value="very_high">Very High</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        {/* Stats */}
        <div className="flex items-center justify-end gap-4 text-xs text-gray-500">
          <span>{filteredInsights.length} insights</span>
          {zeroDay.length > 0 && (
            <span className="text-red-400 font-medium">
              {zeroDay.length} zero-day
            </span>
          )}
        </div>
      </div>

      {/* Confidence Distribution */}
      {filteredInsights.length > 0 && (
        <div className="card">
          <div className="card-body">
            <ConfidenceDistribution 
              summary={confidenceSummary} 
              total={filteredInsights.length} 
            />
          </div>
        </div>
      )}

      {/* Results */}
      {filteredInsights.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <p className="text-sm">No insights match your filters.</p>
        </div>
      ) : viewMode === "cards" ? (
        /* Cards View */
        <div className="space-y-4">
          {filteredInsights.map((insight, index) => (
            <ThreatExplanation
              key={index}
              insight={insight}
              isZeroDay={insight.analysis_type === "zero_day_detection"}
            />
          ))}
        </div>
      ) : (
        /* Table View */
        <div className="overflow-hidden rounded-lg border border-gray-800">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 bg-gray-900/50">
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Threat
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Category
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Confidence
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Files
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Severity
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {filteredInsights.map((insight, index) => (
                  <tr key={index} className="hover:bg-gray-800/30 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {insight.analysis_type === "zero_day_detection" && (
                          <span className="text-red-400 text-xs">🚨</span>
                        )}
                        <div>
                          <div className="font-medium text-gray-300 text-sm">
                            {insight.title}
                          </div>
                          <div className="text-xs text-gray-500 truncate max-w-xs">
                            {insight.description}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700">
                        {insight.threat_category.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <ConfidenceScore 
                        confidence={insight.confidence}
                        confidenceLevel={insight.confidence_level}
                        size="sm"
                        showLabel={false}
                      />
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-gray-400 text-xs">
                        {insight.affected_files.length} files
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-medium ${
                        insight.severity_adjustment > 0 ? 'text-red-400' : 
                        insight.severity_adjustment < 0 ? 'text-green-400' : 'text-gray-400'
                      }`}>
                        {insight.severity_adjustment > 0 ? '+' : ''}{insight.severity_adjustment.toFixed(1)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}