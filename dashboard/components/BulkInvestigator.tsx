import React, { useState, useEffect, useCallback } from 'react';
import { Finding } from '@/lib/types';

interface PatternGroup {
  pattern_type: string;
  group_name: string;
  findings_count: number;
  files_affected: string[];
  severity_distribution: Record<string, number>;
  likely_same_root_cause: boolean;
  root_cause_similarity: number;
  single_fix_possible?: boolean;
  fix_suggestion?: {
    title: string;
    description: string;
    example: string;
    estimated_effort: string;
  };
  analysis?: string;
  key_insights?: string[];
}

interface BulkAnalysisResult {
  timestamp: string;
  total_findings: number;
  pattern_groups: Record<string, PatternGroup>;
  summary: {
    total_groups: number;
    patterns_found: Array<{ type: string; count: number; severity: string }>;
    critical_issues: number;
    high_priority_fixes: Array<{
      pattern: string;
      title: string;
      impact: string;
      effort: string;
    }>;
    estimated_total_effort: string;
    root_causes_identified: number;
  };
  recommendations: Array<{
    priority: number;
    type: string;
    pattern: string;
    title: string;
    description: string;
    impact: string;
    effort: string;
    affected_files: number;
  }>;
  credits_used: number;
}

interface BulkInvestigatorProps {
  findings: Finding[];
  onAnalysisComplete?: (result: BulkAnalysisResult) => void;
}

export default function BulkInvestigator({ findings, onAnalysisComplete }: BulkInvestigatorProps) {
  const [patternGroups, setPatternGroups] = useState<Record<string, PatternGroup> | null>(null);
  const [selectedGroups, setSelectedGroups] = useState<Set<string>>(new Set());
  const [analysisResult, setAnalysisResult] = useState<BulkAnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [credits, setCredits] = useState<number>(0);
  const [depth, setDepth] = useState<'quick' | 'thorough' | 'exhaustive'>('thorough');
  const [showResults, setShowResults] = useState(false);

  // Fetch credit balance
  useEffect(() => {
    fetch('/api/v1/interactive/credits')
      .then(res => res.json())
      .then(data => setCredits(data.balance))
      .catch(err => console.error('Failed to fetch credits:', err));
  }, []);

  // Group findings when findings change
  const groupFindings = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/interactive/bulk/group', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findings })
      });
      
      if (response.ok) {
        const groups = await response.json();
        setPatternGroups(groups);
        // Auto-select groups with likely same root cause
        const autoSelect = new Set<string>();
        Object.entries(groups).forEach(([type, group]: [string, any]) => {
          if (group.likely_same_root_cause) {
            autoSelect.add(type);
          }
        });
        setSelectedGroups(autoSelect);
      }
    } catch (err) {
      console.error('Failed to group findings:', err);
    }
  }, [findings]);

  // Group findings on component mount
  useEffect(() => {
    groupFindings();
  }, [groupFindings]);

  const toggleGroup = (patternType: string) => {
    const newSelection = new Set(selectedGroups);
    if (newSelection.has(patternType)) {
      newSelection.delete(patternType);
    } else {
      newSelection.add(patternType);
    }
    setSelectedGroups(newSelection);
  };

  const selectAll = () => {
    if (patternGroups) {
      setSelectedGroups(new Set(Object.keys(patternGroups)));
    }
  };

  const deselectAll = () => {
    setSelectedGroups(new Set());
  };

  const estimateCredits = (): number => {
    const baseCosts = { quick: 3, thorough: 5, exhaustive: 10 };
    const baseCost = baseCosts[depth];
    let total = 0;
    
    selectedGroups.forEach(type => {
      if (patternGroups && patternGroups[type]) {
        const group = patternGroups[type];
        const multiplier = 1 + (Math.min(group.findings_count, 10) * 0.1);
        total += Math.floor(baseCost * multiplier);
      }
    });
    
    return total;
  };

  const classifyPattern = useCallback((finding: Finding): string => {
    // Simplified pattern classification for component
    const pattern = finding.pattern_matched.toUpperCase();
    if (pattern.includes('SQL')) return 'SQL_INJECTION';
    if (pattern.includes('XSS')) return 'XSS';
    if (pattern.includes('COMMAND')) return 'COMMAND_INJECTION';
    if (pattern.includes('PATH')) return 'PATH_TRAVERSAL';
    if (pattern.includes('SECRET') || pattern.includes('KEY')) return 'HARDCODED_SECRET';
    return 'OTHER';
  }, []);

  const runBulkAnalysis = useCallback(async () => {
    if (selectedGroups.size === 0) {
      setError('Please select at least one pattern group to analyze');
      return;
    }

    const estimatedCredits = estimateCredits();
    if (credits < estimatedCredits) {
      setError(`Insufficient credits. Need ${estimatedCredits} credits.`);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Get selected findings
      const selectedFindings: Finding[] = [];
      selectedGroups.forEach(type => {
        if (patternGroups && patternGroups[type]) {
          // Note: In real implementation, we'd need the actual findings
          // This is simplified for the component
          selectedFindings.push(...findings.filter(f => 
            classifyPattern(f) === type
          ));
        }
      });

      const response = await fetch('/api/v1/interactive/bulk/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          findings: selectedFindings,
          investigation_depth: depth,
          group_by_pattern: true
        })
      });

      if (!response.ok) {
        throw new Error('Bulk analysis failed');
      }

      const result = await response.json();
      setAnalysisResult(result);
      setShowResults(true);
      setCredits(prev => prev - result.credits_used);
      
      if (onAnalysisComplete) {
        onAnalysisComplete(result);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  }, [selectedGroups, patternGroups, findings, depth, credits, onAnalysisComplete, classifyPattern]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-600';
      case 'HIGH': return 'text-orange-600';
      case 'MEDIUM': return 'text-yellow-600';
      case 'LOW': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const getSeverityBadge = (severity: string, count: number) => (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
      severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
      severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
      severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
      'bg-green-100 text-green-800'
    }`}>
      {count} {severity}
    </span>
  );

  if (showResults && analysisResult) {
    return (
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">Bulk Analysis Results</h3>
          <button
            onClick={() => setShowResults(false)}
            className="text-gray-500 hover:text-gray-700"
          >
            ← Back
          </button>
        </div>

        {/* Summary */}
        <div className="bg-blue-50 p-4 rounded-lg mb-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-sm text-gray-600">Total Findings</p>
              <p className="text-2xl font-bold">{analysisResult.total_findings}</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Pattern Groups</p>
              <p className="text-2xl font-bold">{analysisResult.summary.total_groups}</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Root Causes</p>
              <p className="text-2xl font-bold">{analysisResult.summary.root_causes_identified}</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Est. Effort</p>
              <p className="text-xl font-bold">{analysisResult.summary.estimated_total_effort}</p>
            </div>
          </div>
        </div>

        {/* High Priority Fixes */}
        {analysisResult.summary.high_priority_fixes.length > 0 && (
          <div className="mb-6">
            <h4 className="font-semibold mb-3">🎯 High Priority Fixes</h4>
            <div className="space-y-2">
              {analysisResult.summary.high_priority_fixes.map((fix, i) => (
                <div key={i} className="bg-green-50 p-3 rounded-lg">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="font-medium">{fix.title}</p>
                      <p className="text-sm text-gray-600 mt-1">
                        Impact: {fix.impact} • Effort: {fix.effort}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Pattern Group Results */}
        <div className="space-y-4">
          {Object.entries(analysisResult.pattern_groups).map(([type, group]) => (
            <div key={type} className="border rounded-lg p-4">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h5 className="font-medium">{group.group_name}</h5>
                  <p className="text-sm text-gray-600">
                    {group.findings_count} findings across {group.files_affected.length} files
                  </p>
                </div>
                {group.single_fix_possible && (
                  <span className="bg-green-100 text-green-800 text-xs px-2 py-1 rounded">
                    Single Fix Possible
                  </span>
                )}
              </div>

              {/* Key Insights */}
              {group.key_insights && group.key_insights.length > 0 && (
                <div className="mb-3">
                  <p className="text-sm font-medium mb-1">Key Insights:</p>
                  <ul className="text-sm text-gray-700 space-y-1">
                    {group.key_insights.map((insight, i) => (
                      <li key={i} className="flex items-start">
                        <span className="mr-2">•</span>
                        <span>{insight}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Fix Suggestion */}
              {group.fix_suggestion && (
                <div className="bg-gray-50 p-3 rounded mt-3">
                  <p className="font-medium text-sm">{group.fix_suggestion.title}</p>
                  <p className="text-sm text-gray-600 mt-1">{group.fix_suggestion.description}</p>
                  {group.fix_suggestion.example && (
                    <pre className="mt-2 p-2 bg-gray-900 text-gray-100 rounded text-xs overflow-x-auto">
                      <code>{group.fix_suggestion.example}</code>
                    </pre>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Recommendations */}
        {analysisResult.recommendations.length > 0 && (
          <div className="mt-6">
            <h4 className="font-semibold mb-3">📋 Prioritized Recommendations</h4>
            <div className="space-y-2">
              {analysisResult.recommendations.slice(0, 5).map((rec, i) => (
                <div key={i} className={`p-3 rounded-lg border-l-4 ${
                  rec.priority === 1 ? 'border-red-500 bg-red-50' :
                  rec.priority === 2 ? 'border-orange-500 bg-orange-50' :
                  'border-blue-500 bg-blue-50'
                }`}>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <p className="font-medium">{rec.title}</p>
                      <p className="text-sm text-gray-600 mt-1">{rec.description}</p>
                      <p className="text-xs text-gray-500 mt-1">
                        {rec.impact} • {rec.effort} • {rec.affected_files} files
                      </p>
                    </div>
                    <span className={`ml-2 px-2 py-1 text-xs rounded ${
                      rec.priority === 1 ? 'bg-red-200 text-red-800' :
                      rec.priority === 2 ? 'bg-orange-200 text-orange-800' :
                      'bg-blue-200 text-blue-800'
                    }`}>
                      P{rec.priority}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold mb-4">Bulk Pattern Investigation</h3>
      
      {!patternGroups ? (
        <div className="text-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-600 mx-auto"></div>
          <p className="mt-2 text-gray-600">Grouping findings by pattern...</p>
        </div>
      ) : (
        <>
          {/* Depth Selection */}
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Analysis Depth
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(['quick', 'thorough', 'exhaustive'] as const).map(d => (
                <button
                  key={d}
                  onClick={() => setDepth(d)}
                  className={`px-3 py-2 rounded-lg border ${
                    depth === d
                      ? 'border-green-500 bg-green-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <div className="text-sm font-medium capitalize">{d}</div>
                  <div className="text-xs text-gray-500">
                    {d === 'quick' ? '~3 credits' : d === 'thorough' ? '~5 credits' : '~10 credits'}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Pattern Groups */}
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <label className="text-sm font-medium text-gray-700">
                Select Pattern Groups ({selectedGroups.size} selected)
              </label>
              <div className="space-x-2">
                <button
                  onClick={selectAll}
                  className="text-xs text-blue-600 hover:text-blue-700"
                >
                  Select All
                </button>
                <button
                  onClick={deselectAll}
                  className="text-xs text-gray-600 hover:text-gray-700"
                >
                  Clear
                </button>
              </div>
            </div>
            
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {Object.entries(patternGroups).map(([type, group]) => (
                <div
                  key={type}
                  onClick={() => toggleGroup(type)}
                  className={`p-3 rounded-lg border-2 cursor-pointer transition-colors ${
                    selectedGroups.has(type)
                      ? 'border-green-500 bg-green-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={selectedGroups.has(type)}
                          onChange={() => {}}
                          className="rounded text-green-600"
                        />
                        <span className="font-medium">{group.group_name}</span>
                        {group.likely_same_root_cause && (
                          <span className="text-xs bg-yellow-100 text-yellow-800 px-2 py-0.5 rounded">
                            Same Root Cause
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-gray-600 mt-1 ml-6">
                        {group.findings_count} findings • {group.files_affected.length} files
                      </p>
                      <div className="flex gap-2 mt-1 ml-6">
                        {Object.entries(group.severity_distribution).map(([sev, count]) => (
                          <span key={sev}>{getSeverityBadge(sev, count as number)}</span>
                        ))}
                      </div>
                    </div>
                    {group.root_cause_similarity > 0 && (
                      <div className="text-right">
                        <p className="text-xs text-gray-500">Similarity</p>
                        <p className="text-sm font-medium">
                          {Math.round(group.root_cause_similarity * 100)}%
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-between pt-4 border-t">
            <div className="text-sm text-gray-600">
              <span>Estimated cost: </span>
              <span className="font-semibold">{estimateCredits()} credits</span>
              <span className="ml-2">({credits} available)</span>
            </div>
            
            <button
              onClick={runBulkAnalysis}
              disabled={loading || selectedGroups.size === 0 || credits < estimateCredits()}
              className="px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              {loading ? 'Analyzing...' : `Analyze ${selectedGroups.size} Groups`}
            </button>
          </div>

          {error && (
            <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-lg">
              {error}
            </div>
          )}
        </>
      )}
    </div>
  );
}