import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/router';

interface SecurityChange {
  change_type: string;
  file: string;
  line: number;
  commit?: string;
  author?: string;
  timestamp?: string;
  description: string;
  severity?: string;
  old_severity?: string;
}

interface VersionComparison {
  base_version: string;
  compare_version: string;
  vulnerabilities_added: SecurityChange[];
  vulnerabilities_fixed: SecurityChange[];
  severity_changes: SecurityChange[];
  security_score_delta: number;
  risk_trend: string;
  summary_stats: {
    base_total_findings: number;
    compare_total_findings: number;
    vulnerabilities_added: number;
    vulnerabilities_fixed: number;
    critical_added: number;
    critical_fixed: number;
    high_added: number;
    high_fixed: number;
  };
  blame_info: Record<string, string[]>;
  timeline_data: Array<{
    type: string;
    severity?: string;
    old_severity?: string;
    new_severity?: string;
    rule: string;
    file: string;
    timestamp?: string;
    author?: string;
    description: string;
  }>;
}

export default function SecurityTimeline() {
  const router = useRouter();
  const [comparison, setComparison] = useState<VersionComparison | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [credits, setCredits] = useState(0);
  
  // Form inputs
  const [baseRef, setBaseRef] = useState('main');
  const [compareRef, setCompareRef] = useState('HEAD');
  const [includeBlame, setIncludeBlame] = useState(true);

  // Fetch credit balance
  useEffect(() => {
    fetch('/api/v1/interactive/credits')
      .then(res => res.json())
      .then(data => setCredits(data.balance))
      .catch(err => console.error('Failed to fetch credits:', err));
  }, []);

  const compareVersions = async () => {
    if (credits < 6) {
      setError('Insufficient credits. Need 6 credits for version comparison.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/v1/compare-versions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          base_ref: baseRef,
          compare_ref: compareRef,
          include_blame: includeBlame
        })
      });

      if (!response.ok) {
        throw new Error(`Comparison failed: ${response.statusText}`);
      }

      const data = await response.json();
      setComparison(data.comparison);
      setCredits(data.credits_remaining);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to compare versions');
    } finally {
      setLoading(false);
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'improving': return '📈';
      case 'worsening': return '📉';
      case 'stable': return '➡️';
      default: return '❓';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'text-red-600 bg-red-50';
      case 'HIGH': return 'text-orange-600 bg-orange-50';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-50';
      case 'LOW': return 'text-green-600 bg-green-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getChangeIcon = (type: string) => {
    switch (type) {
      case 'added': return '🔴';
      case 'fixed': return '✅';
      case 'severity_change': return '⚠️';
      default: return '•';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-3xl font-bold mb-6">Security Timeline</h1>

        {/* Comparison Form */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">Compare Versions</h2>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Base Version
              </label>
              <input
                type="text"
                value={baseRef}
                onChange={(e) => setBaseRef(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500"
                placeholder="main"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Compare Version
              </label>
              <input
                type="text"
                value={compareRef}
                onChange={(e) => setCompareRef(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500"
                placeholder="feature-branch"
              />
            </div>
            
            <div className="flex items-end">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={includeBlame}
                  onChange={(e) => setIncludeBlame(e.target.checked)}
                  className="mr-2"
                />
                <span className="text-sm">Include Git Blame</span>
              </label>
            </div>
          </div>
          
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-600">
              Cost: <span className="font-semibold">6 credits</span> | 
              Balance: <span className="font-semibold">{credits} credits</span>
            </p>
            
            <button
              onClick={compareVersions}
              disabled={loading || credits < 6}
              className="px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              {loading ? 'Comparing...' : 'Compare Versions'}
            </button>
          </div>
          
          {error && (
            <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-lg">
              {error}
            </div>
          )}
        </div>

        {/* Comparison Results */}
        {comparison && (
          <>
            {/* Summary Card */}
            <div className="bg-white rounded-lg shadow-md p-6 mb-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold">
                  {comparison.base_version} → {comparison.compare_version}
                </h2>
                <div className="flex items-center gap-2">
                  <span className="text-2xl">{getTrendIcon(comparison.risk_trend)}</span>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    comparison.risk_trend === 'improving' ? 'bg-green-100 text-green-800' :
                    comparison.risk_trend === 'worsening' ? 'bg-red-100 text-red-800' :
                    'bg-gray-100 text-gray-800'
                  }`}>
                    {comparison.risk_trend.toUpperCase()}
                  </span>
                </div>
              </div>
              
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center p-4 bg-gray-50 rounded">
                  <div className="text-2xl font-bold text-gray-900">
                    {comparison.security_score_delta > 0 ? '+' : ''}{comparison.security_score_delta.toFixed(1)}
                  </div>
                  <div className="text-sm text-gray-600">Score Delta</div>
                </div>
                
                <div className="text-center p-4 bg-red-50 rounded">
                  <div className="text-2xl font-bold text-red-600">
                    +{comparison.summary_stats.vulnerabilities_added}
                  </div>
                  <div className="text-sm text-gray-600">New Issues</div>
                </div>
                
                <div className="text-center p-4 bg-green-50 rounded">
                  <div className="text-2xl font-bold text-green-600">
                    {comparison.summary_stats.vulnerabilities_fixed}
                  </div>
                  <div className="text-sm text-gray-600">Fixed</div>
                </div>
                
                <div className="text-center p-4 bg-blue-50 rounded">
                  <div className="text-2xl font-bold text-blue-600">
                    {comparison.summary_stats.compare_total_findings}
                  </div>
                  <div className="text-sm text-gray-600">Total Issues</div>
                </div>
              </div>
              
              {/* Critical/High Summary */}
              <div className="mt-4 pt-4 border-t">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <span className="text-sm font-medium text-gray-600">Critical/High Added:</span>
                    <span className="ml-2 text-red-600 font-bold">
                      {comparison.summary_stats.critical_added + comparison.summary_stats.high_added}
                    </span>
                  </div>
                  <div>
                    <span className="text-sm font-medium text-gray-600">Critical/High Fixed:</span>
                    <span className="ml-2 text-green-600 font-bold">
                      {comparison.summary_stats.critical_fixed + comparison.summary_stats.high_fixed}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Timeline */}
            <div className="bg-white rounded-lg shadow-md p-6 mb-6">
              <h2 className="text-xl font-semibold mb-4">Change Timeline</h2>
              
              <div className="space-y-3">
                {comparison.timeline_data.map((event, index) => (
                  <div key={index} className="flex items-start gap-3 p-3 hover:bg-gray-50 rounded">
                    <span className="text-xl mt-1">{getChangeIcon(event.type)}</span>
                    
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                          getSeverityColor(event.severity || event.new_severity || '')
                        }`}>
                          {event.new_severity || event.severity || 'Unknown'}
                        </span>
                        
                        {event.old_severity && (
                          <>
                            <span className="text-gray-400">←</span>
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                              getSeverityColor(event.old_severity)
                            }`}>
                              {event.old_severity}
                            </span>
                          </>
                        )}
                        
                        <span className="text-sm font-medium">{event.rule}</span>
                      </div>
                      
                      <p className="text-sm text-gray-600">{event.description}</p>
                      
                      <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                        <span>📁 {event.file}</span>
                        {event.author && <span>👤 {event.author}</span>}
                        {event.timestamp && <span>🕒 {new Date(event.timestamp).toLocaleDateString()}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Blame Information */}
            {comparison.blame_info && Object.keys(comparison.blame_info).length > 0 && (
              <div className="bg-white rounded-lg shadow-md p-6">
                <h2 className="text-xl font-semibold mb-4">Author Contributions</h2>
                
                <div className="space-y-4">
                  {Object.entries(comparison.blame_info).map(([author, changes]) => (
                    <div key={author} className="border-l-4 border-blue-500 pl-4">
                      <div className="font-medium mb-2">{author}</div>
                      <ul className="space-y-1">
                        {changes.map((change, i) => (
                          <li key={i} className="text-sm text-gray-600">• {change}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}