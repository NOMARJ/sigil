import React, { useState, useEffect } from 'react';
import { Finding } from '@/lib/types';

interface ContextExpansion {
  original_files: string[];
  expanded_files: string[];
  dependencies_added: string[];
  context_size_kb: number;
  credit_cost: number;
  findings_before: Finding[];
  findings_after: Finding[];
  assessment_changes: Array<{
    type: string;
    file: string;
    rule: string;
    before?: string;
    after?: string;
    severity?: string;
    reason: string;
  }>;
  confidence_improvement: number;
}

interface ContextSelectorProps {
  findings: Finding[];
  scanPath?: string;
  onContextExpanded?: (expansion: ContextExpansion) => void;
}

export default function ContextSelector({ 
  findings, 
  scanPath,
  onContextExpanded 
}: ContextSelectorProps) {
  const [expansion, setExpansion] = useState<ContextExpansion | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [credits, setCredits] = useState<number>(0);
  
  // Expansion options
  const [expansionType, setExpansionType] = useState<string>('smart');
  const [customFiles, setCustomFiles] = useState<string>('');
  const [showCustomInput, setShowCustomInput] = useState(false);

  // Fetch credit balance
  useEffect(() => {
    fetch('/api/v1/interactive/credits')
      .then(res => res.json())
      .then(data => setCredits(data.balance))
      .catch(err => console.error('Failed to fetch credits:', err));
  }, []);

  const expandContext = async () => {
    const creditCosts: Record<string, number> = {
      smart: 4,
      dependencies: 3,
      configs: 2,
      custom: 2
    };
    
    const cost = creditCosts[expansionType] || 4;
    
    if (credits < cost) {
      setError(`Insufficient credits. Need ${cost} credits for ${expansionType} expansion.`);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const payload: any = {
        initial_findings: findings,
        scan_path: scanPath || '.',
        expansion_type: expansionType
      };
      
      if (expansionType === 'custom' && customFiles) {
        payload.specific_files = customFiles.split('\n').filter(f => f.trim());
      }

      const response = await fetch('/api/v1/interactive/expand-context', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`Context expansion failed: ${response.statusText}`);
      }

      const data = await response.json();
      setExpansion(data.expansion);
      setCredits(data.credits_remaining);
      
      if (onContextExpanded) {
        onContextExpanded(data.expansion);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to expand context');
    } finally {
      setLoading(false);
    }
  };

  const getExpansionIcon = (type: string) => {
    switch (type) {
      case 'smart': return '🧠';
      case 'dependencies': return '📦';
      case 'configs': return '⚙️';
      case 'custom': return '📝';
      default: return '📂';
    }
  };

  const getChangeIcon = (type: string) => {
    switch (type) {
      case 'severity_change': return '⚠️';
      case 'new_finding': return '🔴';
      case 'false_positive': return '✅';
      default: return '•';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'text-red-600';
      case 'HIGH': return 'text-orange-600';
      case 'MEDIUM': return 'text-yellow-600';
      case 'LOW': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold mb-4">Context Expansion</h3>
      
      {!expansion ? (
        <>
          {/* Expansion Options */}
          <div className="mb-6">
            <p className="text-sm text-gray-600 mb-4">
              Expand analysis context to improve accuracy and reduce false positives
            </p>
            
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
              <button
                onClick={() => {
                  setExpansionType('smart');
                  setShowCustomInput(false);
                }}
                className={`p-3 rounded-lg border-2 transition-colors ${
                  expansionType === 'smart' 
                    ? 'border-green-500 bg-green-50' 
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="text-2xl mb-1">🧠</div>
                <div className="text-sm font-medium">Smart</div>
                <div className="text-xs text-gray-500">4 credits</div>
              </button>
              
              <button
                onClick={() => {
                  setExpansionType('dependencies');
                  setShowCustomInput(false);
                }}
                className={`p-3 rounded-lg border-2 transition-colors ${
                  expansionType === 'dependencies' 
                    ? 'border-green-500 bg-green-50' 
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="text-2xl mb-1">📦</div>
                <div className="text-sm font-medium">Dependencies</div>
                <div className="text-xs text-gray-500">3 credits</div>
              </button>
              
              <button
                onClick={() => {
                  setExpansionType('configs');
                  setShowCustomInput(false);
                }}
                className={`p-3 rounded-lg border-2 transition-colors ${
                  expansionType === 'configs' 
                    ? 'border-green-500 bg-green-50' 
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="text-2xl mb-1">⚙️</div>
                <div className="text-sm font-medium">Configs</div>
                <div className="text-xs text-gray-500">2 credits</div>
              </button>
              
              <button
                onClick={() => {
                  setExpansionType('custom');
                  setShowCustomInput(true);
                }}
                className={`p-3 rounded-lg border-2 transition-colors ${
                  expansionType === 'custom' 
                    ? 'border-green-500 bg-green-50' 
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="text-2xl mb-1">📝</div>
                <div className="text-sm font-medium">Custom</div>
                <div className="text-xs text-gray-500">2 credits</div>
              </button>
            </div>
            
            {/* Custom file input */}
            {showCustomInput && (
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Specify files to include (one per line)
                </label>
                <textarea
                  value={customFiles}
                  onChange={(e) => setCustomFiles(e.target.value)}
                  className="w-full h-32 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500"
                  placeholder="package.json&#10;src/config.js&#10;.env"
                />
              </div>
            )}
            
            {/* Expansion type description */}
            <div className="bg-blue-50 p-3 rounded mb-4">
              <div className="text-sm">
                {expansionType === 'smart' && (
                  <>
                    <strong>Smart Expansion:</strong> Intelligently selects dependencies, configs, and imported files
                    based on your findings. Best for comprehensive analysis.
                  </>
                )}
                {expansionType === 'dependencies' && (
                  <>
                    <strong>Dependencies Only:</strong> Adds package.json, requirements.txt, and other dependency
                    files to detect supply chain issues.
                  </>
                )}
                {expansionType === 'configs' && (
                  <>
                    <strong>Configs Only:</strong> Includes .env, docker-compose.yml, and configuration files
                    to assess security settings.
                  </>
                )}
                {expansionType === 'custom' && (
                  <>
                    <strong>Custom Files:</strong> Add specific files you want included in the analysis.
                    Useful for targeted investigation.
                  </>
                )}
              </div>
            </div>
          </div>
          
          {/* Action buttons */}
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-600">
              <span>Credit balance: </span>
              <span className="font-semibold">{credits} credits</span>
            </div>
            
            <button
              onClick={expandContext}
              disabled={loading || credits < 2}
              className="px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              {loading ? 'Expanding...' : 'Expand Context'}
            </button>
          </div>
          
          {error && (
            <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-lg">
              {error}
            </div>
          )}
        </>
      ) : (
        /* Expansion Results */
        <div className="space-y-4">
          {/* Summary */}
          <div className="bg-green-50 p-4 rounded-lg">
            <div className="flex items-center justify-between mb-2">
              <span className="text-lg font-semibold text-green-800">
                Context Expanded Successfully
              </span>
              <span className="text-2xl">
                {expansion.confidence_improvement > 0 ? '📈' : '📊'}
              </span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="text-gray-600">Files analyzed:</span>
                <p className="font-semibold">{expansion.expanded_files.length}</p>
              </div>
              <div>
                <span className="text-gray-600">Context size:</span>
                <p className="font-semibold">{expansion.context_size_kb.toFixed(1)} KB</p>
              </div>
              <div>
                <span className="text-gray-600">Dependencies found:</span>
                <p className="font-semibold">{expansion.dependencies_added.length}</p>
              </div>
              <div>
                <span className="text-gray-600">Confidence improved:</span>
                <p className="font-semibold text-green-600">
                  +{(expansion.confidence_improvement * 100).toFixed(0)}%
                </p>
              </div>
            </div>
          </div>
          
          {/* Assessment Changes */}
          {expansion.assessment_changes.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2">Assessment Changes</h4>
              <div className="space-y-2">
                {expansion.assessment_changes.map((change, i) => (
                  <div key={i} className="flex items-start gap-2 p-2 bg-gray-50 rounded">
                    <span className="text-lg">{getChangeIcon(change.type)}</span>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-sm">{change.rule}</span>
                        {change.before && change.after && (
                          <>
                            <span className={`text-xs ${getSeverityColor(change.before)}`}>
                              {change.before}
                            </span>
                            <span>→</span>
                            <span className={`text-xs ${getSeverityColor(change.after)}`}>
                              {change.after}
                            </span>
                          </>
                        )}
                        {change.severity && (
                          <span className={`text-xs ${getSeverityColor(change.severity)}`}>
                            {change.severity}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-gray-600">{change.reason}</p>
                      <p className="text-xs text-gray-500">📁 {change.file}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {/* Expanded Files */}
          <details className="cursor-pointer">
            <summary className="font-semibold text-sm hover:text-green-600">
              Files Analyzed ({expansion.expanded_files.length})
            </summary>
            <div className="mt-2 max-h-40 overflow-y-auto">
              <ul className="space-y-1">
                {expansion.expanded_files.map((file, i) => (
                  <li key={i} className="text-xs text-gray-600 pl-4">
                    • {file}
                  </li>
                ))}
              </ul>
            </div>
          </details>
          
          {/* Dependencies */}
          {expansion.dependencies_added.length > 0 && (
            <details className="cursor-pointer">
              <summary className="font-semibold text-sm hover:text-green-600">
                Dependencies Found ({expansion.dependencies_added.length})
              </summary>
              <div className="mt-2 max-h-40 overflow-y-auto">
                <div className="flex flex-wrap gap-2">
                  {expansion.dependencies_added.map((dep, i) => (
                    <span key={i} className="px-2 py-1 bg-blue-100 text-blue-700 text-xs rounded">
                      {dep}
                    </span>
                  ))}
                </div>
              </div>
            </details>
          )}
          
          {/* Actions */}
          <div className="flex gap-3 pt-4 border-t">
            <button 
              onClick={() => setExpansion(null)}
              className="px-4 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300"
            >
              Expand Again
            </button>
            <button className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700">
              Apply Changes
            </button>
          </div>
        </div>
      )}
    </div>
  );
}