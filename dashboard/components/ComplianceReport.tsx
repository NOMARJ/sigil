import React, { useState, useEffect } from 'react';
import { Finding } from '@/lib/types';

interface ComplianceViolation {
  finding_id: string;
  finding_description: string;
  pattern: string;
  category: string;
  category_name?: string;
  category_description?: string;
  severity: string;
  file: string;
  line: number;
  remediation_priority: number;
}

interface ComplianceSummary {
  total_violations: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  categories_affected: number;
  compliance_score: number;
}

interface RemediationPriority {
  pattern: string;
  file: string;
  line: number;
  severity: string;
  priority: number;
  frameworks_violated: string[];
  description: string;
}

interface ComplianceMapping {
  timestamp: string;
  findings_count: number;
  frameworks_checked: string[];
  compliance_context?: string;
  violations: Record<string, ComplianceViolation[]>;
  summary: Record<string, ComplianceSummary>;
  remediation_priorities: RemediationPriority[];
  export_format: any;
  error?: string;
  credits_needed?: number;
}

interface ComplianceReportProps {
  findings: Finding[];
  onExport?: (format: string) => void;
}

export default function ComplianceReport({ findings, onExport }: ComplianceReportProps) {
  const [mapping, setMapping] = useState<ComplianceMapping | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [credits, setCredits] = useState<number>(0);
  
  // Framework selection
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>(['OWASP', 'CWE']);
  const [complianceContext, setComplianceContext] = useState<string>('general');
  const [showExportModal, setShowExportModal] = useState(false);

  // Available frameworks
  const frameworks = [
    { id: 'OWASP', name: 'OWASP Top 10 2021', icon: '🔐' },
    { id: 'CWE', name: 'Common Weakness Enumeration', icon: '📋' },
    { id: 'PCI_DSS', name: 'PCI DSS', icon: '💳' },
    { id: 'HIPAA', name: 'HIPAA', icon: '🏥' },
    { id: 'GDPR', name: 'GDPR', icon: '🇪🇺' },
    { id: 'MITRE_ATTACK', name: 'MITRE ATT&CK', icon: '🎯' }
  ];

  // Compliance contexts
  const contexts = [
    { id: 'general', name: 'General', description: 'Standard security assessment' },
    { id: 'healthcare', name: 'Healthcare', description: 'HIPAA-focused, increased severity' },
    { id: 'financial', name: 'Financial', description: 'PCI DSS focus, payment security' },
    { id: 'privacy', name: 'Privacy', description: 'GDPR emphasis, data protection' }
  ];

  // Fetch credit balance
  useEffect(() => {
    fetch('/api/v1/interactive/credits')
      .then(res => res.json())
      .then(data => setCredits(data.balance))
      .catch(err => console.error('Failed to fetch credits:', err));
  }, []);

  const generateMapping = async () => {
    if (credits < 3) {
      setError('Insufficient credits. Need 3 credits for compliance mapping.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/v1/interactive/compliance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          findings,
          frameworks: selectedFrameworks,
          compliance_context: complianceContext
        })
      });

      if (!response.ok) {
        throw new Error(`Compliance mapping failed: ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.error) {
        throw new Error(data.error);
      }
      
      setMapping(data);
      setCredits(data.credits_remaining || credits - 3);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate compliance mapping');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-600';
      case 'HIGH': return 'text-orange-600';
      case 'MEDIUM': return 'text-yellow-600';
      case 'LOW': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const getComplianceStatus = (score: number) => {
    if (score >= 90) return { icon: '✅', text: 'Compliant', color: 'text-green-600' };
    if (score >= 70) return { icon: '⚠️', text: 'Partial', color: 'text-yellow-600' };
    return { icon: '❌', text: 'Non-Compliant', color: 'text-red-600' };
  };

  const exportReport = (format: string) => {
    if (!mapping) return;
    
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(mapping.export_format, null, 2)], 
        { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `compliance-report-${Date.now()}.json`;
      a.click();
    } else if (format === 'markdown') {
      // Generate markdown report
      fetch('/api/v1/interactive/compliance/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ report: mapping })
      })
        .then(res => res.text())
        .then(markdown => {
          const blob = new Blob([markdown], { type: 'text/markdown' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `compliance-report-${Date.now()}.md`;
          a.click();
        });
    }
    
    setShowExportModal(false);
    if (onExport) onExport(format);
  };

  const toggleFramework = (frameworkId: string) => {
    setSelectedFrameworks(prev => 
      prev.includes(frameworkId)
        ? prev.filter(f => f !== frameworkId)
        : [...prev, frameworkId]
    );
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold mb-4">Compliance Assessment</h3>
      
      {!mapping ? (
        <>
          {/* Framework Selection */}
          <div className="mb-6">
            <h4 className="text-sm font-medium text-gray-700 mb-3">
              Select Compliance Frameworks
            </h4>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {frameworks.map(fw => (
                <button
                  key={fw.id}
                  onClick={() => toggleFramework(fw.id)}
                  className={`p-3 rounded-lg border-2 transition-colors text-left ${
                    selectedFrameworks.includes(fw.id)
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-xl">{fw.icon}</span>
                    <div className="flex-1">
                      <div className="text-sm font-medium">{fw.id}</div>
                      <div className="text-xs text-gray-500">{fw.name}</div>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Compliance Context */}
          <div className="mb-6">
            <h4 className="text-sm font-medium text-gray-700 mb-3">
              Compliance Context
            </h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {contexts.map(ctx => (
                <button
                  key={ctx.id}
                  onClick={() => setComplianceContext(ctx.id)}
                  className={`p-3 rounded-lg border-2 transition-colors ${
                    complianceContext === ctx.id
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <div className="text-sm font-medium">{ctx.name}</div>
                  <div className="text-xs text-gray-500">{ctx.description}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Info Box */}
          <div className="bg-blue-50 p-4 rounded-lg mb-6">
            <p className="text-sm text-blue-900">
              <strong>Compliance Mapping</strong> will analyze {findings.length} findings against{' '}
              {selectedFrameworks.length} framework{selectedFrameworks.length !== 1 ? 's' : ''}{' '}
              to identify regulatory violations, map to specific requirements, and prioritize remediation.
            </p>
            <p className="text-xs text-blue-700 mt-2">
              Severity will be adjusted based on your {complianceContext} context.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-600">
              <span>Credit cost: </span>
              <span className="font-semibold">3 credits</span>
              <span className="ml-2">({credits} available)</span>
            </div>
            
            <button
              onClick={generateMapping}
              disabled={loading || credits < 3 || selectedFrameworks.length === 0}
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              {loading ? 'Analyzing...' : 'Generate Compliance Report'}
            </button>
          </div>

          {error && (
            <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-lg">
              {error}
            </div>
          )}
        </>
      ) : (
        /* Compliance Report Results */
        <div className="space-y-6">
          {/* Executive Summary */}
          <div className="bg-gradient-to-r from-blue-50 to-indigo-50 p-6 rounded-lg">
            <h4 className="text-lg font-semibold mb-4">Executive Summary</h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Object.entries(mapping.summary).map(([framework, summary]) => {
                const status = getComplianceStatus(summary.compliance_score);
                return (
                  <div key={framework} className="bg-white p-4 rounded-lg shadow-sm">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium">{framework}</span>
                      <span className="text-2xl">{status.icon}</span>
                    </div>
                    <div className={`text-2xl font-bold ${status.color}`}>
                      {summary.compliance_score}%
                    </div>
                    <div className="text-xs text-gray-600 mt-1">
                      {summary.total_violations} violations
                    </div>
                    <div className={`text-xs font-medium mt-2 ${status.color}`}>
                      {status.text}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Top Remediation Priorities */}
          {mapping.remediation_priorities.length > 0 && (
            <div>
              <h4 className="font-semibold mb-3">Top Remediation Priorities</h4>
              <div className="bg-gray-50 rounded-lg overflow-hidden">
                <table className="min-w-full">
                  <thead className="bg-gray-100">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-700">Priority</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-700">Severity</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-700">Issue</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-700">Location</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-700">Frameworks</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {mapping.remediation_priorities.slice(0, 10).map((priority, i) => (
                      <tr key={i} className="hover:bg-gray-50">
                        <td className="px-4 py-2">
                          <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-blue-100 text-blue-700 text-xs font-bold">
                            {priority.priority}
                          </span>
                        </td>
                        <td className="px-4 py-2">
                          <span className={`font-medium text-sm ${getSeverityColor(priority.severity)}`}>
                            {priority.severity}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-sm">
                          {priority.description.substring(0, 60)}...
                        </td>
                        <td className="px-4 py-2">
                          <code className="text-xs bg-gray-100 px-1 py-0.5 rounded">
                            {priority.file}:{priority.line}
                          </code>
                        </td>
                        <td className="px-4 py-2">
                          <div className="flex flex-wrap gap-1">
                            {priority.frameworks_violated.map(fw => (
                              <span key={fw} className="text-xs bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded">
                                {fw}
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Detailed Violations */}
          <details className="cursor-pointer">
            <summary className="font-semibold text-sm hover:text-blue-600">
              Detailed Violations by Framework
            </summary>
            <div className="mt-4 space-y-4">
              {Object.entries(mapping.violations).map(([framework, violations]) => (
                violations.length > 0 && (
                  <div key={framework} className="border-l-4 border-blue-500 pl-4">
                    <h5 className="font-medium mb-2">{framework}</h5>
                    <div className="space-y-2">
                      {violations.slice(0, 5).map((violation, i) => (
                        <div key={i} className="text-sm bg-gray-50 p-2 rounded">
                          <div className="flex items-start justify-between">
                            <div>
                              <span className={`font-medium ${getSeverityColor(violation.severity)}`}>
                                {violation.severity}
                              </span>
                              <span className="ml-2 text-gray-700">
                                {violation.category_name || violation.category}
                              </span>
                            </div>
                            <code className="text-xs text-gray-500">
                              {violation.file}:{violation.line}
                            </code>
                          </div>
                          <p className="text-xs text-gray-600 mt-1">
                            {violation.finding_description}
                          </p>
                        </div>
                      ))}
                      {violations.length > 5 && (
                        <p className="text-xs text-gray-500 italic">
                          +{violations.length - 5} more violations
                        </p>
                      )}
                    </div>
                  </div>
                )
              ))}
            </div>
          </details>

          {/* Actions */}
          <div className="flex gap-3 pt-4 border-t">
            <button 
              onClick={() => setMapping(null)}
              className="px-4 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300"
            >
              New Assessment
            </button>
            <button 
              onClick={() => setShowExportModal(true)}
              className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
            >
              Export Report
            </button>
          </div>

          {/* Export Modal */}
          {showExportModal && (
            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
              <div className="bg-white p-6 rounded-lg shadow-xl">
                <h3 className="text-lg font-semibold mb-4">Export Compliance Report</h3>
                <div className="space-y-3">
                  <button
                    onClick={() => exportReport('json')}
                    className="w-full px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded text-left"
                  >
                    📄 JSON (For Auditors)
                  </button>
                  <button
                    onClick={() => exportReport('markdown')}
                    className="w-full px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded text-left"
                  >
                    📝 Markdown (For Documentation)
                  </button>
                </div>
                <button
                  onClick={() => setShowExportModal(false)}
                  className="mt-4 px-4 py-2 bg-gray-500 text-white rounded hover:bg-gray-600"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}