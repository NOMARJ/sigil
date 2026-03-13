import React, { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/router';
import { format } from 'date-fns';

interface ConversationEntry {
  type: string;
  timestamp: string;
  credits_used: number;
  request?: any;
  response?: any;
}

interface SessionData {
  session_id: string;
  scan_id: string;
  status: string;
  owner_id: string;
  is_owner: boolean;
  findings_context: {
    total: number;
    by_severity: Record<string, number>;
    by_phase: Record<string, number>;
    files: string[];
  };
  conversation_history: ConversationEntry[];
  model_preference: string;
  share_url: string;
  expires_at: string;
  started_at: string;
  last_activity: string;
  completed_at?: string;
  total_credits_used: number;
  statistics: {
    total_interactions: number;
    investigations: number;
    false_positive_checks: number;
    remediations: number;
    chats: number;
    avg_credits: number;
  };
}

export default function SessionPage() {
  const router = useRouter();
  const { id } = router.query;
  
  const [session, setSession] = useState<SessionData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showExportModal, setShowExportModal] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);

  useEffect(() => {
    if (id) {
      fetchSession();
    }
  }, [id, fetchSession]);

  const fetchSession = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Try to fetch session by share token
      const response = await fetch(`/api/v1/interactive/sessions/shared/${id}`);
      
      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('Session not found or expired');
        }
        throw new Error('Failed to load session');
      }
      
      const data = await response.json();
      setSession(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load session');
    } finally {
      setLoading(false);
    }
  }, [id]);

  const exportSession = async (format: 'markdown' | 'json') => {
    if (!session) return;
    
    try {
      if (format === 'markdown') {
        const response = await fetch('/api/v1/interactive/sessions/export', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ share_token: id })
        });
        
        const markdown = await response.text();
        
        const blob = new Blob([markdown], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `session-${session.session_id}.md`;
        a.click();
      } else {
        // Export as JSON
        const blob = new Blob([JSON.stringify(session, null, 2)], 
          { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `session-${session.session_id}.json`;
        a.click();
      }
      
      setShowExportModal(false);
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  const copyShareLink = () => {
    const shareUrl = `${window.location.origin}/session/${id}`;
    navigator.clipboard.writeText(shareUrl).then(() => {
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    });
  };

  const continueSession = () => {
    if (session?.is_owner) {
      router.push(`/scan/${session.scan_id}#interactive`);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'text-red-600';
      case 'HIGH': return 'text-orange-600';
      case 'MEDIUM': return 'text-yellow-600';
      case 'LOW': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const getInteractionIcon = (type: string) => {
    switch (type) {
      case 'investigation': return '🔍';
      case 'false_positive_analysis': return '✅';
      case 'remediation': return '🔧';
      case 'chat': return '💬';
      case 'compliance': return '📋';
      case 'attack_chain': return '🎯';
      case 'version_comparison': return '📊';
      default: return '📝';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-green-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading session...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-white p-8 rounded-lg shadow-md max-w-md">
          <h2 className="text-xl font-semibold text-red-600 mb-2">Session Not Available</h2>
          <p className="text-gray-600">{error}</p>
          <button
            onClick={() => router.push('/')}
            className="mt-4 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700"
          >
            Go to Dashboard
          </button>
        </div>
      </div>
    );
  }

  if (!session) return null;

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-6xl mx-auto px-4">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-6">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold mb-2">Interactive Analysis Session</h1>
              <div className="text-sm text-gray-600 space-y-1">
                <p>Session ID: <code className="bg-gray-100 px-1 rounded">{session.session_id}</code></p>
                <p>Started: {format(new Date(session.started_at), 'PPp')}</p>
                <p>Status: <span className={`font-medium ${
                  session.status === 'active' ? 'text-green-600' : 'text-gray-600'
                }`}>{session.status}</span></p>
                {session.expires_at && (
                  <p>Expires: {format(new Date(session.expires_at), 'PPp')}</p>
                )}
              </div>
            </div>
            
            <div className="flex gap-2">
              <button
                onClick={copyShareLink}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 flex items-center gap-2"
              >
                {copySuccess ? '✓ Copied!' : '📋 Copy Link'}
              </button>
              <button
                onClick={() => setShowExportModal(true)}
                className="px-4 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300"
              >
                Export
              </button>
              {session.is_owner && session.status === 'active' && (
                <button
                  onClick={continueSession}
                  className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700"
                >
                  Continue Session
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Statistics */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <div className="bg-white p-4 rounded-lg shadow">
            <div className="text-2xl font-bold">{session.statistics.total_interactions}</div>
            <div className="text-sm text-gray-600">Total Interactions</div>
          </div>
          <div className="bg-white p-4 rounded-lg shadow">
            <div className="text-2xl font-bold">{session.statistics.investigations}</div>
            <div className="text-sm text-gray-600">Investigations</div>
          </div>
          <div className="bg-white p-4 rounded-lg shadow">
            <div className="text-2xl font-bold">{session.statistics.false_positive_checks}</div>
            <div className="text-sm text-gray-600">FP Checks</div>
          </div>
          <div className="bg-white p-4 rounded-lg shadow">
            <div className="text-2xl font-bold">{session.statistics.remediations}</div>
            <div className="text-sm text-gray-600">Remediations</div>
          </div>
          <div className="bg-white p-4 rounded-lg shadow">
            <div className="text-2xl font-bold">{session.total_credits_used}</div>
            <div className="text-sm text-gray-600">Credits Used</div>
          </div>
        </div>

        {/* Findings Context */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4">Findings Context</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <h3 className="font-medium text-gray-700 mb-2">Total Findings</h3>
              <div className="text-2xl font-bold">{session.findings_context.total}</div>
            </div>
            
            <div>
              <h3 className="font-medium text-gray-700 mb-2">By Severity</h3>
              <div className="space-y-1">
                {Object.entries(session.findings_context.by_severity).map(([severity, count]) => (
                  <div key={severity} className="flex justify-between">
                    <span className={`font-medium ${getSeverityColor(severity)}`}>
                      {severity}
                    </span>
                    <span>{count}</span>
                  </div>
                ))}
              </div>
            </div>
            
            <div>
              <h3 className="font-medium text-gray-700 mb-2">By Phase</h3>
              <div className="space-y-1 text-sm">
                {Object.entries(session.findings_context.by_phase).map(([phase, count]) => (
                  <div key={phase} className="flex justify-between">
                    <span className="text-gray-600">{phase}</span>
                    <span>{count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          
          {session.findings_context.files.length > 0 && (
            <div className="mt-4">
              <h3 className="font-medium text-gray-700 mb-2">Files Analyzed</h3>
              <div className="flex flex-wrap gap-2">
                {session.findings_context.files.slice(0, 10).map((file, i) => (
                  <code key={i} className="text-xs bg-gray-100 px-2 py-1 rounded">
                    {file}
                  </code>
                ))}
                {session.findings_context.files.length > 10 && (
                  <span className="text-xs text-gray-500">
                    +{session.findings_context.files.length - 10} more
                  </span>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Conversation History */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-lg font-semibold mb-4">Conversation History</h2>
          
          <div className="space-y-4">
            {session.conversation_history.length === 0 ? (
              <p className="text-gray-500 text-center py-8">
                No interactions yet
              </p>
            ) : (
              session.conversation_history.map((entry, i) => (
                <div key={i} className="border-l-4 border-blue-500 pl-4 py-2">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xl">{getInteractionIcon(entry.type)}</span>
                      <span className="font-medium capitalize">
                        {entry.type.replace(/_/g, ' ')}
                      </span>
                    </div>
                    <div className="text-sm text-gray-500">
                      {format(new Date(entry.timestamp), 'PPp')} • {entry.credits_used} credits
                    </div>
                  </div>
                  
                  {/* Render response based on type */}
                  {entry.response && (
                    <div className="mt-2 bg-gray-50 p-3 rounded">
                      {entry.type === 'investigation' && (
                        <>
                          <div className="grid grid-cols-3 gap-2 text-sm mb-2">
                            <div>
                              <span className="text-gray-600">Threat:</span>{' '}
                              <span className={`font-medium ${
                                entry.response.is_real_threat ? 'text-red-600' : 'text-green-600'
                              }`}>
                                {entry.response.is_real_threat ? 'Real' : 'False Positive'}
                              </span>
                            </div>
                            <div>
                              <span className="text-gray-600">Confidence:</span>{' '}
                              <span className="font-medium">{entry.response.confidence}%</span>
                            </div>
                            <div>
                              <span className="text-gray-600">Priority:</span>{' '}
                              <span className="font-medium">{entry.response.priority}</span>
                            </div>
                          </div>
                          {entry.response.analysis && (
                            <p className="text-sm text-gray-700">{entry.response.analysis}</p>
                          )}
                        </>
                      )}
                      
                      {entry.type === 'false_positive_analysis' && (
                        <>
                          <div className="flex items-center gap-4 text-sm mb-2">
                            <span className={`font-medium ${
                              entry.response.is_false_positive ? 'text-green-600' : 'text-red-600'
                            }`}>
                              {entry.response.is_false_positive ? '✅ False Positive' : '⚠️ Real Issue'}
                            </span>
                            <span>Confidence: {entry.response.confidence}%</span>
                          </div>
                          {entry.response.explanation && (
                            <p className="text-sm text-gray-700">{entry.response.explanation}</p>
                          )}
                        </>
                      )}
                      
                      {entry.type === 'remediation' && (
                        <>
                          <div className="text-sm mb-2">
                            <span className="text-gray-600">Language:</span>{' '}
                            <span className="font-medium">{entry.response.language}</span>
                          </div>
                          {entry.response.code && (
                            <pre className="bg-gray-900 text-gray-100 p-2 rounded text-xs overflow-x-auto">
                              <code>{entry.response.code}</code>
                            </pre>
                          )}
                        </>
                      )}
                      
                      {entry.type === 'chat' && entry.response.message && (
                        <p className="text-sm text-gray-700">{entry.response.message}</p>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Export Modal */}
        {showExportModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white p-6 rounded-lg shadow-xl">
              <h3 className="text-lg font-semibold mb-4">Export Session</h3>
              <div className="space-y-3">
                <button
                  onClick={() => exportSession('markdown')}
                  className="w-full px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded text-left"
                >
                  📝 Markdown Report
                </button>
                <button
                  onClick={() => exportSession('json')}
                  className="w-full px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded text-left"
                >
                  📄 JSON Data
                </button>
              </div>
              <button
                onClick={() => setShowExportModal(false)}
                className="mt-4 px-4 py-2 bg-gray-500 text-white rounded hover:bg-gray-600 w-full"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}