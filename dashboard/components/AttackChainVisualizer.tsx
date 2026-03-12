import React, { useState, useEffect } from 'react';
import { Finding } from '@/lib/types';

interface AttackStep {
  stage: string;
  description: string;
  code_location?: string;
  technique: string;
  mitre_att_ck?: string;
  risk_level: string;
  mitigation?: string;
}

interface AttackChain {
  finding_id: string;
  vulnerability_type: string;
  entry_points: string[];
  attack_steps: AttackStep[];
  total_risk_score: number;
  blast_radius: {
    files_affected: number;
    systems_affected: number;
    data_categories: number;
    maximum_impact: string;
  };
  affected_systems: string[];
  data_at_risk: string[];
  mitigation_points: Array<{ stage: string; mitigation: string }>;
  kill_chain_disruption: Record<string, string>;
  visualization_data: {
    nodes: Array<{
      id: string;
      label: string;
      description?: string;
      risk?: string;
      mitre?: string;
      type: string;
    }>;
    edges: Array<{
      source: string;
      target: string;
      label: string;
    }>;
    layout: string;
  };
}

interface AttackChainVisualizerProps {
  finding: Finding;
  scanId: string;
  onClose?: () => void;
}

export default function AttackChainVisualizer({ 
  finding, 
  scanId,
  onClose 
}: AttackChainVisualizerProps) {
  const [attackChain, setAttackChain] = useState<AttackChain | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedStep, setSelectedStep] = useState<AttackStep | null>(null);
  const [credits, setCredits] = useState<number>(0);

  // Fetch credit balance
  useEffect(() => {
    fetch('/api/v1/interactive/credits')
      .then(res => res.json())
      .then(data => setCredits(data.balance))
      .catch(err => console.error('Failed to fetch credits:', err));
  }, []);

  const traceAttackChain = async () => {
    if (credits < 8) {
      setError('Insufficient credits. Need 8 credits for attack chain analysis.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/v1/interactive/attack-chain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding,
          scan_id: scanId
        })
      });

      if (!response.ok) {
        throw new Error(`Failed to trace attack chain: ${response.statusText}`);
      }

      const data = await response.json();
      setAttackChain(data.attack_chain);
      setCredits(data.credits_remaining);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to trace attack chain');
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level.toUpperCase()) {
      case 'CRITICAL': return 'text-red-600 bg-red-50';
      case 'HIGH': return 'text-orange-600 bg-orange-50';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-50';
      case 'LOW': return 'text-green-600 bg-green-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getStageIcon = (stage: string) => {
    const icons: Record<string, string> = {
      entry_point: '🚪',
      initial_access: '🔓',
      execution: '⚙️',
      persistence: '🔄',
      privilege_escalation: '⬆️',
      defense_evasion: '🛡️',
      credential_access: '🔑',
      discovery: '🔍',
      lateral_movement: '↔️',
      collection: '📦',
      exfiltration: '📤',
      impact: '💥'
    };
    return icons[stage] || '📍';
  };

  if (!attackChain && !loading) {
    return (
      <div className="bg-white rounded-lg shadow-md p-6">
        <h3 className="text-lg font-semibold mb-4">Attack Chain Analysis</h3>
        
        <div className="text-center py-8">
          <div className="mb-4">
            <span className="text-4xl">🔗</span>
          </div>
          <p className="text-gray-600 mb-4">
            Trace how this vulnerability could be exploited end-to-end
          </p>
          <p className="text-sm text-gray-500 mb-4">
            Cost: <span className="font-semibold">8 credits</span> | 
            Your balance: <span className="font-semibold">{credits} credits</span>
          </p>
          
          <button
            onClick={traceAttackChain}
            disabled={loading || credits < 8}
            className="px-6 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
          >
            {loading ? 'Tracing...' : 'Trace Attack Chain'}
          </button>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-lg">
            {error}
          </div>
        )}
      </div>
    );
  }

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-green-600"></div>
        </div>
        <p className="text-center text-gray-600">Analyzing attack chain...</p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-md">
      {/* Header */}
      <div className="border-b px-6 py-4">
        <div className="flex justify-between items-start">
          <div>
            <h3 className="text-xl font-semibold">Attack Chain Analysis</h3>
            <p className="text-gray-600 mt-1">{attackChain?.vulnerability_type}</p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-700"
          >
            ✕
          </button>
        </div>
      </div>

      {/* Risk Score */}
      <div className="px-6 py-4 bg-red-50 border-b">
        <div className="flex items-center justify-between">
          <div>
            <span className="text-sm text-gray-600">Total Risk Score</span>
            <p className="text-2xl font-bold text-red-600">
              {attackChain?.total_risk_score.toFixed(1)}/10
            </p>
          </div>
          <div className="text-right">
            <span className="text-sm text-gray-600">Maximum Impact</span>
            <p className="text-lg font-semibold text-red-600">
              {attackChain?.blast_radius.maximum_impact}
            </p>
          </div>
        </div>
      </div>

      {/* Attack Chain Steps */}
      <div className="px-6 py-4">
        <h4 className="font-semibold mb-4">Attack Progression</h4>
        
        <div className="space-y-3">
          {/* Entry Points */}
          <div className="border-l-4 border-blue-500 pl-4">
            <div className="font-medium text-blue-600">Entry Points</div>
            <ul className="mt-1 space-y-1">
              {attackChain?.entry_points.map((entry, i) => (
                <li key={i} className="text-sm text-gray-600">
                  🚪 {entry}
                </li>
              ))}
            </ul>
          </div>

          {/* Attack Steps */}
          {attackChain?.attack_steps.map((step, index) => (
            <div 
              key={index}
              className={`border-l-4 pl-4 cursor-pointer hover:bg-gray-50 py-2 -my-2 rounded ${
                selectedStep === step ? 'bg-blue-50 border-blue-600' : 'border-gray-300'
              }`}
              onClick={() => setSelectedStep(step === selectedStep ? null : step)}
            >
              <div className="flex items-start gap-3">
                <span className="text-2xl">{getStageIcon(step.stage)}</span>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">
                      Step {index + 1}: {step.stage.replace(/_/g, ' ').toUpperCase()}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${getRiskColor(step.risk_level)}`}>
                      {step.risk_level}
                    </span>
                    {step.mitre_att_ck && (
                      <span className="text-xs text-gray-500">
                        MITRE: {step.mitre_att_ck}
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-gray-600 mt-1">{step.description}</p>
                  {step.code_location && (
                    <p className="text-xs text-gray-500 mt-1">📍 {step.code_location}</p>
                  )}
                  
                  {selectedStep === step && step.mitigation && (
                    <div className="mt-3 p-3 bg-green-50 rounded">
                      <div className="text-sm font-medium text-green-800 mb-1">Mitigation:</div>
                      <p className="text-sm text-green-700">{step.mitigation}</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Blast Radius */}
      <div className="px-6 py-4 bg-gray-50 border-t">
        <h4 className="font-semibold mb-3">Blast Radius</h4>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-red-600">
              {attackChain?.blast_radius.files_affected}
            </div>
            <div className="text-sm text-gray-600">Files Affected</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-orange-600">
              {attackChain?.blast_radius.systems_affected}
            </div>
            <div className="text-sm text-gray-600">Systems Affected</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-600">
              {attackChain?.blast_radius.data_categories}
            </div>
            <div className="text-sm text-gray-600">Data Categories</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-purple-600">
              {attackChain?.affected_systems.length}
            </div>
            <div className="text-sm text-gray-600">Components</div>
          </div>
        </div>

        {/* Affected Systems */}
        <div className="mt-4">
          <div className="text-sm font-medium text-gray-700 mb-2">Affected Systems:</div>
          <div className="flex flex-wrap gap-2">
            {attackChain?.affected_systems.map((system, i) => (
              <span key={i} className="px-2 py-1 bg-white rounded border text-sm">
                {system}
              </span>
            ))}
          </div>
        </div>

        {/* Data at Risk */}
        <div className="mt-4">
          <div className="text-sm font-medium text-gray-700 mb-2">Data at Risk:</div>
          <div className="flex flex-wrap gap-2">
            {attackChain?.data_at_risk.map((data, i) => (
              <span key={i} className="px-2 py-1 bg-yellow-100 rounded text-sm text-yellow-800">
                {data}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Kill Chain Disruption */}
      <div className="px-6 py-4 border-t">
        <h4 className="font-semibold mb-3">🛡️ Kill Chain Disruption Points</h4>
        {Object.entries(attackChain?.kill_chain_disruption || {}).length > 0 ? (
          <div className="space-y-2">
            {Object.entries(attackChain?.kill_chain_disruption || {}).map(([step, mitigation]) => (
              <div key={step} className="flex items-start gap-2">
                <span className="text-green-600">✓</span>
                <div>
                  <span className="font-medium text-sm">{step}:</span>
                  <span className="text-sm text-gray-600 ml-2">{mitigation}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-gray-600">No automated disruption points identified</p>
        )}
      </div>

      {/* Actions */}
      <div className="px-6 py-4 border-t bg-gray-50">
        <div className="flex gap-3">
          <button className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700">
            Export Report
          </button>
          <button className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
            Get Mitigations
          </button>
          <button className="px-4 py-2 border border-gray-300 rounded hover:bg-white">
            Share Analysis
          </button>
        </div>
      </div>
    </div>
  );
}