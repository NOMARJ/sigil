"use client";

import type { ForgeTool } from "@/lib/types";

interface ToolTrackingCardProps {
  tool: ForgeTool;
  onTrack?: (tool: ForgeTool) => void;
  onUntrack?: (toolId: string) => void;
  tracked?: boolean;
  compact?: boolean;
}

export default function ToolTrackingCard({ 
  tool, 
  onTrack, 
  onUntrack, 
  tracked = true,
  compact = false 
}: ToolTrackingCardProps) {
  const getRiskColor = (score?: number) => {
    if (!score) return "text-gray-500";
    if (score < 2) return "text-green-400";
    if (score < 4) return "text-yellow-400";
    return "text-red-400";
  };

  const getRiskLabel = (score?: number) => {
    if (!score) return "Unknown";
    if (score < 2) return "Low Risk";
    if (score < 4) return "Medium Risk";
    return "High Risk";
  };

  const handleAction = () => {
    if (tracked && onUntrack) {
      onUntrack(tool.id);
    } else if (!tracked && onTrack) {
      onTrack(tool);
    }
  };

  if (compact) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 hover:border-gray-700 transition-colors">
        <div className="flex items-center justify-between">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3">
              <h4 className="font-medium text-white truncate">{tool.name}</h4>
              <span className="text-sm text-gray-500">v{tool.version}</span>
              <span className={`text-sm font-medium ${getRiskColor(tool.risk_score)}`}>
                {getRiskLabel(tool.risk_score)}
              </span>
            </div>
            <p className="text-sm text-gray-400 mt-1 truncate">{tool.description}</p>
          </div>
          <button
            onClick={handleAction}
            className={`ml-4 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
              tracked 
                ? "text-gray-400 hover:text-red-400" 
                : "bg-brand-600 hover:bg-brand-700 text-white"
            }`}
          >
            {tracked ? "Untrack" : "Track"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 hover:border-gray-700 transition-colors">
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <h3 className="text-lg font-semibold text-white mb-2">{tool.name}</h3>
          <p className="text-gray-400 text-sm mb-3">{tool.description}</p>
          <div className="flex items-center gap-4 text-sm">
            <span className="bg-gray-800 text-gray-300 px-2 py-1 rounded">
              {tool.category}
            </span>
            <span className="text-gray-500">v{tool.version}</span>
            <span className={`font-medium ${getRiskColor(tool.risk_score)}`}>
              {getRiskLabel(tool.risk_score)}
            </span>
          </div>
        </div>
        <button
          onClick={handleAction}
          className={`text-sm font-medium px-3 py-1.5 rounded-md transition-colors ${
            tracked
              ? "text-gray-500 hover:text-red-400"
              : "bg-brand-600 hover:bg-brand-700 text-white"
          }`}
          title={tracked ? "Untrack tool" : "Track tool"}
        >
          {tracked ? (
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1-1H9a1 1 0 00-1 1v3M4 7h16" />
            </svg>
          ) : (
            "Track"
          )}
        </button>
      </div>

      <div className="flex items-center justify-between pt-4 border-t border-gray-800">
        <div className="flex items-center gap-4">
          <a 
            href={tool.repository_url}
            target="_blank" 
            rel="noopener noreferrer"
            className="text-brand-400 hover:text-brand-300 text-sm font-medium transition-colors"
          >
            Repository →
          </a>
          {tool.documentation_url && (
            <a 
              href={tool.documentation_url}
              target="_blank" 
              rel="noopener noreferrer"
              className="text-gray-400 hover:text-gray-300 text-sm transition-colors"
            >
              Docs →
            </a>
          )}
        </div>
        
        {tool.last_scan_id && (
          <button className="text-gray-400 hover:text-white text-sm font-medium transition-colors">
            View Scan →
          </button>
        )}
      </div>
    </div>
  );
}