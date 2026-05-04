"use client";

import { useState } from "react";

interface Rule {
  id: string;
  pattern: string;
  description: string;
}

interface ScanPhaseCardProps {
  phase: number;
  name: string;
  weight: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  rules: Rule[];
}

// Brand v1.0 — 5-tier verdict family per directive 2026-05-04 §3.
// (CLEAN belongs on SealVerdict, not on per-phase badges.)
const severityStyles = {
  critical: {
    badge: "bg-[#DC2626]/10 text-[#DC2626] border-[#DC2626]/20",
    border: "border-[#DC2626]/20",
    glow: "hover:shadow-[0_0_15px_rgba(220,38,38,0.1)]",
  },
  high: {
    badge: "bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/20",
    border: "border-[#EF4444]/20",
    glow: "hover:shadow-[0_0_15px_rgba(239,68,68,0.1)]",
  },
  medium: {
    badge: "bg-[#F97316]/10 text-[#F97316] border-[#F97316]/20",
    border: "border-[#F97316]/20",
    glow: "hover:shadow-[0_0_15px_rgba(249,115,22,0.1)]",
  },
  low: {
    badge: "bg-[#EAB308]/10 text-[#EAB308] border-[#EAB308]/20",
    border: "border-[#EAB308]/20",
    glow: "hover:shadow-[0_0_15px_rgba(234,179,8,0.1)]",
  },
};

export default function ScanPhaseCard({
  phase,
  name,
  weight,
  severity,
  description,
  rules,
}: ScanPhaseCardProps) {
  const [expanded, setExpanded] = useState(false);
  const styles = severityStyles[severity];

  return (
    <div
      className={`rounded-lg border bg-gray-900 transition-shadow ${styles.border} ${styles.glow}`}
    >
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-4 px-5 py-4 text-left"
      >
        <span className="flex items-center justify-center w-8 h-8 rounded-lg bg-gray-800 text-gray-400 text-sm font-bold">
          {phase}
        </span>
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-semibold text-gray-100">{name}</h3>
          <p className="text-xs text-gray-500 mt-0.5 truncate">{description}</p>
        </div>
        <span
          className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold border ${styles.badge}`}
        >
          {weight}
        </span>
        <svg
          className={`w-4 h-4 text-gray-500 transition-transform ${
            expanded ? "rotate-180" : ""
          }`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Rules list */}
      {expanded && (
        <div className="border-t border-gray-800 px-5 py-4">
          <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-3">
            Detection Rules ({rules.length})
          </h4>
          <div className="space-y-2">
            {rules.map((rule) => (
              <div
                key={rule.id}
                className="flex items-start gap-3 p-3 rounded-lg bg-gray-800/50"
              >
                <code className="text-xs text-brand-400 font-mono bg-brand-500/10 px-1.5 py-0.5 rounded flex-shrink-0">
                  {rule.pattern}
                </code>
                <span className="text-xs text-gray-400">{rule.description}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
