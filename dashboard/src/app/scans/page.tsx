"use client";

import { useState } from "react";
import ScanTable from "@/components/ScanTable";
import type { Scan, Verdict } from "@/lib/types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const allScans: Scan[] = [
  {
    id: "scan-001",
    package_name: "langchain-agent",
    package_version: "0.4.2",
    source: "pip",
    verdict: "CLEAN",
    score: 0,
    findings_count: 0,
    findings: [],
    quarantine_path: null,
    status: "completed",
    created_at: "2026-02-15T10:23:00Z",
    completed_at: "2026-02-15T10:23:45Z",
    approved_by: null,
    approved_at: null,
  },
  {
    id: "scan-002",
    package_name: "openai-tools",
    package_version: "1.2.0",
    source: "npm",
    verdict: "HIGH",
    score: 78,
    findings_count: 5,
    findings: [],
    quarantine_path: "/tmp/sigil/quarantine/scan-002",
    status: "completed",
    created_at: "2026-02-15T09:15:00Z",
    completed_at: "2026-02-15T09:16:12Z",
    approved_by: null,
    approved_at: null,
  },
  {
    id: "scan-003",
    package_name: "agent-framework",
    package_version: "2.1.0",
    source: "pip",
    verdict: "CRITICAL",
    score: 145,
    findings_count: 12,
    findings: [],
    quarantine_path: "/tmp/sigil/quarantine/scan-003",
    status: "completed",
    created_at: "2026-02-14T22:45:00Z",
    completed_at: "2026-02-14T22:47:30Z",
    approved_by: null,
    approved_at: null,
  },
  {
    id: "scan-004",
    package_name: "mcp-server-utils",
    package_version: "0.9.1",
    source: "npm",
    verdict: "LOW",
    score: 8,
    findings_count: 2,
    findings: [],
    quarantine_path: null,
    status: "completed",
    created_at: "2026-02-14T18:30:00Z",
    completed_at: "2026-02-14T18:30:22Z",
    approved_by: "user-001",
    approved_at: "2026-02-14T18:35:00Z",
  },
  {
    id: "scan-005",
    package_name: "llm-sandbox",
    package_version: "3.0.0-beta",
    source: "git",
    verdict: "MEDIUM",
    score: 34,
    findings_count: 4,
    findings: [],
    quarantine_path: "/tmp/sigil/quarantine/scan-005",
    status: "completed",
    created_at: "2026-02-14T15:12:00Z",
    completed_at: "2026-02-14T15:14:55Z",
    approved_by: null,
    approved_at: null,
  },
  {
    id: "scan-006",
    package_name: "autogen-core",
    package_version: "0.2.8",
    source: "pip",
    verdict: "CLEAN",
    score: 0,
    findings_count: 0,
    findings: [],
    quarantine_path: null,
    status: "completed",
    created_at: "2026-02-14T12:00:00Z",
    completed_at: "2026-02-14T12:00:38Z",
    approved_by: null,
    approved_at: null,
  },
  {
    id: "scan-007",
    package_name: "crewai-tools",
    package_version: "1.0.3",
    source: "pip",
    verdict: "LOW",
    score: 5,
    findings_count: 1,
    findings: [],
    quarantine_path: null,
    status: "completed",
    created_at: "2026-02-13T20:45:00Z",
    completed_at: "2026-02-13T20:45:28Z",
    approved_by: "user-002",
    approved_at: "2026-02-13T21:00:00Z",
  },
  {
    id: "scan-008",
    package_name: "suspicious-helper",
    package_version: "0.0.1",
    source: "npm",
    verdict: "CRITICAL",
    score: 220,
    findings_count: 18,
    findings: [],
    quarantine_path: "/tmp/sigil/quarantine/scan-008",
    status: "completed",
    created_at: "2026-02-13T16:30:00Z",
    completed_at: "2026-02-13T16:33:15Z",
    approved_by: null,
    approved_at: null,
  },
];

const verdictOptions: (Verdict | "ALL")[] = [
  "ALL",
  "CLEAN",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
];

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ScansPage() {
  const [verdictFilter, setVerdictFilter] = useState<Verdict | "ALL">("ALL");

  const filteredScans =
    verdictFilter === "ALL"
      ? allScans
      : allScans.filter((s) => s.verdict === verdictFilter);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
            Scan History
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Browse all package and repository scans.
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-gray-500 uppercase tracking-wider mr-2">
          Filter by verdict:
        </span>
        {verdictOptions.map((v) => (
          <button
            key={v}
            onClick={() => setVerdictFilter(v)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              verdictFilter === v
                ? "bg-brand-600/20 text-brand-400 border border-brand-500/30"
                : "bg-gray-800/50 text-gray-400 border border-gray-800 hover:border-gray-700 hover:text-gray-300"
            }`}
          >
            {v}
            {v !== "ALL" && (
              <span className="ml-1.5 text-gray-600">
                ({allScans.filter((s) => s.verdict === v).length})
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="card">
        <div className="card-body">
          <ScanTable scans={filteredScans} />
        </div>
      </div>

      {/* Pagination placeholder */}
      <div className="flex items-center justify-between text-sm text-gray-500">
        <p>
          Showing {filteredScans.length} of {allScans.length} scans
        </p>
        <div className="flex gap-2">
          <button className="btn-secondary text-xs" disabled>
            Previous
          </button>
          <button className="btn-secondary text-xs" disabled>
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
