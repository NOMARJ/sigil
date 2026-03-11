"use client";

import { useState, useEffect, useCallback } from "react";
import ScanTable from "@/components/ScanTable";
import * as api from "@/lib/api";
import type { Scan, Verdict, PaginatedResponse } from "@/lib/types";

const verdictOptions: (Verdict | "ALL")[] = [
  "ALL",
  "LOW_RISK",
  "MEDIUM_RISK",
  "HIGH_RISK",
  "CRITICAL_RISK",
];

type Scope = "all" | "own" | "public" | "community";
const scopeOptions: { value: Scope; label: string }[] = [
  { value: "all", label: "All" },
  { value: "own", label: "My Scans" },
  { value: "public", label: "Public" },
  { value: "community", label: "Community" },
];

const sourceOptions = [
  { value: "", label: "All Sources" },
  { value: "pip", label: "PyPI" },
  { value: "npm", label: "npm" },
  { value: "skills", label: "Skills" },
  { value: "git", label: "Git" },
  { value: "directory", label: "Local" },
];

const PER_PAGE = 20;

export default function ScansPage() {
  const [verdictFilter, setVerdictFilter] = useState<Verdict | "ALL">("ALL");
  const [scope, setScope] = useState<Scope>("all");
  const [source, setSource] = useState("");
  const [page, setPage] = useState(1);
  const [scans, setScans] = useState<Scan[]>([]);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Parameters<typeof api.listScans>[0] = {
        page,
        per_page: PER_PAGE,
        scope,
      };
      if (verdictFilter !== "ALL") params.verdict = verdictFilter;
      if (source) params.source = source;

      const data: PaginatedResponse<Scan> = await api.listScans(params);
      setScans(data.items);
      setTotal(data.total);
      setHasMore(data.total > page * PER_PAGE);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scans.");
    } finally {
      setLoading(false);
    }
  }, [page, verdictFilter, scope, source]);

  useEffect(() => { fetchScans(); }, [fetchScans]);

  const resetPage = () => setPage(1);

  const startIndex = (page - 1) * PER_PAGE + 1;
  const endIndex = Math.min(page * PER_PAGE, total);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100 tracking-tight">Scan History</h1>
        <p className="text-sm text-gray-500 mt-1">
          Browse public, community, and your own package scans.
        </p>
      </div>

      {/* Notice */}
      <div className="p-3 rounded-lg bg-gray-900/50 border border-gray-800 text-xs text-gray-500 leading-relaxed">
        Sigil scans packages across ClawHub, PyPI, npm, and GitHub using automated static analysis.
        Results indicate detected patterns, not certified safety status. See our{" "}
        <a href="/terms" className="text-brand-400 hover:text-brand-300 underline">Terms of Service</a>{" "}
        for full details.
      </div>

      {/* Error */}
      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={fetchScans} className="text-red-400 hover:text-red-300 text-xs font-medium underline">
            Retry
          </button>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Scope */}
        <div className="flex items-center gap-1 bg-gray-900 border border-gray-800 rounded-lg p-1">
          {scopeOptions.map((s) => (
            <button
              key={s.value}
              onClick={() => { setScope(s.value); resetPage(); }}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                scope === s.value
                  ? "bg-brand-600/20 text-brand-400"
                  : "text-gray-500 hover:text-gray-300"
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>

        {/* Source */}
        <select
          value={source}
          onChange={(e) => { setSource(e.target.value); resetPage(); }}
          className="bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-brand-500"
        >
          {sourceOptions.map((s) => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>

        {/* Verdict */}
        <div className="flex items-center gap-1">
          {verdictOptions.map((v) => (
            <button
              key={v}
              onClick={() => { setVerdictFilter(v); resetPage(); }}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors border ${
                verdictFilter === v
                  ? "bg-brand-600/20 text-brand-400 border-brand-500/30"
                  : "bg-gray-800/50 text-gray-500 border-gray-800 hover:border-gray-700 hover:text-gray-300"
              }`}
            >
              {v === "ALL" ? "All Verdicts" : v.replace("_RISK", "")}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="card">
        <div className="card-body">
          {loading ? (
            <div className="space-y-3">
              {[1,2,3,4,5,6,7,8].map((i) => (
                <div key={i} className="flex items-center gap-4 animate-pulse py-2">
                  <div className="h-4 w-36 bg-gray-800 rounded" />
                  <div className="h-4 w-12 bg-gray-800 rounded" />
                  <div className="h-4 w-16 bg-gray-800 rounded" />
                  <div className="h-4 w-10 bg-gray-800 rounded" />
                  <div className="flex-1" />
                  <div className="h-4 w-28 bg-gray-800 rounded" />
                </div>
              ))}
            </div>
          ) : (
            <ScanTable scans={scans} />
          )}
        </div>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm text-gray-500">
        <p>
          {total > 0
            ? `Showing ${startIndex}–${endIndex} of ${total.toLocaleString()} scans`
            : loading ? "Loading..." : "No scans found"}
        </p>
        <div className="flex gap-2">
          <button
            className="btn-secondary text-xs"
            disabled={page <= 1 || loading}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            Previous
          </button>
          <button
            className="btn-secondary text-xs"
            disabled={!hasMore || loading}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
