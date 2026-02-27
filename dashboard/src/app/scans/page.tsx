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

const PER_PAGE = 10;

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ScansPage() {
  const [verdictFilter, setVerdictFilter] = useState<Verdict | "ALL">("ALL");
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
      };

      if (verdictFilter !== "ALL") {
        params.verdict = verdictFilter;
      }

      const data: PaginatedResponse<Scan> = await api.listScans(params);
      setScans(data.items);
      setTotal(data.total);
      setHasMore(data.total > page * PER_PAGE);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to load scans.";
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [page, verdictFilter]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  // Reset to page 1 when filter changes
  const handleFilterChange = (v: Verdict | "ALL") => {
    setVerdictFilter(v);
    setPage(1);
  };

  const startIndex = (page - 1) * PER_PAGE + 1;
  const endIndex = Math.min(page * PER_PAGE, total);

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

      {/* Error banner */}
      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400 flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={fetchScans}
            className="text-red-400 hover:text-red-300 text-xs font-medium underline"
          >
            Retry
          </button>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-gray-500 uppercase tracking-wider mr-2">
          Filter by verdict:
        </span>
        {verdictOptions.map((v) => (
          <button
            key={v}
            onClick={() => handleFilterChange(v)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              verdictFilter === v
                ? "bg-brand-600/20 text-brand-400 border border-brand-500/30"
                : "bg-gray-800/50 text-gray-400 border border-gray-800 hover:border-gray-700 hover:text-gray-300"
            }`}
          >
            {v}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="card">
        <div className="card-body">
          {loading ? (
            <div className="space-y-3">
              {[1, 2, 3, 4, 5, 6, 7, 8].map((i) => (
                <div key={i} className="flex items-center gap-4 animate-pulse py-2">
                  <div className="h-4 w-36 bg-gray-800 rounded" />
                  <div className="h-4 w-12 bg-gray-800 rounded" />
                  <div className="h-4 w-16 bg-gray-800 rounded" />
                  <div className="h-4 w-10 bg-gray-800 rounded" />
                  <div className="h-4 w-8 bg-gray-800 rounded" />
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
            ? `Showing ${startIndex}--${endIndex} of ${total} scans`
            : loading
              ? "Loading..."
              : "No scans found"}
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
