"use client";

import { useState, useEffect, useCallback } from "react";
import VerdictBadge from "@/components/VerdictBadge";
import * as api from "@/lib/api";
import type { ThreatEntry, Verdict, ScanSource, ReportThreatRequest } from "@/lib/types";

const severityOptions: (Verdict | "ALL")[] = [
  "ALL",
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
];

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ThreatsPage() {
  const [severityFilter, setSeverityFilter] = useState<Verdict | "ALL">("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [threats, setThreats] = useState<ThreatEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Report threat modal state
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportForm, setReportForm] = useState<ReportThreatRequest>({
    package_name: "",
    source: "npm",
    threat_type: "Supply Chain Attack",
    description: "",
    severity: "HIGH",
    indicators: [],
    references: [],
  });
  const [reportIndicator, setReportIndicator] = useState("");
  const [reportReference, setReportReference] = useState("");
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportSuccess, setReportSuccess] = useState(false);

  const fetchThreats = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const params: Parameters<typeof api.searchThreats>[0] = {
        page,
        per_page: 20,
      };

      if (severityFilter !== "ALL") {
        params.severity = severityFilter;
      }
      if (searchQuery.trim()) {
        params.search = searchQuery.trim();
      }

      const data = await api.searchThreats(params);
      setThreats(data.items);
      setTotal(data.total);
      setHasMore(data.has_more);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to load threats.";
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [page, severityFilter, searchQuery]);

  useEffect(() => {
    const debounce = setTimeout(() => {
      fetchThreats();
    }, searchQuery ? 300 : 0);

    return () => clearTimeout(debounce);
  }, [fetchThreats, searchQuery]);

  const handleFilterChange = (v: Verdict | "ALL") => {
    setSeverityFilter(v);
    setPage(1);
  };

  const handleSearchChange = (value: string) => {
    setSearchQuery(value);
    setPage(1);
  };

  const addIndicator = () => {
    if (reportIndicator.trim()) {
      setReportForm((prev) => ({
        ...prev,
        indicators: [...prev.indicators, reportIndicator.trim()],
      }));
      setReportIndicator("");
    }
  };

  const removeIndicator = (index: number) => {
    setReportForm((prev) => ({
      ...prev,
      indicators: prev.indicators.filter((_, i) => i !== index),
    }));
  };

  const addReference = () => {
    if (reportReference.trim()) {
      setReportForm((prev) => ({
        ...prev,
        references: [...prev.references, reportReference.trim()],
      }));
      setReportReference("");
    }
  };

  const removeReference = (index: number) => {
    setReportForm((prev) => ({
      ...prev,
      references: prev.references.filter((_, i) => i !== index),
    }));
  };

  const handleReportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setReportLoading(true);
    setReportError(null);
    setReportSuccess(false);

    try {
      await api.submitReport(reportForm);
      setReportSuccess(true);
      setReportForm({
        package_name: "",
        source: "npm",
        threat_type: "Supply Chain Attack",
        description: "",
        severity: "HIGH",
        indicators: [],
        references: [],
      });
      // Refresh the list
      fetchThreats();
      // Auto-close after success
      setTimeout(() => {
        setShowReportModal(false);
        setReportSuccess(false);
      }, 2000);
    } catch (err) {
      setReportError(
        err instanceof Error ? err.message : "Failed to submit report.",
      );
    } finally {
      setReportLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
            Threat Intelligence
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Known malicious packages and community-reported threats.
          </p>
        </div>
        <button
          onClick={() => setShowReportModal(true)}
          className="btn-primary"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          Report Threat
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400 flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={fetchThreats}
            className="text-red-400 hover:text-red-300 text-xs font-medium underline"
          >
            Retry
          </button>
        </div>
      )}

      {/* Search + Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1">
          <input
            type="text"
            placeholder="Search threats by package name or description..."
            value={searchQuery}
            onChange={(e) => handleSearchChange(e.target.value)}
            className="input"
          />
        </div>
        <div className="flex items-center gap-2">
          {severityOptions.map((v) => (
            <button
              key={v}
              onClick={() => handleFilterChange(v)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                severityFilter === v
                  ? "bg-brand-600/20 text-brand-400 border border-brand-500/30"
                  : "bg-gray-800/50 text-gray-400 border border-gray-800 hover:border-gray-700 hover:text-gray-300"
              }`}
            >
              {v}
            </button>
          ))}
        </div>
      </div>

      {/* Threat cards */}
      <div className="space-y-4">
        {loading ? (
          <>
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="card animate-pulse">
                <div className="card-body">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="h-5 w-32 bg-gray-800 rounded" />
                    <div className="h-5 w-16 bg-gray-800 rounded-full" />
                    <div className="h-5 w-10 bg-gray-800 rounded" />
                  </div>
                  <div className="h-4 w-full bg-gray-800 rounded mb-2" />
                  <div className="h-4 w-3/4 bg-gray-800 rounded" />
                </div>
              </div>
            ))}
          </>
        ) : threats.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <p className="text-sm">No threats match your filters.</p>
          </div>
        ) : (
          threats.map((threat) => (
            <div
              key={threat.id}
              className="card hover:border-gray-700 transition-colors"
            >
              <div className="card-body">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="text-base font-semibold text-gray-100">
                        {threat.package_name}
                      </h3>
                      <VerdictBadge verdict={threat.severity} size="sm" />
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700">
                        {threat.source}
                      </span>
                    </div>

                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20 mb-2">
                      {threat.threat_type}
                    </span>

                    <p className="text-sm text-gray-400 mt-2">
                      {threat.description}
                    </p>

                    {/* Indicators */}
                    {threat.indicators.length > 0 && (
                      <div className="mt-3">
                        <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5">
                          Indicators
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {threat.indicators.map((indicator, i) => (
                            <span
                              key={i}
                              className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-gray-800/50 text-gray-400 border border-gray-700/50"
                            >
                              {indicator}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="text-right shrink-0 text-xs text-gray-500">
                    <p>Reported by {threat.reporter}</p>
                    <p className="mt-0.5">
                      {new Date(threat.reported_at).toLocaleDateString("en-US", {
                        month: "short",
                        day: "numeric",
                        year: "numeric",
                      })}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Pagination */}
      {!loading && total > 0 && (
        <div className="flex items-center justify-between text-sm text-gray-500">
          <p>Showing {threats.length} of {total} threats</p>
          <div className="flex gap-2">
            <button
              className="btn-secondary text-xs"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              Previous
            </button>
            <button
              className="btn-secondary text-xs"
              disabled={!hasMore}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </div>
      )}

      {/* Report Threat Modal */}
      {showReportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="card w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
            <div className="card-header flex items-center justify-between">
              <div>
                <h2 className="section-header">Report a Threat</h2>
                <p className="section-description">
                  Submit a threat report for a malicious package.
                </p>
              </div>
              <button
                onClick={() => { setShowReportModal(false); setReportError(null); setReportSuccess(false); }}
                className="text-gray-500 hover:text-gray-300 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="card-body">
              {reportSuccess && (
                <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20 text-sm text-green-400 mb-4">
                  Threat reported successfully.
                </div>
              )}
              {reportError && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400 mb-4">
                  {reportError}
                </div>
              )}
              <form onSubmit={handleReportSubmit} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="input-label">Package Name</label>
                    <input
                      type="text"
                      value={reportForm.package_name}
                      onChange={(e) => setReportForm((prev) => ({ ...prev, package_name: e.target.value }))}
                      className="input"
                      placeholder="package-name"
                      required
                    />
                  </div>
                  <div>
                    <label className="input-label">Source</label>
                    <select
                      value={reportForm.source}
                      onChange={(e) => setReportForm((prev) => ({ ...prev, source: e.target.value as ScanSource }))}
                      className="input"
                    >
                      <option value="npm">npm</option>
                      <option value="pip">PyPI</option>
                      <option value="git">Git</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="input-label">Threat Type</label>
                    <select
                      value={reportForm.threat_type}
                      onChange={(e) => setReportForm((prev) => ({ ...prev, threat_type: e.target.value }))}
                      className="input"
                    >
                      <option value="Supply Chain Attack">Supply Chain Attack</option>
                      <option value="Typosquatting">Typosquatting</option>
                      <option value="Account Takeover">Account Takeover</option>
                      <option value="Data Exfiltration">Data Exfiltration</option>
                      <option value="Maintainer Sabotage">Maintainer Sabotage</option>
                      <option value="Other">Other</option>
                    </select>
                  </div>
                  <div>
                    <label className="input-label">Severity</label>
                    <select
                      value={reportForm.severity}
                      onChange={(e) => setReportForm((prev) => ({ ...prev, severity: e.target.value as Verdict }))}
                      className="input"
                    >
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH">High</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="LOW">Low</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="input-label">Description</label>
                  <textarea
                    value={reportForm.description}
                    onChange={(e) => setReportForm((prev) => ({ ...prev, description: e.target.value }))}
                    className="input"
                    rows={3}
                    placeholder="Describe the threat, how it was discovered, and its impact..."
                    required
                  />
                </div>

                {/* Indicators */}
                <div>
                  <label className="input-label">Indicators</label>
                  <div className="flex gap-2 mb-2">
                    <input
                      type="text"
                      value={reportIndicator}
                      onChange={(e) => setReportIndicator(e.target.value)}
                      className="input flex-1"
                      placeholder="e.g., eval() with network fetch"
                      onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addIndicator(); } }}
                    />
                    <button type="button" onClick={addIndicator} className="btn-secondary text-xs">
                      Add
                    </button>
                  </div>
                  {reportForm.indicators.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {reportForm.indicators.map((ind, i) => (
                        <span
                          key={i}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono bg-gray-800/50 text-gray-400 border border-gray-700/50"
                        >
                          {ind}
                          <button
                            type="button"
                            onClick={() => removeIndicator(i)}
                            className="text-gray-600 hover:text-red-400"
                          >
                            x
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* References */}
                <div>
                  <label className="input-label">References</label>
                  <div className="flex gap-2 mb-2">
                    <input
                      type="url"
                      value={reportReference}
                      onChange={(e) => setReportReference(e.target.value)}
                      className="input flex-1"
                      placeholder="https://..."
                      onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addReference(); } }}
                    />
                    <button type="button" onClick={addReference} className="btn-secondary text-xs">
                      Add
                    </button>
                  </div>
                  {reportForm.references.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {reportForm.references.map((ref, i) => (
                        <span
                          key={i}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-gray-800/50 text-gray-400 border border-gray-700/50 truncate max-w-full"
                        >
                          {ref}
                          <button
                            type="button"
                            onClick={() => removeReference(i)}
                            className="text-gray-600 hover:text-red-400 shrink-0"
                          >
                            x
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => { setShowReportModal(false); setReportError(null); setReportSuccess(false); }}
                    className="btn-secondary"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={reportLoading}
                    className="btn-primary"
                  >
                    {reportLoading ? (
                      <span className="flex items-center gap-2">
                        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                        Submitting...
                      </span>
                    ) : (
                      "Submit Report"
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
