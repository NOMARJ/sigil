"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import VerdictBadge from "@/components/VerdictBadge";
import FindingsList from "@/components/FindingsList";
import * as api from "@/lib/api";
import type { Scan, Finding, Verdict, ScanPhase } from "@/lib/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

const severityOrder: Record<string, number> = {
  CRITICAL_RISK: 4,
  CRITICAL: 4,
  HIGH_RISK: 3,
  HIGH: 3,
  MEDIUM_RISK: 2,
  MEDIUM: 2,
  LOW_RISK: 1,
  LOW: 1,
};

function riskBreakdown(findings: Finding[]): { phase: ScanPhase; count: number; maxSeverity: Verdict; totalWeight: number }[] {
  const map = new Map<
    ScanPhase,
    { count: number; maxSeverity: Verdict; totalWeight: number }
  >();

  for (const f of findings) {
    const entry = map.get(f.phase) ?? {
      count: 0,
      maxSeverity: "LOW_RISK" as Verdict,
      totalWeight: 0,
    };
    entry.count += 1;
    entry.totalWeight += f.weight;
    if (severityOrder[f.severity] > severityOrder[entry.maxSeverity]) {
      entry.maxSeverity = f.severity;
    }
    map.set(f.phase, entry);
  }

  return Array.from(map.entries())
    .map(([phase, data]) => ({ phase, ...data }))
    .sort((a, b) => b.totalWeight - a.totalWeight);
}

const phaseLabels: Record<ScanPhase, string> = {
  install_hooks: "Install Hooks",
  code_patterns: "Code Patterns",
  network_exfil: "Network / Exfil",
  credentials: "Credentials",
  obfuscation: "Obfuscation",
  provenance: "Provenance",
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<"approve" | "reject" | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const fetchScanData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const [scanData, findingsData] = await Promise.all([
        api.getScan(scanId),
        api.getScanFindings(scanId),
      ]);
      setScan(scanData);
      setFindings(findingsData);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to load scan details.";
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    fetchScanData();
  }, [fetchScanData]);

  const handleApprove = async () => {
    setActionLoading("approve");
    setActionError(null);
    try {
      const updated = await api.approveScan(scanId);
      setScan(updated);
    } catch (err) {
      setActionError(
        err instanceof Error ? err.message : "Failed to approve scan.",
      );
    } finally {
      setActionLoading(null);
    }
  };

  const handleReject = async () => {
    setActionLoading("reject");
    setActionError(null);
    try {
      const updated = await api.rejectScan(scanId);
      setScan(updated);
    } catch (err) {
      setActionError(
        err instanceof Error ? err.message : "Failed to reject scan.",
      );
    } finally {
      setActionLoading(null);
    }
  };

  // Loading state
  if (loading) {
    return (
      <div className="space-y-8">
        <Link
          href="/scans"
          className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Back to Scans
        </Link>
        <div className="animate-pulse space-y-6">
          <div className="flex items-center gap-3">
            <div className="h-8 w-48 bg-gray-800 rounded" />
            <div className="h-6 w-20 bg-gray-800 rounded-full" />
          </div>
          <div className="h-4 w-64 bg-gray-800 rounded" />
          <div className="grid grid-cols-3 gap-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-24 bg-gray-800/30 rounded-lg border border-gray-800" />
            ))}
          </div>
          <div className="space-y-4">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-20 bg-gray-800/20 rounded-lg border border-gray-800" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error || !scan) {
    return (
      <div className="space-y-8">
        <Link
          href="/scans"
          className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Back to Scans
        </Link>
        <div className="text-center py-16">
          <svg className="w-12 h-12 mx-auto mb-3 text-red-500/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-sm text-red-400">{error ?? "Scan not found."}</p>
          <button
            onClick={fetchScanData}
            className="mt-4 btn-secondary text-xs"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const breakdown = riskBreakdown(findings);

  return (
    <div className="space-y-8">
      {/* Back link */}
      <Link
        href="/scans"
        className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 transition-colors"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
        </svg>
        Back to Scans
      </Link>

      {/* Action error */}
      {actionError && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400">
          {actionError}
        </div>
      )}

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
              {scan.target}
            </h1>
            <VerdictBadge verdict={scan.verdict} size="lg" />
          </div>
          <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
            <span>
              Type:{" "}
              <span className="text-gray-300 font-medium">{scan.target_type.toUpperCase()}</span>
            </span>
            <span>
              Score:{" "}
              <span className="font-mono text-gray-300">{scan.risk_score}</span>
            </span>
            <span>Scanned {formatDate(scan.created_at)}</span>
            {scan.metadata && Boolean((scan.metadata as Record<string, unknown>).approved) && (
              <span className="text-green-400">Approved</span>
            )}
          </div>
        </div>

        {/* Actions */}
        {!(scan.metadata && (scan.metadata as Record<string, unknown>).approved) && (
          <div className="flex gap-2">
            <button
              className="btn-primary"
              onClick={handleApprove}
              disabled={actionLoading !== null}
            >
              {actionLoading === "approve" ? (
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : (
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              )}
              Approve
            </button>
            <button
              className="btn-danger"
              onClick={handleReject}
              disabled={actionLoading !== null}
            >
              {actionLoading === "reject" ? (
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : (
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              )}
              Reject
            </button>
          </div>
        )}
      </div>

      {/* Risk Breakdown */}
      {breakdown.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h2 className="section-header">Risk Breakdown</h2>
            <p className="section-description">
              Weighted severity by scan phase.
            </p>
          </div>
          <div className="card-body">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {breakdown.map((entry) => (
                <div
                  key={entry.phase}
                  className="flex items-center justify-between p-4 bg-gray-800/30 rounded-lg border border-gray-800"
                >
                  <div>
                    <p className="text-sm font-medium text-gray-200">
                      {phaseLabels[entry.phase]}
                    </p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      {entry.count} finding{entry.count !== 1 ? "s" : ""}
                    </p>
                  </div>
                  <div className="text-right">
                    <VerdictBadge verdict={entry.maxSeverity} size="sm" />
                    <p className="text-xs text-gray-500 mt-1">
                      Weight: <span className="font-mono">{entry.totalWeight}</span>
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Findings */}
      <div>
        <div className="mb-4">
          <h2 className="section-header">
            Findings{" "}
            <span className="text-gray-500 font-normal">
              ({findings.length})
            </span>
          </h2>
          <p className="section-description">
            Detailed findings grouped by scan phase.
          </p>
        </div>
        <FindingsList findings={findings} />
      </div>

      {/* Threat hits info */}
      {scan.threat_hits > 0 && (
        <div className="card border-red-500/20">
          <div className="card-body flex items-start gap-3">
            <svg className="w-5 h-5 text-red-500 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <p className="text-sm font-medium text-red-400">
                {scan.threat_hits} known threat{scan.threat_hits !== 1 ? "s" : ""} detected
              </p>
              <p className="text-xs text-gray-500 mt-0.5">
                This target matched entries in the threat intelligence database.
                Approve or reject to proceed.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Badge embed — with point-in-time disclaimer per Section 2 */}
      <div className="card">
        <div className="card-header">
          <h2 className="section-header">Badge</h2>
          <p className="section-description">
            Embed a scan result badge in your README.
          </p>
        </div>
        <div className="card-body space-y-3">
          <p className="text-xs text-gray-500 leading-relaxed">
            The Sigil badge reflects the result of an automated point-in-time
            scan. It is not an endorsement, certification, or guarantee of
            safety. Results may change between versions. Package authors who
            display this badge are responsible for keeping their scanned
            version current.
          </p>
          <div className="bg-gray-900 rounded p-3 font-mono text-xs text-gray-300 break-all select-all">
            {`[![Scanned by Sigil](https://sigilsec.ai/badge/scan/${scan.id ?? scanId})](https://sigilsec.ai/scans/${scanId})`}
          </div>
        </div>
      </div>

      {/* Disclaimer — required per liability spec Section 1 */}
      <aside className="mt-8 p-4 rounded-lg bg-gray-900/50 border border-gray-800 text-xs text-gray-500 leading-relaxed">
        <p className="font-semibold text-gray-400 mb-2 uppercase tracking-wider text-[10px]">
          Disclaimer
        </p>
        <p>
          This scan was performed by automated static analysis. A LOW RISK
          verdict means no known malicious patterns were detected at the time
          of scanning &mdash; it does not certify that this package is safe,
          free from vulnerabilities, or suitable for any purpose. Risk
          classifications reflect the output of automated analysis based on
          defined detection criteria and are statements of algorithmic opinion,
          not assertions of malicious intent by any author or publisher. Scan
          results may contain false positives or false negatives. Always review
          source code before installing or executing any package. NOMARK Pty
          Ltd provides this information &ldquo;as is&rdquo; without warranty
          of any kind and accepts no liability for any loss or damage arising
          from reliance on these results.
        </p>
        <p className="mt-3">
          Believe this result is incorrect?{" "}
          <a
            href="mailto:security@nomark.ai"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            Request a review
          </a>{" "}
          or see our{" "}
          <a href="/terms" className="text-brand-400 hover:text-brand-300 underline">
            Terms of Service
          </a>
          {" "}and{" "}
          <a href="/methodology" className="text-brand-400 hover:text-brand-300 underline">
            Methodology
          </a>.
        </p>
      </aside>
    </div>
  );
}
