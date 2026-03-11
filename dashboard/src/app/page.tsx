"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { EnhancedStatsCard } from "@/components/ui/EnhancedStatsCard";
import { RiskFilterBar } from "@/components/ui/RiskFilterBar";
import ScanTable from "@/components/ScanTable";
import * as api from "@/lib/api";
import type { DashboardStats, Scan } from "@/lib/types";

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchData() {
      setLoading(true);
      setError(null);

      try {
        const [statsData, scansData] = await Promise.all([
          api.getDashboardStats(),
          api.listScans({ page: 1, per_page: 5 }),
        ]);

        if (!cancelled) {
          setStats(statsData);
          setRecentScans(scansData.items);
        }
      } catch (err) {
        if (!cancelled) {
          const message =
            err instanceof Error
              ? err.message
              : "Failed to load dashboard data.";
          setError(message);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    fetchData();
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-semibold" style={{ color: 'var(--color-text-primary)' }}>
          Dashboard
        </h1>
        <p className="mt-2" style={{ color: 'var(--color-text-secondary)' }}>
          Security overview for your AI agent supply chain
        </p>
      </div>

      {/* Error banner */}
      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {loading ? (
          <>
            {[1, 2, 3, 4].map((i) => (
              <div
                key={i}
                className="bg-gray-900 border border-gray-800 rounded-xl p-5 animate-pulse"
              >
                <div className="h-3 w-24 bg-gray-800 rounded mb-4" />
                <div className="h-8 w-16 bg-gray-800 rounded mb-3" />
                <div className="h-3 w-20 bg-gray-800 rounded" />
              </div>
            ))}
          </>
        ) : stats ? (
          <>
            <EnhancedStatsCard
              title="TOTAL SCANS"
              value={stats.total_scans.toLocaleString()}
              subtitle="all time"
              trend={stats.scans_trend ? { value: Math.abs(stats.scans_trend), isPositive: stats.scans_trend > 0 } : undefined}
              status="default"
              icon={
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              }
            />
            <EnhancedStatsCard
              title="CRITICAL THREATS"
              value={stats.threats_blocked}
              subtitle="this month"
              trend={stats.threats_trend ? { value: Math.abs(stats.threats_trend), isPositive: false } : undefined}
              status="danger"
              icon={
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              }
            />
            <EnhancedStatsCard
              title="PACKAGES APPROVED"
              value={stats.packages_approved.toLocaleString()}
              subtitle="all time"
              status="success"
              icon={
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              }
            />
            <EnhancedStatsCard
              title="HIGH RISK"
              value={stats.critical_findings}
              subtitle="pending review"
              status="warning"
              icon={
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              }
            />
          </>
        ) : null}
      </div>

      {/* Recent Scans */}
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <div>
            <h2 className="section-header">Recent Scans</h2>
            <p className="section-description">
              Latest package and repository scans.
            </p>
          </div>
          <Link
            href="/scans"
            className="btn-ghost text-xs"
          >
            View all
          </Link>
        </div>
        <div className="card-body">
          {loading ? (
            <div className="space-y-3">
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="flex items-center gap-4 animate-pulse">
                  <div className="h-4 w-32 bg-gray-800 rounded" />
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
            <ScanTable scans={recentScans} />
          )}
        </div>
      </div>
    </div>
  );
}
