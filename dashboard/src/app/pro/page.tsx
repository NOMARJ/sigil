"use client";

import { useEffect, useState } from "react";
import { PlanBadge } from "@/components/ui/PlanBadge";
import * as api from "@/lib/api";
import type { Subscription } from "@/lib/types";

export default function ProDashboard(): JSX.Element {
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getSubscription()
      .then(setSubscription)
      .catch(() => {/* not logged in or error */})
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-8 bg-gray-800 rounded w-1/3" />
        <div className="h-4 bg-gray-800 rounded w-2/3" />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {[1, 2, 3].map((i) => (
            <div key={i} className="card">
              <div className="card-body space-y-3">
                <div className="h-6 bg-gray-800 rounded" />
                <div className="h-4 bg-gray-800 rounded" />
                <div className="h-4 bg-gray-800 rounded w-3/4" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const plan = subscription?.plan ?? "free";
  const isPro = plan === "pro" || plan === "team" || plan === "enterprise";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-3xl font-semibold" style={{ color: 'var(--color-text-primary)' }}>
            Pro Dashboard
          </h1>
          <p className="mt-2" style={{ color: 'var(--color-text-secondary)' }}>
            AI-powered threat detection insights
          </p>
        </div>
        {isPro && <PlanBadge plan={plan as 'pro' | 'enterprise'} />}
      </div>

      {/* Not on Pro */}
      {!isPro && (
        <div className="card border-brand-500/30">
          <div className="card-body text-center py-12">
            <div className="text-4xl mb-4">🔒</div>
            <h2 className="text-lg font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>Pro features require a Pro plan</h2>
            <p className="text-sm mb-6" style={{ color: 'var(--color-text-secondary)' }}>
              You&apos;re on the <span className="font-medium capitalize" style={{ color: 'var(--color-text-primary)' }}>{plan}</span> plan.
              Upgrade to unlock AI-powered threat analysis.
            </p>
            <a href="/pricing" className="btn-primary">Upgrade to Pro</a>
          </div>
        </div>
      )}

      {/* Pro user */}
      {isPro && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="card">
              <div className="card-body">
                <p className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--color-text-muted)' }}>PLAN</p>
                <p className="text-2xl font-bold capitalize" style={{ color: 'var(--color-accent)' }}>{plan}</p>
                <p className="text-xs mt-1 capitalize" style={{ color: 'var(--color-text-muted)' }}>
                  {subscription?.status ?? "active"}
                </p>
              </div>
            </div>
            <div className="card">
              <div className="card-body">
                <p className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--color-text-muted)' }}>RENEWS</p>
                <p className="text-lg font-semibold" style={{ color: 'var(--color-text-primary)' }}>
                  {subscription?.current_period_end
                    ? new Date(subscription.current_period_end).toLocaleDateString("en-US", {
                        month: "short", day: "numeric", year: "numeric",
                      })
                    : "—"}
                </p>
                <p className="text-xs mt-1 capitalize" style={{ color: 'var(--color-text-muted)' }}>
                  {subscription?.billing_interval ?? "monthly"} billing
                </p>
              </div>
            </div>
            <div className="card">
              <div className="card-body">
                <p className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--color-text-muted)' }}>AI ANALYSIS</p>
                <p className="text-lg font-semibold" style={{ color: 'var(--color-accent)' }}>Enabled</p>
                <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>LLM threat detection active</p>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-body text-center py-12">
              <div className="w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-4" style={{ background: 'var(--color-accent-glow)', border: '1px solid var(--color-accent)' }}>
                <svg className="w-6 h-6" style={{ color: 'var(--color-accent)' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
              <h2 className="text-base font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>AI insights appear on scan results</h2>
              <p className="text-sm max-w-sm mx-auto mb-6" style={{ color: 'var(--color-text-secondary)' }}>
                Run a scan on a package or repository to get AI-powered threat analysis,
                zero-day detection, and remediation suggestions.
              </p>
              <a href="/scans" className="btn-secondary text-sm">View Scans</a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
