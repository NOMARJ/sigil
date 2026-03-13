"use client";

import { useEffect, useState } from "react";
import { PlanBadge } from "@/components/ui/PlanBadge";
import { CreditUsageDashboard } from "@/components/CreditUsageDashboard";
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
            AI investigation features and credit usage analytics
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
              Upgrade to unlock AI investigation features and 5,000 monthly credits.
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
                <p className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--color-text-muted)' }}>AI FEATURES</p>
                <p className="text-lg font-semibold" style={{ color: 'var(--color-accent)' }}>Active</p>
                <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>Investigation assistant enabled</p>
              </div>
            </div>
          </div>

          <CreditUsageDashboard subscription={subscription || undefined} />

          <div className="card">
            <div className="card-body text-center py-8">
              <h3 className="text-base font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
                AI Features Available
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                <div className="p-3 rounded border border-gray-800">
                  <div className="w-8 h-8 rounded-full bg-blue-500/20 flex items-center justify-center mx-auto mb-2">
                    <svg className="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <h4 className="text-sm font-medium mb-1" style={{ color: 'var(--color-text-primary)' }}>Investigation</h4>
                  <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Deep analysis of security findings</p>
                </div>
                <div className="p-3 rounded border border-gray-800">
                  <div className="w-8 h-8 rounded-full bg-green-500/20 flex items-center justify-center mx-auto mb-2">
                    <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <h4 className="text-sm font-medium mb-1" style={{ color: 'var(--color-text-primary)' }}>Verification</h4>
                  <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>False positive detection</p>
                </div>
                <div className="p-3 rounded border border-gray-800">
                  <div className="w-8 h-8 rounded-full bg-purple-500/20 flex items-center justify-center mx-auto mb-2">
                    <svg className="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                    </svg>
                  </div>
                  <h4 className="text-sm font-medium mb-1" style={{ color: 'var(--color-text-primary)' }}>Chat</h4>
                  <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Interactive security assistant</p>
                </div>
              </div>
              <div className="mt-6">
                <a href="/scans" className="btn-secondary text-sm mr-2">View Scans</a>
                <a href="/settings" className="btn-outline text-sm">Manage Subscription</a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
