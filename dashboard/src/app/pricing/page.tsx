"use client";

import { useState, useEffect } from "react";
import { PlanBadge } from "@/components/ui/PlanBadge";
import * as api from "@/lib/api";
import type { Subscription } from "@/lib/types";

export default function PricingPage(): JSX.Element {
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [loading, setLoading] = useState(true);
  const [portalLoading, setPortalLoading] = useState(false);

  useEffect(() => {
    api.getSubscription()
      .then(setSubscription)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const handleManage = async () => {
    setPortalLoading(true);
    try {
      const session = await api.createPortalSession();
      window.location.href = session.url;
    } catch {
      alert("Unable to open billing portal. Please try again.");
    } finally {
      setPortalLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6 animate-pulse max-w-2xl mx-auto pt-8">
        <div className="h-8 bg-gray-800 rounded w-1/2" />
        <div className="h-4 bg-gray-800 rounded w-3/4" />
        <div className="h-48 bg-gray-800/50 rounded-xl border border-gray-800" />
      </div>
    );
  }

  const plan = subscription?.plan ?? "free";
  const isActive = subscription?.status === "active" || subscription?.status === "trialing";
  const isPaid = plan !== "free";

  // Subscribed user — show account/billing management
  if (isPaid && isActive) {
    const renewDate = subscription?.current_period_end
      ? new Date(subscription.current_period_end).toLocaleDateString("en-US", {
          month: "long", day: "numeric", year: "numeric",
        })
      : null;

    const PLAN_FEATURES: Record<string, string[]> = {
      pro: [
        "5,000 monthly AI credits",
        "AI Investigation Assistant",
        "False Positive Verification",
        "Interactive Security Chat",
        "Transform scanner into AI consultant",
        "Attack chain tracing & analysis",
        "Security version comparison",
        "Compliance mapping & reporting",
        "Priority support & API access",
      ],
      team: [
        "50,000 monthly AI credits",
        "Everything in Pro",
        "Team dashboard & management",
        "RBAC & audit log",
        "Slack / webhook alerts",
        "Custom policies",
        "SSO (SAML)",
      ],
      enterprise: [
        "Unlimited AI credits",
        "Everything in Team",
        "Dedicated account manager",
        "Custom integrations",
        "SLA guarantee",
        "On-premise deployment option",
        "Advanced audit & compliance",
        "SSO (SAML / OIDC)",
      ],
    };

    const features = PLAN_FEATURES[plan] ?? [];

    return (
      <div className="space-y-6 max-w-2xl">
        <div>
          <h1 className="text-3xl font-semibold" style={{ color: 'var(--color-text-primary)' }}>Subscription</h1>
          <p className="mt-2" style={{ color: 'var(--color-text-secondary)' }}>Manage your plan and billing</p>
        </div>

        {/* Current plan card */}
        <div className="card border-brand-500/30">
          <div className="card-body">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-lg font-bold capitalize" style={{ color: 'var(--color-text-primary)' }}>{plan}</span>
                  <PlanBadge plan={plan as 'pro' | 'enterprise'} />
                </div>
                <p className="text-sm capitalize" style={{ color: 'var(--color-text-muted)' }}>
                  {subscription?.billing_interval ?? "monthly"} billing
                  {renewDate && ` · renews ${renewDate}`}
                </p>
              </div>
              <button
                onClick={handleManage}
                disabled={portalLoading}
                className="btn-secondary text-sm shrink-0"
              >
                {portalLoading ? "Opening..." : "Manage Billing"}
              </button>
            </div>

            {features.length > 0 && (
              <div className="mt-5 pt-5 border-t border-gray-800">
                <p className="text-xs font-medium uppercase tracking-wider mb-3" style={{ color: 'var(--color-text-muted)' }}>INCLUDED IN YOUR PLAN</p>
                <ul className="grid grid-cols-1 sm:grid-cols-2 gap-y-2 gap-x-4">
                  {features.map((f) => (
                    <li key={f} className="flex items-center gap-2 text-sm" style={{ color: 'var(--color-text-secondary)' }}>
                      <svg className="w-4 h-4 shrink-0" style={{ color: 'var(--color-accent)' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                      {f}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>

        {/* Upgrade path for pro users */}
        {plan === "pro" && (
          <div className="card">
            <div className="card-body">
              <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--color-text-primary)' }}>Need more?</h2>
              <p className="text-sm mb-4" style={{ color: 'var(--color-text-secondary)' }}>
                Team plan includes 50,000 monthly AI credits, RBAC, audit logs, and Slack alerts.
              </p>
              <button onClick={handleManage} className="btn-secondary text-sm">
                Upgrade to Team
              </button>
            </div>
          </div>
        )}

        <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
          To cancel or update payment details, use the billing portal above.
          Contact <a href="mailto:support@sigilsec.ai" className="hover:opacity-80" style={{ color: 'var(--color-accent)' }}>support@sigilsec.ai</a> for help.
        </p>
      </div>
    );
  }

  // Free user — minimal upgrade prompt
  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-3xl font-semibold" style={{ color: 'var(--color-text-primary)' }}>Upgrade to Pro</h1>
        <p className="mt-2" style={{ color: 'var(--color-text-secondary)' }}>
          You&apos;re on the free plan. Transform your scanner into an AI security consultant for $29/month.
        </p>
      </div>

      <div className="card border-brand-500/30">
        <div className="card-body">
          <div className="flex items-baseline gap-1 mb-4">
            <span className="text-3xl font-bold" style={{ color: 'var(--color-text-primary)' }}>$29</span>
            <span style={{ color: 'var(--color-text-muted)' }}>/month</span>
          </div>
          <ul className="space-y-2 mb-6">
            {[
              "5,000 monthly AI credits",
              "AI Investigation Assistant",
              "False Positive Verification",
              "Interactive Security Chat",
              "Attack chain tracing & analysis",
              "Priority support & API access",
            ].map((f) => (
              <li key={f} className="flex items-center gap-2 text-sm" style={{ color: 'var(--color-text-secondary)' }}>
                <svg className="w-4 h-4 shrink-0" style={{ color: 'var(--color-accent)' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                {f}
              </li>
            ))}
          </ul>
          <a href="/settings" className="btn-primary w-full text-center block">
            Subscribe — $29/month
          </a>
        </div>
      </div>
    </div>
  );
}
