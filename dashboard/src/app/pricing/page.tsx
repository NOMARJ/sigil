"use client";

import { useState, useEffect } from "react";
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
        "500 scans / month",
        "AI-powered threat detection (LLM analysis)",
        "Zero-day vulnerability detection",
        "Advanced obfuscation analysis",
        "Contextual threat correlation",
        "AI-generated remediation suggestions",
        "Full threat intelligence access",
        "Priority support",
        "API access",
      ],
      team: [
        "5,000 scans / month",
        "Everything in Pro",
        "Team dashboard",
        "RBAC & audit log",
        "Slack / webhook alerts",
        "Custom policies",
        "SSO (SAML)",
      ],
      enterprise: [
        "Unlimited scans",
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
          <h1 className="text-2xl font-bold text-gray-100 tracking-tight">Subscription</h1>
          <p className="text-sm text-gray-500 mt-1">Manage your plan and billing</p>
        </div>

        {/* Current plan card */}
        <div className="card border-brand-500/30">
          <div className="card-body">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-lg font-bold text-gray-100 capitalize">{plan}</span>
                  <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
                    Active
                  </span>
                </div>
                <p className="text-sm text-gray-500 capitalize">
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
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-3">Included in your plan</p>
                <ul className="grid grid-cols-1 sm:grid-cols-2 gap-y-2 gap-x-4">
                  {features.map((f) => (
                    <li key={f} className="flex items-center gap-2 text-sm text-gray-300">
                      <svg className="w-4 h-4 text-green-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
              <h2 className="text-sm font-semibold text-gray-100 mb-1">Need more?</h2>
              <p className="text-sm text-gray-500 mb-4">
                Team plan includes 5,000 scans/month, RBAC, audit logs, and Slack alerts.
              </p>
              <button onClick={handleManage} className="btn-secondary text-sm">
                Upgrade to Team
              </button>
            </div>
          </div>
        )}

        <p className="text-xs text-gray-600">
          To cancel or update payment details, use the billing portal above.
          Contact <a href="mailto:support@sigilsec.ai" className="text-brand-400 hover:text-brand-300">support@sigilsec.ai</a> for help.
        </p>
      </div>
    );
  }

  // Free user — minimal upgrade prompt
  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-100 tracking-tight">Upgrade to Pro</h1>
        <p className="text-sm text-gray-500 mt-1">
          You&apos;re on the free plan. Get AI-powered threat detection for $29/month.
        </p>
      </div>

      <div className="card border-brand-500/30">
        <div className="card-body">
          <div className="flex items-baseline gap-1 mb-4">
            <span className="text-3xl font-bold text-gray-100">$29</span>
            <span className="text-gray-500">/month</span>
          </div>
          <ul className="space-y-2 mb-6">
            {[
              "500 scans / month",
              "AI-powered LLM threat analysis",
              "Zero-day vulnerability detection",
              "Advanced obfuscation analysis",
              "Full threat intelligence access",
              "Priority support & API access",
            ].map((f) => (
              <li key={f} className="flex items-center gap-2 text-sm text-gray-300">
                <svg className="w-4 h-4 text-green-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
