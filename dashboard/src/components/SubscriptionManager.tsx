"use client";

import { useState } from "react";
import * as api from "@/lib/api";

interface SubscriptionDetails {
  plan: string;
  status: string;
  billing_interval: "monthly" | "annual";
  current_period_start?: string | null;
  current_period_end?: string | null;
  cancel_at_period_end?: boolean;
  price_amount?: number;
  stripe_subscription_id?: string;
  checkout_url?: string;
}

interface SubscriptionManagerProps {
  subscription: SubscriptionDetails | null;
  onSubscriptionUpdate?: (subscription: SubscriptionDetails) => void;
}

export function SubscriptionManager({
  subscription,
}: SubscriptionManagerProps) {
  const [portalLoading, setPortalLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleManageBilling = async (): Promise<void> => {
    setPortalLoading(true);
    setError(null);
    try {
      const session = await api.createPortalSession();
      window.location.href = session.url;
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to open billing portal",
      );
    } finally {
      setPortalLoading(false);
    }
  };

  if (!subscription || subscription.plan === "free") {
    return (
      <div className="card border-blue-500/30">
        <div className="card-body text-center py-8">
          <div className="text-4xl mb-4">💎</div>
          <h3
            className="text-lg font-semibold mb-2"
            style={{ color: "var(--color-text-primary)" }}
          >
            No active subscription
          </h3>
          <p
            className="text-sm mb-6"
            style={{ color: "var(--color-text-secondary)" }}
          >
            You&apos;re currently on the free plan. Upgrade to Pro for AI
            investigation features and 5,000 monthly credits.
          </p>
          <a href="/pricing" className="btn-primary">
            View Plans
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2
          className="text-xl font-semibold mb-2"
          style={{ color: "var(--color-text-primary)" }}
        >
          Subscription Management
        </h2>
        <p
          className="text-sm"
          style={{ color: "var(--color-text-secondary)" }}
        >
          Manage your billing, payment method, invoices, and cancellation in
          the secure Stripe Customer Portal.
        </p>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400">
          {error}
        </div>
      )}

      <div className="card">
        <div className="card-body">
          <div className="flex items-start justify-between mb-4">
            <div>
              <h3
                className="text-lg font-semibold capitalize mb-1"
                style={{ color: "var(--color-text-primary)" }}
              >
                {subscription.plan} Plan
              </h3>
              <div className="flex items-center gap-3 text-sm">
                <span
                  className={`px-2 py-1 rounded text-xs font-medium ${
                    subscription.status === "active"
                      ? "bg-green-500/10 text-green-400 border border-green-500/20"
                      : subscription.status === "trialing"
                        ? "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                        : "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
                  }`}
                >
                  {subscription.status.charAt(0).toUpperCase() +
                    subscription.status.slice(1)}
                </span>
                <span
                  style={{ color: "var(--color-text-muted)" }}
                  className="capitalize"
                >
                  {subscription.billing_interval} billing
                </span>
                {subscription.price_amount && (
                  <span style={{ color: "var(--color-text-muted)" }}>
                    ${subscription.price_amount}/
                    {subscription.billing_interval === "annual"
                      ? "year"
                      : "month"}
                  </span>
                )}
              </div>
              {subscription.cancel_at_period_end && (
                <p className="text-sm mt-2 text-yellow-400">
                  ⚠️ Subscription will cancel on{" "}
                  {subscription.current_period_end
                    ? new Date(
                        subscription.current_period_end,
                      ).toLocaleDateString()
                    : "the next billing date"}
                </p>
              )}
            </div>
            <button
              onClick={handleManageBilling}
              disabled={portalLoading}
              className="btn-primary"
            >
              {portalLoading ? (
                <span className="flex items-center gap-2">
                  <svg
                    className="animate-spin h-4 w-4"
                    viewBox="0 0 24 24"
                    fill="none"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                    />
                  </svg>
                  Opening...
                </span>
              ) : (
                "Manage in Stripe"
              )}
            </button>
          </div>

          {subscription.current_period_start &&
            subscription.current_period_end && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 bg-gray-800/30 rounded-lg">
                <div>
                  <p
                    className="text-xs font-medium uppercase tracking-wider mb-1"
                    style={{ color: "var(--color-text-muted)" }}
                  >
                    CURRENT PERIOD START
                  </p>
                  <p
                    className="text-sm"
                    style={{ color: "var(--color-text-primary)" }}
                  >
                    {new Date(
                      subscription.current_period_start,
                    ).toLocaleDateString("en-US", {
                      year: "numeric",
                      month: "long",
                      day: "numeric",
                    })}
                  </p>
                </div>
                <div>
                  <p
                    className="text-xs font-medium uppercase tracking-wider mb-1"
                    style={{ color: "var(--color-text-muted)" }}
                  >
                    NEXT BILLING DATE
                  </p>
                  <p
                    className="text-sm"
                    style={{ color: "var(--color-text-primary)" }}
                  >
                    {new Date(
                      subscription.current_period_end,
                    ).toLocaleDateString("en-US", {
                      year: "numeric",
                      month: "long",
                      day: "numeric",
                    })}
                  </p>
                </div>
              </div>
            )}
        </div>
      </div>

      <div className="card">
        <div className="card-body">
          <h3
            className="text-sm font-semibold mb-2"
            style={{ color: "var(--color-text-primary)" }}
          >
            Payment, invoices &amp; cancellation
          </h3>
          <p
            className="text-sm mb-4"
            style={{ color: "var(--color-text-secondary)" }}
          >
            Update your payment method, download invoices, or cancel your
            subscription in the Stripe Customer Portal.
          </p>
          <button
            onClick={handleManageBilling}
            disabled={portalLoading}
            className="btn-secondary text-sm"
          >
            {portalLoading ? "Opening..." : "Open Stripe Portal"}
          </button>
        </div>
      </div>
    </div>
  );
}
