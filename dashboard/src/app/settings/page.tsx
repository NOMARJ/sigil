"use client";

import { useState, useEffect, useCallback } from "react";
import * as api from "@/lib/api";
import type { Verdict, AlertChannel, AlertChannelType, Policy, BillingPlan, Subscription } from "@/lib/types";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const verdictLevels: Verdict[] = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

const channelTypeStyles: Record<string, string> = {
  slack: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  email: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  webhook: "bg-green-500/10 text-green-400 border-green-500/20",
};

const channelTypeIcons: Record<string, string> = {
  slack: "Slack",
  email: "Email",
  webhook: "Webhook",
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function SettingsPage() {
  // Policy state
  const [autoApproveThreshold, setAutoApproveThreshold] = useState<Verdict>("CLEAN");
  const [allowlist, setAllowlist] = useState("");
  const [blocklist, setBlocklist] = useState("");
  const [requireApproval, setRequireApproval] = useState<Verdict[]>([]);

  // Alert channels state
  const [channels, setChannels] = useState<AlertChannel[]>([]);
  const [newChannelType, setNewChannelType] = useState<AlertChannelType>("slack");
  const [newChannelTarget, setNewChannelTarget] = useState("");
  const [newChannelSeverity, setNewChannelSeverity] = useState<Verdict>("HIGH");

  // Billing state
  const [plans, setPlans] = useState<BillingPlan[]>([]);
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [billingInterval, setBillingInterval] = useState<"monthly" | "annual">("monthly");

  // Loading / error states
  const [policyLoading, setPolicyLoading] = useState(true);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [policySaving, setPolicySaving] = useState(false);
  const [policySaveSuccess, setPolicySaveSuccess] = useState(false);

  const [alertsLoading, setAlertsLoading] = useState(true);
  const [alertsError, setAlertsError] = useState<string | null>(null);
  const [addChannelLoading, setAddChannelLoading] = useState(false);

  const [billingLoading, setBillingLoading] = useState(true);
  const [billingError, setBillingError] = useState<string | null>(null);
  const [portalLoading, setPortalLoading] = useState(false);

  // ---------------------------------------------------------------------------
  // Fetch data
  // ---------------------------------------------------------------------------

  const fetchPolicy = useCallback(async () => {
    setPolicyLoading(true);
    setPolicyError(null);

    try {
      const policy: Policy = await api.listPolicies();
      setAutoApproveThreshold(policy.auto_approve_threshold ?? "CLEAN");
      setAllowlist((policy.allowlisted_packages ?? []).join("\n"));
      setBlocklist((policy.blocklisted_packages ?? []).join("\n"));
      setRequireApproval(policy.require_approval_for ?? []);
    } catch (err) {
      setPolicyError(
        err instanceof Error ? err.message : "Failed to load policy settings.",
      );
      console.error("Failed to fetch policy:", err);
    } finally {
      setPolicyLoading(false);
    }
  }, []);

  const fetchAlerts = useCallback(async () => {
    setAlertsLoading(true);
    setAlertsError(null);

    try {
      const data = await api.listAlerts();
      setChannels(data ?? []);
    } catch (err) {
      setAlertsError(
        err instanceof Error ? err.message : "Failed to load alert channels.",
      );
      console.error("Failed to fetch alerts:", err);
    } finally {
      setAlertsLoading(false);
    }
  }, []);

  const fetchBilling = useCallback(async () => {
    setBillingLoading(true);
    setBillingError(null);

    try {
      const [plansData, subData] = await Promise.allSettled([
        api.getPlans(),
        api.getSubscription(),
      ]);

      if (plansData.status === "fulfilled") {
        setPlans(plansData.value ?? []);
      } else {
        console.error("Failed to fetch plans:", plansData.reason);
      }

      if (subData.status === "fulfilled") {
        setSubscription(subData.value);
      } else {
        console.error("Failed to fetch subscription:", subData.reason);
      }
    } catch (err) {
      setBillingError(
        err instanceof Error ? err.message : "Failed to load billing data.",
      );
      console.error("Failed to fetch billing:", err);
    } finally {
      setBillingLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPolicy();
    fetchAlerts();
    fetchBilling();
  }, [fetchPolicy, fetchAlerts, fetchBilling]);

  // ---------------------------------------------------------------------------
  // Policy handlers
  // ---------------------------------------------------------------------------

  const toggleApproval = (verdict: Verdict) => {
    setRequireApproval((prev) =>
      prev.includes(verdict)
        ? prev.filter((v) => v !== verdict)
        : [...prev, verdict],
    );
  };

  const handleSavePolicy = async () => {
    setPolicySaving(true);
    setPolicyError(null);
    setPolicySaveSuccess(false);

    try {
      const policy: Partial<Policy> = {
        auto_approve_threshold: autoApproveThreshold,
        allowlisted_packages: allowlist
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
        blocklisted_packages: blocklist
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
        require_approval_for: requireApproval,
      };

      await api.updatePolicy(policy);
      setPolicySaveSuccess(true);
      setTimeout(() => setPolicySaveSuccess(false), 3000);
    } catch (err) {
      setPolicyError(
        err instanceof Error ? err.message : "Failed to save policy settings.",
      );
    } finally {
      setPolicySaving(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Alert channel handlers
  // ---------------------------------------------------------------------------

  const toggleChannel = async (id: string) => {
    const channel = channels.find((c) => c.id === id);
    if (!channel) return;

    try {
      const updated = await api.updateAlert(id, { enabled: !channel.enabled });
      setChannels((prev) =>
        prev.map((c) => (c.id === id ? { ...c, enabled: updated.enabled } : c)),
      );
    } catch (err) {
      setAlertsError(
        err instanceof Error ? err.message : "Failed to toggle alert channel.",
      );
    }
  };

  const removeChannel = async (id: string) => {
    try {
      await api.deleteAlert(id);
      setChannels((prev) => prev.filter((c) => c.id !== id));
    } catch (err) {
      setAlertsError(
        err instanceof Error ? err.message : "Failed to remove alert channel.",
      );
    }
  };

  const addChannel = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newChannelTarget.trim()) return;

    setAddChannelLoading(true);
    setAlertsError(null);

    try {
      const newChannel = await api.createAlert({
        type: newChannelType,
        target: newChannelTarget.trim(),
        enabled: true,
        min_severity: newChannelSeverity,
      });
      setChannels((prev) => [...prev, newChannel]);
      setNewChannelTarget("");
    } catch (err) {
      setAlertsError(
        err instanceof Error ? err.message : "Failed to add alert channel.",
      );
    } finally {
      setAddChannelLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Billing handlers
  // ---------------------------------------------------------------------------

  const handleManageBilling = async () => {
    setPortalLoading(true);
    setBillingError(null);

    try {
      const session = await api.createPortalSession();
      window.open(session.url, "_blank");
    } catch (err) {
      setBillingError(
        err instanceof Error ? err.message : "Failed to open billing portal.",
      );
    } finally {
      setPortalLoading(false);
    }
  };

  const handleSubscribe = async (planId: string) => {
    setBillingError(null);

    try {
      const sub = await api.subscribe(planId, billingInterval);
      setSubscription(sub);
    } catch (err) {
      setBillingError(
        err instanceof Error ? err.message : "Failed to subscribe to plan.",
      );
    }
  };

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
          Settings
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Configure scan policies, allowlists, alert channels, and billing.
        </p>
      </div>

      {/* Policies */}
      <div className="card">
        <div className="card-header">
          <h2 className="section-header">Scan Policies</h2>
          <p className="section-description">
            Control how scans are automatically processed.
          </p>
        </div>
        <div className="card-body space-y-6">
          {policyLoading ? (
            <div className="space-y-6 animate-pulse">
              <div className="h-4 w-40 bg-gray-800 rounded" />
              <div className="flex gap-2">
                {[1, 2, 3, 4, 5].map((i) => (
                  <div key={i} className="h-8 w-16 bg-gray-800 rounded-lg" />
                ))}
              </div>
              <div className="h-4 w-48 bg-gray-800 rounded" />
              <div className="h-24 bg-gray-800 rounded" />
              <div className="h-24 bg-gray-800 rounded" />
            </div>
          ) : (
            <>
              {policyError && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400">
                  {policyError}
                </div>
              )}

              {policySaveSuccess && (
                <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20 text-sm text-green-400">
                  Policy settings saved successfully.
                </div>
              )}

              {/* Auto-approve threshold */}
              <div>
                <label className="input-label">Auto-Approve Threshold</label>
                <p className="text-xs text-gray-500 mb-2">
                  Packages with a verdict at or below this level will be automatically approved.
                </p>
                <div className="flex gap-2">
                  {verdictLevels.map((v) => (
                    <button
                      key={v}
                      onClick={() => setAutoApproveThreshold(v)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                        autoApproveThreshold === v
                          ? "bg-brand-600/20 text-brand-400 border border-brand-500/30"
                          : "bg-gray-800/50 text-gray-400 border border-gray-800 hover:border-gray-700"
                      }`}
                    >
                      {v}
                    </button>
                  ))}
                </div>
              </div>

              {/* Require approval for */}
              <div>
                <label className="input-label">Require Manual Approval For</label>
                <p className="text-xs text-gray-500 mb-2">
                  Verdicts that always require human review before approval.
                </p>
                <div className="flex gap-2">
                  {verdictLevels.map((v) => (
                    <button
                      key={v}
                      onClick={() => toggleApproval(v)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                        requireApproval.includes(v)
                          ? "bg-red-600/20 text-red-400 border border-red-500/30"
                          : "bg-gray-800/50 text-gray-400 border border-gray-800 hover:border-gray-700"
                      }`}
                    >
                      {v}
                    </button>
                  ))}
                </div>
              </div>

              {/* Allowlist */}
              <div>
                <label htmlFor="allowlist" className="input-label">
                  Allowlisted Packages
                </label>
                <p className="text-xs text-gray-500 mb-2">
                  One package name per line. These packages will always be auto-approved.
                </p>
                <textarea
                  id="allowlist"
                  value={allowlist}
                  onChange={(e) => setAllowlist(e.target.value)}
                  rows={4}
                  className="input font-mono text-xs"
                  placeholder="package-name"
                />
              </div>

              {/* Blocklist */}
              <div>
                <label htmlFor="blocklist" className="input-label">
                  Blocklisted Packages
                </label>
                <p className="text-xs text-gray-500 mb-2">
                  One package name per line. These packages will always be rejected. Append @version to block specific versions.
                </p>
                <textarea
                  id="blocklist"
                  value={blocklist}
                  onChange={(e) => setBlocklist(e.target.value)}
                  rows={4}
                  className="input font-mono text-xs"
                  placeholder="package-name@version"
                />
              </div>

              <div className="pt-2">
                <button
                  className="btn-primary"
                  onClick={handleSavePolicy}
                  disabled={policySaving}
                >
                  {policySaving ? (
                    <span className="flex items-center gap-2">
                      <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                      Saving...
                    </span>
                  ) : (
                    "Save Policies"
                  )}
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Alert Channels */}
      <div className="card">
        <div className="card-header">
          <h2 className="section-header">Alert Channels</h2>
          <p className="section-description">
            Configure where to receive notifications about scan results.
          </p>
        </div>
        <div className="card-body space-y-6">
          {alertsError && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400">
              {alertsError}
            </div>
          )}

          {/* Existing channels */}
          {alertsLoading ? (
            <div className="space-y-3 animate-pulse">
              {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center justify-between p-4 bg-gray-800/30 rounded-lg border border-gray-800">
                  <div className="flex items-center gap-4">
                    <div className="h-6 w-14 bg-gray-800 rounded-full" />
                    <div>
                      <div className="h-4 w-40 bg-gray-800 rounded mb-1" />
                      <div className="h-3 w-24 bg-gray-800 rounded" />
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="h-6 w-11 bg-gray-800 rounded-full" />
                    <div className="h-4 w-4 bg-gray-800 rounded" />
                  </div>
                </div>
              ))}
            </div>
          ) : channels.length > 0 ? (
            <div className="space-y-3">
              {channels.map((channel) => (
                <div
                  key={channel.id}
                  className="flex items-center justify-between p-4 bg-gray-800/30 rounded-lg border border-gray-800"
                >
                  <div className="flex items-center gap-4">
                    <span
                      className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${channelTypeStyles[channel.type]}`}
                    >
                      {channelTypeIcons[channel.type]}
                    </span>
                    <div>
                      <p className="text-sm font-medium text-gray-200 font-mono">
                        {channel.target}
                      </p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        Min severity: {channel.min_severity}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    {/* Toggle */}
                    <button
                      onClick={() => toggleChannel(channel.id)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        channel.enabled ? "bg-brand-600" : "bg-gray-700"
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          channel.enabled ? "translate-x-6" : "translate-x-1"
                        }`}
                      />
                    </button>
                    {/* Remove */}
                    <button
                      onClick={() => removeChannel(channel.id)}
                      className="text-gray-500 hover:text-red-400 transition-colors"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-6 text-gray-500">
              <p className="text-sm">No alert channels configured yet.</p>
            </div>
          )}

          {/* Add channel form */}
          <div className="border-t border-gray-800 pt-6">
            <h3 className="text-sm font-medium text-gray-300 mb-3">
              Add Alert Channel
            </h3>
            <form onSubmit={addChannel} className="flex items-end gap-4">
              <div className="w-36">
                <label htmlFor="channel-type" className="input-label">
                  Type
                </label>
                <select
                  id="channel-type"
                  value={newChannelType}
                  onChange={(e) =>
                    setNewChannelType(e.target.value as AlertChannelType)
                  }
                  className="input"
                >
                  <option value="slack">Slack</option>
                  <option value="email">Email</option>
                  <option value="webhook">Webhook</option>
                </select>
              </div>
              <div className="flex-1">
                <label htmlFor="channel-target" className="input-label">
                  Target
                </label>
                <input
                  id="channel-target"
                  type="text"
                  placeholder={
                    newChannelType === "slack"
                      ? "#channel-name"
                      : newChannelType === "email"
                        ? "email@example.com"
                        : "https://webhook.url/..."
                  }
                  value={newChannelTarget}
                  onChange={(e) => setNewChannelTarget(e.target.value)}
                  className="input"
                  required
                />
              </div>
              <div className="w-36">
                <label htmlFor="channel-severity" className="input-label">
                  Min Severity
                </label>
                <select
                  id="channel-severity"
                  value={newChannelSeverity}
                  onChange={(e) =>
                    setNewChannelSeverity(e.target.value as Verdict)
                  }
                  className="input"
                >
                  {verdictLevels.map((v) => (
                    <option key={v} value={v}>
                      {v}
                    </option>
                  ))}
                </select>
              </div>
              <button
                type="submit"
                className="btn-primary whitespace-nowrap"
                disabled={addChannelLoading}
              >
                {addChannelLoading ? (
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                ) : (
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                  </svg>
                )}
                Add
              </button>
            </form>
          </div>
        </div>
      </div>

      {/* Billing / Subscription */}
      <div className="card">
        <div className="card-header">
          <h2 className="section-header">Billing & Subscription</h2>
          <p className="section-description">
            Manage your plan and payment details.
          </p>
        </div>
        <div className="card-body space-y-6">
          {billingError && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400">
              {billingError}
            </div>
          )}

          {billingLoading ? (
            <div className="space-y-4 animate-pulse">
              <div className="h-4 w-32 bg-gray-800 rounded" />
              <div className="grid grid-cols-3 gap-4">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-40 bg-gray-800/30 rounded-lg border border-gray-800" />
                ))}
              </div>
            </div>
          ) : (
            <>
              {/* Current subscription */}
              {subscription && (
                <div className="p-4 bg-gray-800/30 rounded-lg border border-gray-800">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-200">
                        Current Plan:{" "}
                        <span className="text-brand-400">{subscription.plan_name}</span>
                      </p>
                      <p className="text-xs text-gray-500 mt-1">
                        Status:{" "}
                        <span className={`font-medium ${
                          subscription.status === "active"
                            ? "text-green-400"
                            : subscription.status === "trialing"
                              ? "text-blue-400"
                              : "text-yellow-400"
                        }`}>
                          {subscription.status.charAt(0).toUpperCase() + subscription.status.slice(1)}
                        </span>
                        {subscription.cancel_at_period_end && (
                          <span className="text-yellow-400 ml-2">
                            (cancels at end of period)
                          </span>
                        )}
                      </p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        Billing: {subscription.billing_interval === "annual" ? "Annual" : "Monthly"}
                      </p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        Period: {new Date(subscription.current_period_start).toLocaleDateString()} --{" "}
                        {new Date(subscription.current_period_end).toLocaleDateString()}
                      </p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        Scans used: {(subscription.scan_usage ?? 0).toLocaleString()} / {(subscription.scan_limit ?? 0).toLocaleString()}
                      </p>
                    </div>
                    <button
                      onClick={handleManageBilling}
                      disabled={portalLoading}
                      className="btn-secondary text-xs"
                    >
                      {portalLoading ? (
                        <span className="flex items-center gap-2">
                          <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24" fill="none">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                          </svg>
                          Opening...
                        </span>
                      ) : (
                        "Manage Billing"
                      )}
                    </button>
                  </div>

                  {/* Usage bar */}
                  {(subscription.scan_limit ?? 0) > 0 && (
                    <div className="mt-3">
                      <div className="w-full bg-gray-700 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full transition-all ${
                            (subscription.scan_usage ?? 0) / (subscription.scan_limit ?? 1) > 0.9
                              ? "bg-red-500"
                              : (subscription.scan_usage ?? 0) / (subscription.scan_limit ?? 1) > 0.7
                                ? "bg-yellow-500"
                                : "bg-brand-500"
                          }`}
                          style={{
                            width: `${Math.min(100, ((subscription.scan_usage ?? 0) / (subscription.scan_limit ?? 1)) * 100)}%`,
                          }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Available plans */}
              {plans.length > 0 && (
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-medium text-gray-300">
                      Available Plans
                    </h3>
                    {/* Billing interval toggle */}
                    <div className="flex items-center gap-1 p-0.5 bg-gray-800 rounded-lg border border-gray-700">
                      <button
                        onClick={() => setBillingInterval("monthly")}
                        className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                          billingInterval === "monthly"
                            ? "bg-gray-700 text-gray-100"
                            : "text-gray-400 hover:text-gray-300"
                        }`}
                      >
                        Monthly
                      </button>
                      <button
                        onClick={() => setBillingInterval("annual")}
                        className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                          billingInterval === "annual"
                            ? "bg-gray-700 text-gray-100"
                            : "text-gray-400 hover:text-gray-300"
                        }`}
                      >
                        Annual
                        <span className="ml-1.5 text-green-400 font-semibold">Save 17%</span>
                      </button>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {plans.map((plan) => {
                      const isCurrent = subscription?.plan_id === plan.id;
                      const showAnnual = billingInterval === "annual" && plan.price_yearly > 0;
                      const displayPrice = showAnnual
                        ? (plan.price_yearly / 12).toFixed(2)
                        : plan.price_monthly.toFixed(2);
                      return (
                        <div
                          key={plan.id}
                          className={`p-4 rounded-lg border ${
                            isCurrent
                              ? "bg-brand-600/10 border-brand-500/30"
                              : "bg-gray-800/30 border-gray-800 hover:border-gray-700"
                          } transition-colors`}
                        >
                          <h4 className="text-base font-semibold text-gray-100">
                            {plan.name}
                          </h4>
                          <p className="text-xs text-gray-500 mt-1">
                            {plan.description}
                          </p>
                          <div className="mt-3">
                            <p className="text-2xl font-bold text-gray-100">
                              ${displayPrice}
                              <span className="text-sm font-normal text-gray-500">/mo</span>
                            </p>
                            {showAnnual && (
                              <p className="text-xs text-gray-500 mt-0.5">
                                ${plan.price_yearly}/yr — billed annually
                              </p>
                            )}
                          </div>
                          <ul className="mt-3 space-y-1">
                            <li className="text-xs text-gray-400">
                              {(plan.scan_limit ?? 0).toLocaleString()} scans/month
                            </li>
                            <li className="text-xs text-gray-400">
                              {plan.team_member_limit ?? 0} team members
                            </li>
                            {plan.features.map((feature, i) => (
                              <li key={i} className="text-xs text-gray-400">
                                {feature}
                              </li>
                            ))}
                          </ul>
                          <button
                            onClick={() => handleSubscribe(plan.id)}
                            disabled={isCurrent}
                            className={`mt-4 w-full text-xs ${
                              isCurrent ? "btn-secondary" : "btn-primary"
                            }`}
                          >
                            {isCurrent ? "Current Plan" : "Subscribe"}
                          </button>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* If no plans or subscription */}
              {plans.length === 0 && !subscription && (
                <div className="text-center py-6 text-gray-500">
                  <p className="text-sm">
                    No billing plans available. Contact support for details.
                  </p>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
