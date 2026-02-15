"use client";

import { useState } from "react";
import type { Verdict, AlertChannel } from "@/lib/types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const verdictLevels: Verdict[] = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

const mockAlertChannels: AlertChannel[] = [
  {
    id: "alert-001",
    type: "slack",
    target: "#security-alerts",
    enabled: true,
    min_severity: "HIGH",
  },
  {
    id: "alert-002",
    type: "email",
    target: "security-team@company.com",
    enabled: true,
    min_severity: "CRITICAL",
  },
  {
    id: "alert-003",
    type: "webhook",
    target: "https://hooks.company.com/sigil",
    enabled: false,
    min_severity: "MEDIUM",
  },
];

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
  const [allowlist, setAllowlist] = useState("langchain\nopenai\nanthropic");
  const [blocklist, setBlocklist] = useState("event-stream\ncolors@1.4.1");
  const [requireApproval, setRequireApproval] = useState<Verdict[]>(["HIGH", "CRITICAL"]);

  // Alert channels state
  const [channels, setChannels] = useState<AlertChannel[]>(mockAlertChannels);
  const [newChannelType, setNewChannelType] = useState<"slack" | "email" | "webhook">("slack");
  const [newChannelTarget, setNewChannelTarget] = useState("");
  const [newChannelSeverity, setNewChannelSeverity] = useState<Verdict>("HIGH");

  const toggleApproval = (verdict: Verdict) => {
    setRequireApproval((prev) =>
      prev.includes(verdict)
        ? prev.filter((v) => v !== verdict)
        : [...prev, verdict],
    );
  };

  const toggleChannel = (id: string) => {
    setChannels((prev) =>
      prev.map((c) => (c.id === id ? { ...c, enabled: !c.enabled } : c)),
    );
  };

  const removeChannel = (id: string) => {
    setChannels((prev) => prev.filter((c) => c.id !== id));
  };

  const addChannel = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newChannelTarget.trim()) return;
    const newChannel: AlertChannel = {
      id: `alert-${Date.now()}`,
      type: newChannelType,
      target: newChannelTarget.trim(),
      enabled: true,
      min_severity: newChannelSeverity,
    };
    setChannels((prev) => [...prev, newChannel]);
    setNewChannelTarget("");
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
          Settings
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Configure scan policies, allowlists, and alert channels.
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
            <button className="btn-primary">Save Policies</button>
          </div>
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
          {/* Existing channels */}
          {channels.length > 0 && (
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
                    setNewChannelType(
                      e.target.value as "slack" | "email" | "webhook",
                    )
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
              <button type="submit" className="btn-primary whitespace-nowrap">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                </svg>
                Add
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
