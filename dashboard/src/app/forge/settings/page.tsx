"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/lib/auth";
import PlanGate from "@/components/PlanGate";
import type { ForgeSettings } from "@/lib/types";

// Mock initial settings - replace with API call
const mockInitialSettings: ForgeSettings = {
  notifications: {
    security_alerts: true,
    version_updates: false,
    weekly_digest: true,
  },
  privacy: {
    public_profile: false,
    share_anonymized_data: true,
  },
  tracking: {
    auto_track_dependencies: false,
    scan_frequency: "weekly",
  },
};

interface SettingSectionProps {
  title: string;
  description: string;
  children: React.ReactNode;
}

function SettingSection({ title, description, children }: SettingSectionProps) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
      <div className="mb-6">
        <h3 className="text-lg font-semibold text-white mb-2">{title}</h3>
        <p className="text-gray-400 text-sm">{description}</p>
      </div>
      <div className="space-y-4">
        {children}
      </div>
    </div>
  );
}

interface ToggleSettingProps {
  label: string;
  description: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}

function ToggleSetting({ label, description, checked, onChange, disabled = false }: ToggleSettingProps) {
  return (
    <div className="flex items-center justify-between py-2">
      <div className="flex-1">
        <div className="text-sm font-medium text-white">{label}</div>
        <div className="text-xs text-gray-400">{description}</div>
      </div>
      <button
        onClick={() => !disabled && onChange(!checked)}
        disabled={disabled}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-brand-500 focus:ring-offset-2 focus:ring-offset-gray-900 ${
          checked 
            ? 'bg-brand-600' 
            : 'bg-gray-700'
        } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
            checked ? 'translate-x-6' : 'translate-x-1'
          }`}
        />
      </button>
    </div>
  );
}

interface SelectSettingProps {
  label: string;
  description: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  disabled?: boolean;
}

function SelectSetting({ label, description, value, onChange, options, disabled = false }: SelectSettingProps) {
  return (
    <div className="py-2">
      <div className="flex items-center justify-between mb-2">
        <div className="flex-1">
          <div className="text-sm font-medium text-white">{label}</div>
          <div className="text-xs text-gray-400">{description}</div>
        </div>
      </div>
      <select
        value={value}
        onChange={(e) => !disabled && onChange(e.target.value)}
        disabled={disabled}
        className={`w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white text-sm focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent ${
          disabled ? 'opacity-50 cursor-not-allowed' : ''
        }`}
      >
        {options.map(option => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export default function ForgeSettingsPage() {
  const { user } = useAuth();
  const [settings, setSettings] = useState<ForgeSettings>(mockInitialSettings);
  const [loading, setLoading] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleNotificationChange = (key: keyof ForgeSettings['notifications'], value: boolean) => {
    setSettings(prev => ({
      ...prev,
      notifications: {
        ...prev.notifications,
        [key]: value
      }
    }));
  };

  const handlePrivacyChange = (key: keyof ForgeSettings['privacy'], value: boolean) => {
    setSettings(prev => ({
      ...prev,
      privacy: {
        ...prev.privacy,
        [key]: value
      }
    }));
  };

  const handleTrackingChange = (key: keyof ForgeSettings['tracking'], value: any) => {
    setSettings(prev => ({
      ...prev,
      tracking: {
        ...prev.tracking,
        [key]: value
      }
    }));
  };

  const handleSaveSettings = async () => {
    setLoading(true);
    // Simulate API call to save settings
    setTimeout(() => {
      setLoading(false);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    }, 500);
  };

  const scanFrequencyOptions = [
    { value: "manual", label: "Manual only" },
    { value: "daily", label: "Daily" },
    { value: "weekly", label: "Weekly" },
  ];

  if (!user?.plan) {
    return <div>Loading...</div>;
  }

  return (
    <PlanGate requiredPlan="pro" currentPlan={user.plan}>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Forge Settings</h1>
            <p className="text-gray-400 mt-1">
              Configure your preferences for Forge tool tracking and monitoring
            </p>
          </div>
          <button
            onClick={handleSaveSettings}
            disabled={loading}
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-md font-medium transition-colors ${
              saved 
                ? 'bg-green-600 text-white' 
                : 'bg-brand-600 hover:bg-brand-700 text-white'
            } ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                Saving...
              </>
            ) : saved ? (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                Saved!
              </>
            ) : (
              'Save Settings'
            )}
          </button>
        </div>

        <div className="grid gap-6">
          {/* Notifications */}
          <SettingSection
            title="Notifications"
            description="Configure when and how you receive alerts about your tracked tools"
          >
            <ToggleSetting
              label="Security Alerts"
              description="Get notified immediately when security vulnerabilities are found"
              checked={settings.notifications.security_alerts}
              onChange={(value) => handleNotificationChange('security_alerts', value)}
            />
            
            <ToggleSetting
              label="Version Updates"
              description="Get notified when new versions are available for tracked tools"
              checked={settings.notifications.version_updates}
              onChange={(value) => handleNotificationChange('version_updates', value)}
            />
            
            <ToggleSetting
              label="Weekly Digest"
              description="Receive a weekly summary of security status and updates"
              checked={settings.notifications.weekly_digest}
              onChange={(value) => handleNotificationChange('weekly_digest', value)}
            />
          </SettingSection>

          {/* Privacy */}
          <SettingSection
            title="Privacy & Data"
            description="Control how your data is used and shared"
          >
            <ToggleSetting
              label="Public Profile"
              description="Make your tool tracking profile visible to other Forge users"
              checked={settings.privacy.public_profile}
              onChange={(value) => handlePrivacyChange('public_profile', value)}
            />
            
            <ToggleSetting
              label="Share Anonymized Data"
              description="Help improve Sigil by sharing anonymized usage and threat data"
              checked={settings.privacy.share_anonymized_data}
              onChange={(value) => handlePrivacyChange('share_anonymized_data', value)}
            />
          </SettingSection>

          {/* Tracking */}
          <SettingSection
            title="Tool Tracking"
            description="Configure how tools are tracked and monitored"
          >
            <ToggleSetting
              label="Auto-track Dependencies"
              description="Automatically track dependencies when scanning repositories"
              checked={settings.tracking.auto_track_dependencies}
              onChange={(value) => handleTrackingChange('auto_track_dependencies', value)}
              disabled={user.plan === "pro"} // Example: feature for Team+ plans
            />
            {user.plan === "pro" && (
              <div className="text-xs text-amber-400 mb-2">
                Available in Team plans and above
              </div>
            )}
            
            <SelectSetting
              label="Scan Frequency"
              description="How often to automatically scan tracked tools for security issues"
              value={settings.tracking.scan_frequency}
              onChange={(value) => handleTrackingChange('scan_frequency', value as any)}
              options={scanFrequencyOptions}
            />
          </SettingSection>

          {/* Danger Zone */}
          <SettingSection
            title="Danger Zone"
            description="Irreversible actions that affect your Forge data"
          >
            <div className="border border-red-800 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm font-medium text-red-400 mb-1">Clear All Tracked Tools</div>
                  <div className="text-xs text-gray-400">
                    This will remove all tools from your tracking list. This action cannot be undone.
                  </div>
                </div>
                <button className="px-3 py-1.5 bg-red-600/10 border border-red-600/20 text-red-400 text-sm font-medium rounded hover:bg-red-600/20 transition-colors">
                  Clear All
                </button>
              </div>
            </div>
          </SettingSection>
        </div>

        {/* Plan Info */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-white mb-2">Current Plan</h3>
              <p className="text-gray-400 text-sm">
                You&apos;re on the <span className="capitalize text-brand-400 font-medium">{user.plan}</span> plan
              </p>
            </div>
            {user.plan === "pro" && (
              <button
                onClick={() => window.open('/settings#billing', '_self')}
                className="px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white font-medium rounded-md transition-colors"
              >
                Upgrade to Team
              </button>
            )}
          </div>
        </div>
      </div>
    </PlanGate>
  );
}