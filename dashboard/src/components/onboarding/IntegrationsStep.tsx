"use client";

import { useState } from "react";
import { OnboardingStepProps } from "../OnboardingStep";

interface Integration {
  id: string;
  name: string;
  description: string;
  icon: string;
  enabled: boolean;
  configured: boolean;
  popular: boolean;
}

export default function IntegrationsStep({ step, onComplete, onSkip }: OnboardingStepProps): JSX.Element {
  const [integrations, setIntegrations] = useState<Integration[]>([
    {
      id: "slack",
      name: "Slack Notifications",
      description: "Get real-time alerts for high-confidence threats in your team's Slack workspace",
      icon: "💬",
      enabled: false,
      configured: false,
      popular: true
    },
    {
      id: "github",
      name: "GitHub Webhooks",
      description: "Automatically scan packages in pull requests and prevent malicious code merges",
      icon: "🔧",
      enabled: false,
      configured: false,
      popular: true
    },
    {
      id: "vscode",
      name: "VS Code Extension",
      description: "Scan dependencies directly from your IDE with real-time threat detection",
      icon: "💻",
      enabled: false,
      configured: false,
      popular: false
    },
    {
      id: "email",
      name: "Email Notifications",
      description: "Receive daily/weekly security digests and critical threat alerts via email",
      icon: "📧",
      enabled: false,
      configured: false,
      popular: false
    }
  ]);

  const [activeSetup, setActiveSetup] = useState<string | null>(null);
  const [setupData, setSetupData] = useState<Record<string, any>>({});

  const toggleIntegration = (id: string): void => {
    setIntegrations(prev => prev.map(integration => 
      integration.id === id 
        ? { ...integration, enabled: !integration.enabled }
        : integration
    ));
  };

  const startSetup = (id: string): void => {
    setActiveSetup(id);
  };

  const completeSetup = (id: string, data: any): void => {
    setIntegrations(prev => prev.map(integration =>
      integration.id === id
        ? { ...integration, configured: true, enabled: true }
        : integration
    ));
    setSetupData(prev => ({ ...prev, [id]: data }));
    setActiveSetup(null);
  };

  const handleContinue = (): void => {
    const enabledIntegrations = integrations.filter(i => i.enabled);
    onComplete(step.id, {
      integrationsConfigured: enabledIntegrations.length,
      integrations: enabledIntegrations.map(i => ({
        id: i.id,
        name: i.name,
        configured: i.configured,
        setupData: setupData[i.id] || null
      })),
      timestamp: new Date().toISOString()
    });
  };

  const renderSetupModal = (integration: Integration): JSX.Element => {
    switch (integration.id) {
      case "slack":
        return (
          <SlackSetup 
            onComplete={(data) => completeSetup("slack", data)}
            onCancel={() => setActiveSetup(null)}
          />
        );
      case "github":
        return (
          <GitHubSetup
            onComplete={(data) => completeSetup("github", data)}
            onCancel={() => setActiveSetup(null)}
          />
        );
      case "vscode":
        return (
          <VSCodeSetup
            onComplete={(data) => completeSetup("vscode", data)}
            onCancel={() => setActiveSetup(null)}
          />
        );
      case "email":
        return (
          <EmailSetup
            onComplete={(data) => completeSetup("email", data)}
            onCancel={() => setActiveSetup(null)}
          />
        );
      default:
        return <div></div>;
    }
  };

  const enabledCount = integrations.filter(i => i.enabled).length;

  return (
    <div className="p-8">
      <div className="max-w-4xl mx-auto">
        {/* Step Description */}
        <div className="mb-8 text-center">
          <div className="w-16 h-16 bg-purple-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
          </div>
          <h3 className="text-xl font-bold text-white mb-2">Connect Your Tools</h3>
          <p className="text-gray-400 mb-4">
            Integrate Sigil Pro with your workflow for seamless threat monitoring.
          </p>
          <div className="inline-flex items-center px-3 py-1 bg-blue-900 border border-blue-700 rounded-full text-sm text-blue-300">
            Optional Step - You can configure these later
          </div>
        </div>

        {/* Integrations Grid */}
        <div className="grid md:grid-cols-2 gap-6 mb-8">
          {integrations.map((integration) => (
            <div key={integration.id} className={`border rounded-lg p-6 transition-all ${
              integration.enabled
                ? "border-purple-500 bg-purple-900 bg-opacity-20"
                : "border-gray-600 bg-gray-800"
            }`}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center">
                  <span className="text-2xl mr-3">{integration.icon}</span>
                  <div>
                    <h4 className="text-white font-semibold flex items-center">
                      {integration.name}
                      {integration.popular && (
                        <span className="ml-2 px-2 py-0.5 bg-green-600 text-white text-xs rounded-full">
                          Popular
                        </span>
                      )}
                    </h4>
                  </div>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={integration.enabled}
                    onChange={() => toggleIntegration(integration.id)}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                </label>
              </div>

              <p className="text-gray-400 text-sm mb-4">{integration.description}</p>

              {integration.enabled && (
                <div className="pt-4 border-t border-gray-700">
                  {integration.configured ? (
                    <div className="flex items-center text-green-400 text-sm">
                      <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                      </svg>
                      Configured
                    </div>
                  ) : (
                    <button
                      onClick={() => startSetup(integration.id)}
                      className="w-full py-2 bg-purple-600 hover:bg-purple-700 text-white rounded font-medium text-sm transition-colors"
                    >
                      Configure {integration.name}
                    </button>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Continue/Skip Buttons */}
        <div className="text-center">
          <div className="mb-4">
            <span className="text-gray-400">
              {enabledCount} integration{enabledCount !== 1 ? 's' : ''} selected
            </span>
          </div>
          <div className="flex justify-center space-x-4">
            <button
              onClick={onSkip}
              className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg font-medium transition-colors"
            >
              Skip for Now
            </button>
            <button
              onClick={handleContinue}
              className="px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium transition-colors"
            >
              Continue
            </button>
          </div>
        </div>

        {/* Setup Modal */}
        {activeSetup && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-600 rounded-lg max-w-lg w-full mx-4">
              {renderSetupModal(integrations.find(i => i.id === activeSetup)!)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// Setup Components
function SlackSetup({ onComplete, onCancel }: { onComplete: (data: any) => void; onCancel: () => void }): JSX.Element {
  const [webhookUrl, setWebhookUrl] = useState("");
  const [channel, setChannel] = useState("#security");

  return (
    <div className="p-6">
      <h4 className="text-lg font-semibold text-white mb-4">Configure Slack Notifications</h4>
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Webhook URL
          </label>
          <input
            type="url"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/..."
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:ring-2 focus:ring-purple-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Channel
          </label>
          <input
            type="text"
            value={channel}
            onChange={(e) => setChannel(e.target.value)}
            placeholder="#security"
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:ring-2 focus:ring-purple-500"
          />
        </div>
      </div>
      <div className="flex justify-end space-x-3 mt-6">
        <button
          onClick={onCancel}
          className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={() => onComplete({ webhookUrl, channel })}
          disabled={!webhookUrl}
          className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded disabled:opacity-50"
        >
          Save
        </button>
      </div>
    </div>
  );
}

function GitHubSetup({ onComplete, onCancel }: { onComplete: (data: any) => void; onCancel: () => void }): JSX.Element {
  const [repoUrl, setRepoUrl] = useState("");

  return (
    <div className="p-6">
      <h4 className="text-lg font-semibold text-white mb-4">Configure GitHub Integration</h4>
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Repository URL
          </label>
          <input
            type="url"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="https://github.com/user/repo"
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:ring-2 focus:ring-purple-500"
          />
        </div>
        <p className="text-sm text-gray-400">
          Add our webhook URL to your repository settings for automatic PR scanning.
        </p>
      </div>
      <div className="flex justify-end space-x-3 mt-6">
        <button
          onClick={onCancel}
          className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={() => onComplete({ repoUrl })}
          disabled={!repoUrl}
          className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded disabled:opacity-50"
        >
          Save
        </button>
      </div>
    </div>
  );
}

function VSCodeSetup({ onComplete, onCancel }: { onComplete: (data: any) => void; onCancel: () => void }): JSX.Element {
  return (
    <div className="p-6">
      <h4 className="text-lg font-semibold text-white mb-4">Install VS Code Extension</h4>
      <div className="space-y-4">
        <p className="text-gray-300">
          Install the Sigil Pro extension from the VS Code marketplace.
        </p>
        <div className="bg-gray-900 border border-gray-600 rounded p-3">
          <code className="text-green-400 font-mono text-sm">
            ext install sigil.sigil-pro
          </code>
        </div>
        <p className="text-sm text-gray-400">
          The extension will use your API key for authentication.
        </p>
      </div>
      <div className="flex justify-end space-x-3 mt-6">
        <button
          onClick={onCancel}
          className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={() => onComplete({ installed: true })}
          className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded"
        >
          Mark as Installed
        </button>
      </div>
    </div>
  );
}

function EmailSetup({ onComplete, onCancel }: { onComplete: (data: any) => void; onCancel: () => void }): JSX.Element {
  const [frequency, setFrequency] = useState("weekly");
  const [criticalAlerts, setCriticalAlerts] = useState(true);

  return (
    <div className="p-6">
      <h4 className="text-lg font-semibold text-white mb-4">Configure Email Notifications</h4>
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Digest Frequency
          </label>
          <select
            value={frequency}
            onChange={(e) => setFrequency(e.target.value)}
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:ring-2 focus:ring-purple-500"
          >
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
          </select>
        </div>
        <div>
          <label className="flex items-center">
            <input
              type="checkbox"
              checked={criticalAlerts}
              onChange={(e) => setCriticalAlerts(e.target.checked)}
              className="w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 rounded focus:ring-purple-500"
            />
            <span className="ml-2 text-gray-300">
              Immediate alerts for critical threats
            </span>
          </label>
        </div>
      </div>
      <div className="flex justify-end space-x-3 mt-6">
        <button
          onClick={onCancel}
          className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={() => onComplete({ frequency, criticalAlerts })}
          className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded"
        >
          Save
        </button>
      </div>
    </div>
  );
}