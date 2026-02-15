import type { Finding, ScanPhase } from "@/lib/types";
import VerdictBadge from "./VerdictBadge";

interface FindingsListProps {
  findings: Finding[];
}

const phaseLabels: Record<ScanPhase, string> = {
  install_hooks: "Install Hooks",
  code_patterns: "Code Patterns",
  network_exfil: "Network / Exfiltration",
  credentials: "Credentials",
  obfuscation: "Obfuscation",
  provenance: "Provenance",
};

const phaseDescriptions: Record<ScanPhase, string> = {
  install_hooks: "setup.py, npm postinstall, and other install-time hooks",
  code_patterns: "eval, exec, pickle, child_process, and other dangerous patterns",
  network_exfil: "Outbound HTTP, webhooks, sockets, and data exfiltration",
  credentials: "ENV vars, API keys, SSH keys, and credential access",
  obfuscation: "base64, charCode, hex encoding, and code obfuscation",
  provenance: "Git history anomalies, binaries, and hidden files",
};

const phaseOrder: ScanPhase[] = [
  "install_hooks",
  "code_patterns",
  "network_exfil",
  "credentials",
  "obfuscation",
  "provenance",
];

export default function FindingsList({ findings }: FindingsListProps) {
  const grouped = findings.reduce(
    (acc, finding) => {
      if (!acc[finding.phase]) acc[finding.phase] = [];
      acc[finding.phase].push(finding);
      return acc;
    },
    {} as Record<ScanPhase, Finding[]>,
  );

  if (findings.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        <svg className="w-12 h-12 mx-auto mb-3 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <p className="text-sm font-medium text-green-500">No findings detected</p>
        <p className="text-xs text-gray-600 mt-1">This package passed all scan phases.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {phaseOrder.map((phase) => {
        const phaseFindings = grouped[phase];
        if (!phaseFindings || phaseFindings.length === 0) return null;

        return (
          <div key={phase} className="border border-gray-800 rounded-xl overflow-hidden">
            {/* Phase header */}
            <div className="bg-gray-900/50 px-5 py-3 border-b border-gray-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-gray-200">
                  {phaseLabels[phase]}
                </h3>
                <p className="text-xs text-gray-500 mt-0.5">
                  {phaseDescriptions[phase]}
                </p>
              </div>
              <span className="text-xs font-medium text-gray-400 bg-gray-800 px-2 py-1 rounded-full">
                {phaseFindings.length} finding{phaseFindings.length !== 1 ? "s" : ""}
              </span>
            </div>

            {/* Findings */}
            <div className="divide-y divide-gray-800/50">
              {phaseFindings.map((finding) => (
                <div key={finding.id} className="px-5 py-4 hover:bg-gray-800/20 transition-colors">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <VerdictBadge verdict={finding.severity} size="sm" />
                        <span className="text-sm font-medium text-gray-100">
                          {finding.title}
                        </span>
                      </div>
                      <p className="text-xs text-gray-400 mt-1">
                        {finding.description}
                      </p>
                      {finding.file_path && (
                        <div className="mt-2 flex items-center gap-2 text-xs">
                          <span className="font-mono text-gray-500 bg-gray-800/50 px-2 py-0.5 rounded">
                            {finding.file_path}
                            {finding.line_number !== null && `:${finding.line_number}`}
                          </span>
                          {finding.pattern_matched && (
                            <span className="font-mono text-yellow-500/70 bg-yellow-500/5 px-2 py-0.5 rounded border border-yellow-500/10">
                              {finding.pattern_matched}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                    <div className="text-right shrink-0">
                      <span className="text-xs text-gray-500">
                        Weight: <span className="font-mono text-gray-400">{finding.weight}x</span>
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
