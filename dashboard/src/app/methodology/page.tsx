import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Scanning Methodology — Sigil",
  description:
    "How Sigil performs automated security scanning. Detection criteria, scan phases, and limitations.",
};

export default function MethodologyPage() {
  return (
    <div className="max-w-3xl mx-auto py-12 px-4 space-y-8 text-gray-300 text-sm leading-relaxed">
      <div>
        <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
          Scanning Methodology
        </h1>
        <p className="text-xs text-gray-500 mt-1">
          How Sigil scans work, what they detect, and their limitations.
        </p>
      </div>

      {/* Static Analysis Only */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          Static Analysis Only
        </h2>
        <p>
          Sigil uses automated static pattern analysis. No code is executed at
          any point during scanning. There is no runtime execution, no manual
          audit, and no penetration testing. Scans examine source code,
          configuration files, and metadata at rest.
        </p>
      </section>

      {/* Pattern / Signature Detection */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          Pattern / Signature Detection
        </h2>
        <p>
          Scans match code against defined detection rules targeting known
          malicious patterns. These rules are developed from research into
          supply chain attacks, malware, and suspicious coding practices
          observed in public package registries.
        </p>
      </section>

      {/* Point-in-Time */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          Point-in-Time Analysis
        </h2>
        <p>
          Each scan represents analysis of a specific version at a specific
          time. Results do not reflect changes made after scanning. A LOW RISK
          verdict on version 1.0.0 says nothing about version 1.0.1 or any
          subsequent release.
        </p>
      </section>

      {/* No Continuous Monitoring */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          No Continuous Monitoring
        </h2>
        <p>
          Sigil does not watch packages for changes in real time. Rescans occur
          on a defined schedule or on-demand. Between scans, packages may be
          updated by their authors without Sigil&apos;s knowledge.
        </p>
      </section>

      {/* False Positive / Negative */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          False Positive &amp; False Negative Risk
        </h2>
        <p>
          Automated analysis may flag legitimate patterns (false positives) or
          miss novel attack techniques (false negatives). No scanning tool
          achieves 100% accuracy. Sigil&apos;s detection rules are continuously
          updated, but there will always be patterns that evade detection and
          benign patterns that trigger alerts.
        </p>
      </section>

      {/* Scan Phases */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-gray-100">
          Detection Criteria — Scan Phases
        </h2>
        <p>
          Each scan runs through the following phases. Each phase has a severity
          weight that contributes to the final risk score.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="text-left py-2 pr-4 font-medium">Phase</th>
                <th className="text-left py-2 pr-4 font-medium">Weight</th>
                <th className="text-left py-2 font-medium">What It Detects</th>
              </tr>
            </thead>
            <tbody className="text-gray-400">
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Install Hooks
                </td>
                <td className="py-2 pr-4 font-mono">10&times;</td>
                <td className="py-2">
                  setup.py cmdclass overrides, npm preinstall/postinstall
                  scripts, Makefile install targets with network/exec calls
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Code Patterns
                </td>
                <td className="py-2 pr-4 font-mono">5&times;</td>
                <td className="py-2">
                  eval(), exec(), pickle.loads, child_process, Function(),
                  vm.runInNewContext, auto_approve, skip_confirmation
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Network / Exfil
                </td>
                <td className="py-2 pr-4 font-mono">3&times;</td>
                <td className="py-2">
                  Outbound HTTP requests, webhooks (Discord, Telegram),
                  websockets, ngrok tunnels, DNS exfiltration patterns
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Credentials
                </td>
                <td className="py-2 pr-4 font-mono">2&times;</td>
                <td className="py-2">
                  Environment variable access (API keys, tokens), SSH key
                  paths, credential file access (.aws/credentials,
                  .kube/config)
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Obfuscation
                </td>
                <td className="py-2 pr-4 font-mono">5&times;</td>
                <td className="py-2">
                  base64 decoding, String.fromCharCode, hex-encoded strings,
                  dynamic code construction
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Provenance
                </td>
                <td className="py-2 pr-4 font-mono">1-3&times;</td>
                <td className="py-2">
                  Git history depth, author count, binary executables, hidden
                  files, large files, filesystem manipulation
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Prompt Injection
                </td>
                <td className="py-2 pr-4 font-mono">10&times;</td>
                <td className="py-2">
                  Embedded instructions targeting AI agents, system prompt
                  overrides, tool-call injection patterns
                </td>
              </tr>
              <tr>
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Skill Security
                </td>
                <td className="py-2 pr-4 font-mono">5&times;</td>
                <td className="py-2">
                  MCP server permission escalation, undeclared tool
                  capabilities, auto-approve patterns
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Verdict Scale */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-gray-100">
          Risk Classification Scale
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="text-left py-2 pr-4 font-medium">Score</th>
                <th className="text-left py-2 pr-4 font-medium">Verdict</th>
                <th className="text-left py-2 font-medium">Meaning</th>
              </tr>
            </thead>
            <tbody className="text-gray-400">
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 font-mono">0 &ndash; 9</td>
                <td className="py-2 pr-4 text-green-400 font-medium">
                  LOW RISK
                </td>
                <td className="py-2">
                  No known malicious patterns detected at time of scanning
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 font-mono">10 &ndash; 24</td>
                <td className="py-2 pr-4 text-yellow-400 font-medium">
                  MEDIUM RISK
                </td>
                <td className="py-2">
                  Patterns consistent with suspicious behaviour detected;
                  manual review recommended
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 font-mono">25 &ndash; 49</td>
                <td className="py-2 pr-4 text-orange-400 font-medium">
                  HIGH RISK
                </td>
                <td className="py-2">
                  Multiple risk indicators detected; do not install without
                  thorough review
                </td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono">50+</td>
                <td className="py-2 pr-4 text-red-400 font-medium">
                  CRITICAL RISK
                </td>
                <td className="py-2">
                  Automated analysis identified strong risk indicators across
                  multiple phases
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-gray-500 text-xs">
          Risk levels indicate detection results only and are not safety
          ratings or certifications.
        </p>
      </section>

      {/* External Scanners */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          External Scanner Integration
        </h2>
        <p>
          When available, Sigil integrates results from third-party tools
          including Semgrep, Bandit (Python), TruffleHog (secrets detection),
          npm audit, and Safety (Python dependency vulnerabilities). These tools
          have their own detection methodologies and their findings contribute
          to the overall risk score.
        </p>
      </section>

      {/* Dispute Process */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          Dispute Process
        </h2>
        <p>
          Package authors who believe results are incorrect may request review
          by contacting{" "}
          <a
            href="mailto:security@nomark.ai"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            security@nomark.ai
          </a>{" "}
          or using the &ldquo;Request a review&rdquo; link on the scan report
          page. We target a 48-hour response time for dispute reviews.
        </p>
      </section>

      <hr className="border-gray-800" />

      <div className="space-y-2 text-xs text-gray-600">
        <p>
          For more information, see our{" "}
          <a
            href="/terms"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            Terms of Service
          </a>{" "}
          and{" "}
          <a
            href="/privacy"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            Privacy Policy
          </a>
          .
        </p>
      </div>
    </div>
  );
}
