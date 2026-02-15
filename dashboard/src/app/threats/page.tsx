"use client";

import { useState } from "react";
import VerdictBadge from "@/components/VerdictBadge";
import type { ThreatEntry, Verdict } from "@/lib/types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const mockThreats: ThreatEntry[] = [
  {
    id: "threat-001",
    package_name: "event-stream",
    source: "npm",
    threat_type: "Supply Chain Attack",
    description:
      "Malicious code injected via flatmap-stream dependency. Targeted cryptocurrency wallets by stealing private keys through a hidden payload activated only for specific Bitcoin wallet applications.",
    reporter: "npm Security",
    reported_at: "2026-01-15T12:00:00Z",
    severity: "CRITICAL",
    indicators: [
      "flatmap-stream dependency",
      "Obfuscated AES decryption",
      "Targeted copay wallet",
    ],
    references: [
      "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
    ],
  },
  {
    id: "threat-002",
    package_name: "colors",
    source: "npm",
    threat_type: "Maintainer Sabotage",
    description:
      "Maintainer introduced infinite loop in v1.4.1 as protest, causing denial-of-service in downstream projects. Packages depending on colors would hang indefinitely during startup.",
    reporter: "Community",
    reported_at: "2026-01-10T08:30:00Z",
    severity: "HIGH",
    indicators: [
      "Infinite loop in index.js",
      "LIBERTY LIBERTY LIBERTY console output",
    ],
    references: ["https://github.com/Marak/colors.js/issues/289"],
  },
  {
    id: "threat-003",
    package_name: "ctx",
    source: "pip",
    threat_type: "Account Takeover",
    description:
      "PyPI package hijacked via expired maintainer email domain. Attacker uploaded new version containing credential-stealing code that exfiltrated environment variables to an external server.",
    reporter: "PyPI Security",
    reported_at: "2026-02-01T14:20:00Z",
    severity: "CRITICAL",
    indicators: [
      "os.environ exfiltration",
      "HTTP POST to external domain",
      "New maintainer email domain",
    ],
    references: ["https://python-security.readthedocs.io/"],
  },
  {
    id: "threat-004",
    package_name: "ua-parser-js",
    source: "npm",
    threat_type: "Supply Chain Attack",
    description:
      "Hijacked npm package contained cryptomining and credential-stealing malware. Affected versions 0.7.29, 0.8.0, and 1.0.0 installed platform-specific binaries on victim machines.",
    reporter: "npm Security",
    reported_at: "2025-12-20T09:00:00Z",
    severity: "CRITICAL",
    indicators: [
      "Preinstall script",
      "Platform-specific binary download",
      "Cryptominer payload",
    ],
    references: ["https://github.com/nicerequest/advisories/GHSA-pjwm-rvh2-c87w"],
  },
  {
    id: "threat-005",
    package_name: "agent-toolkit-helper",
    source: "pip",
    threat_type: "Typosquatting",
    description:
      "Typosquatting package mimicking popular agent-toolkit library. Contains obfuscated code that exfiltrates SSH keys and AWS credentials upon installation via setup.py postinstall hook.",
    reporter: "Sigil Scanner",
    reported_at: "2026-02-12T16:45:00Z",
    severity: "CRITICAL",
    indicators: [
      "setup.py postinstall",
      "SSH key read",
      "AWS credential exfil",
      "base64 obfuscation",
    ],
    references: [],
  },
  {
    id: "threat-006",
    package_name: "lodash-utils",
    source: "npm",
    threat_type: "Typosquatting",
    description:
      "Fake package with similar name to lodash. Contains hidden eval() call that downloads and executes remote payload on first import.",
    reporter: "Community",
    reported_at: "2026-02-08T11:30:00Z",
    severity: "HIGH",
    indicators: [
      "eval() with network fetch",
      "Obfuscated URL string",
      "Similar name to popular package",
    ],
    references: [],
  },
  {
    id: "threat-007",
    package_name: "debug-tools-pro",
    source: "npm",
    threat_type: "Data Exfiltration",
    description:
      "Package advertised as debugging utility but secretly collects and transmits project source code and environment variables to an external endpoint.",
    reporter: "Sigil Scanner",
    reported_at: "2026-02-05T20:15:00Z",
    severity: "MEDIUM",
    indicators: [
      "process.env access",
      "File system traversal",
      "Outbound HTTP with project data",
    ],
    references: [],
  },
];

const severityOptions: (Verdict | "ALL")[] = [
  "ALL",
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
];

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ThreatsPage() {
  const [severityFilter, setSeverityFilter] = useState<Verdict | "ALL">("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const filtered = mockThreats.filter((t) => {
    if (severityFilter !== "ALL" && t.severity !== severityFilter) return false;
    if (
      searchQuery &&
      !t.package_name.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !t.description.toLowerCase().includes(searchQuery.toLowerCase())
    )
      return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
          Threat Intelligence
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Known malicious packages and community-reported threats.
        </p>
      </div>

      {/* Search + Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1">
          <input
            type="text"
            placeholder="Search threats by package name or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input"
          />
        </div>
        <div className="flex items-center gap-2">
          {severityOptions.map((v) => (
            <button
              key={v}
              onClick={() => setSeverityFilter(v)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                severityFilter === v
                  ? "bg-brand-600/20 text-brand-400 border border-brand-500/30"
                  : "bg-gray-800/50 text-gray-400 border border-gray-800 hover:border-gray-700 hover:text-gray-300"
              }`}
            >
              {v}
            </button>
          ))}
        </div>
      </div>

      {/* Threat cards */}
      <div className="space-y-4">
        {filtered.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            <p className="text-sm">No threats match your filters.</p>
          </div>
        )}

        {filtered.map((threat) => (
          <div
            key={threat.id}
            className="card hover:border-gray-700 transition-colors"
          >
            <div className="card-body">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-base font-semibold text-gray-100">
                      {threat.package_name}
                    </h3>
                    <VerdictBadge verdict={threat.severity} size="sm" />
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700">
                      {threat.source}
                    </span>
                  </div>

                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20 mb-2">
                    {threat.threat_type}
                  </span>

                  <p className="text-sm text-gray-400 mt-2">
                    {threat.description}
                  </p>

                  {/* Indicators */}
                  {threat.indicators.length > 0 && (
                    <div className="mt-3">
                      <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5">
                        Indicators
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {threat.indicators.map((indicator, i) => (
                          <span
                            key={i}
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-gray-800/50 text-gray-400 border border-gray-700/50"
                          >
                            {indicator}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div className="text-right shrink-0 text-xs text-gray-500">
                  <p>Reported by {threat.reporter}</p>
                  <p className="mt-0.5">
                    {new Date(threat.reported_at).toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                      year: "numeric",
                    })}
                  </p>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
