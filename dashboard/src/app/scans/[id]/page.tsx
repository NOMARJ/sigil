import VerdictBadge from "@/components/VerdictBadge";
import FindingsList from "@/components/FindingsList";
import type { Scan, Finding, Verdict, ScanPhase } from "@/lib/types";

// ---------------------------------------------------------------------------
// Mock data — single scan with findings
// ---------------------------------------------------------------------------

const mockScan: Scan = {
  id: "scan-003",
  package_name: "agent-framework",
  package_version: "2.1.0",
  source: "pip",
  verdict: "CRITICAL",
  score: 145,
  findings_count: 8,
  findings: [],
  quarantine_path: "/tmp/sigil/quarantine/scan-003",
  status: "completed",
  created_at: "2026-02-14T22:45:00Z",
  completed_at: "2026-02-14T22:47:30Z",
  approved_by: null,
  approved_at: null,
};

const mockFindings: Finding[] = [
  {
    id: "f-001",
    scan_id: "scan-003",
    phase: "install_hooks",
    severity: "CRITICAL",
    title: "Malicious postinstall script",
    description:
      "setup.py contains a postinstall command that downloads and executes a remote script from an untrusted domain.",
    file_path: "setup.py",
    line_number: 42,
    pattern_matched: "subprocess.call(['curl', ...])",
    weight: 10,
  },
  {
    id: "f-002",
    scan_id: "scan-003",
    phase: "code_patterns",
    severity: "HIGH",
    title: "Dynamic code execution with eval()",
    description:
      "Uses eval() to execute dynamically constructed code from user input, enabling arbitrary code execution.",
    file_path: "src/agent/runtime.py",
    line_number: 156,
    pattern_matched: "eval(user_input)",
    weight: 5,
  },
  {
    id: "f-003",
    scan_id: "scan-003",
    phase: "code_patterns",
    severity: "HIGH",
    title: "Pickle deserialization of untrusted data",
    description:
      "Deserializes data using pickle.loads() from a network source, which can execute arbitrary code.",
    file_path: "src/agent/cache.py",
    line_number: 89,
    pattern_matched: "pickle.loads(response.content)",
    weight: 5,
  },
  {
    id: "f-004",
    scan_id: "scan-003",
    phase: "network_exfil",
    severity: "HIGH",
    title: "Outbound HTTP to unknown domain",
    description:
      "Makes HTTP POST requests to a hard-coded external domain not associated with the package's stated purpose.",
    file_path: "src/agent/telemetry.py",
    line_number: 23,
    pattern_matched: "requests.post('https://collect.evil-analytics.com/...')",
    weight: 3,
  },
  {
    id: "f-005",
    scan_id: "scan-003",
    phase: "credentials",
    severity: "MEDIUM",
    title: "Environment variable access for API keys",
    description:
      "Reads multiple environment variables that commonly contain API keys and tokens.",
    file_path: "src/agent/config.py",
    line_number: 12,
    pattern_matched: "os.environ['OPENAI_API_KEY']",
    weight: 2,
  },
  {
    id: "f-006",
    scan_id: "scan-003",
    phase: "credentials",
    severity: "MEDIUM",
    title: "SSH key file access",
    description:
      "Attempts to read SSH private key files from the user's home directory.",
    file_path: "src/agent/auth.py",
    line_number: 67,
    pattern_matched: "open(os.path.expanduser('~/.ssh/id_rsa'))",
    weight: 2,
  },
  {
    id: "f-007",
    scan_id: "scan-003",
    phase: "obfuscation",
    severity: "HIGH",
    title: "Base64-encoded payload execution",
    description:
      "Decodes a base64-encoded string and passes it to exec(), likely to hide malicious code from static analysis.",
    file_path: "src/agent/loader.py",
    line_number: 5,
    pattern_matched: "exec(base64.b64decode(...))",
    weight: 5,
  },
  {
    id: "f-008",
    scan_id: "scan-003",
    phase: "provenance",
    severity: "LOW",
    title: "Binary file in repository",
    description:
      "Contains a compiled binary file that cannot be audited through static analysis.",
    file_path: "bin/helper.so",
    line_number: null,
    pattern_matched: "ELF binary",
    weight: 1,
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

const severityOrder: Record<Verdict, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  CLEAN: 0,
};

function riskBreakdown(findings: Finding[]): { phase: ScanPhase; count: number; maxSeverity: Verdict; totalWeight: number }[] {
  const map = new Map<
    ScanPhase,
    { count: number; maxSeverity: Verdict; totalWeight: number }
  >();

  for (const f of findings) {
    const entry = map.get(f.phase) ?? {
      count: 0,
      maxSeverity: "CLEAN" as Verdict,
      totalWeight: 0,
    };
    entry.count += 1;
    entry.totalWeight += f.weight;
    if (severityOrder[f.severity] > severityOrder[entry.maxSeverity]) {
      entry.maxSeverity = f.severity;
    }
    map.set(f.phase, entry);
  }

  return Array.from(map.entries())
    .map(([phase, data]) => ({ phase, ...data }))
    .sort((a, b) => b.totalWeight - a.totalWeight);
}

const phaseLabels: Record<ScanPhase, string> = {
  install_hooks: "Install Hooks",
  code_patterns: "Code Patterns",
  network_exfil: "Network / Exfil",
  credentials: "Credentials",
  obfuscation: "Obfuscation",
  provenance: "Provenance",
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ScanDetailPage() {
  const scan = mockScan;
  const findings = mockFindings;
  const breakdown = riskBreakdown(findings);

  return (
    <div className="space-y-8">
      {/* Back link */}
      <a
        href="/scans"
        className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 transition-colors"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
        </svg>
        Back to Scans
      </a>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
              {scan.package_name}
              <span className="text-gray-500 font-normal ml-2">
                @{scan.package_version}
              </span>
            </h1>
            <VerdictBadge verdict={scan.verdict} size="lg" />
          </div>
          <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
            <span>
              Source:{" "}
              <span className="text-gray-300 font-medium">{scan.source.toUpperCase()}</span>
            </span>
            <span>
              Score:{" "}
              <span className="font-mono text-gray-300">{scan.score}</span>
            </span>
            <span>Scanned {formatDate(scan.created_at)}</span>
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          <button className="btn-primary">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
            Approve
          </button>
          <button className="btn-danger">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
            Reject
          </button>
        </div>
      </div>

      {/* Risk Breakdown */}
      <div className="card">
        <div className="card-header">
          <h2 className="section-header">Risk Breakdown</h2>
          <p className="section-description">
            Weighted severity by scan phase.
          </p>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {breakdown.map((entry) => (
              <div
                key={entry.phase}
                className="flex items-center justify-between p-4 bg-gray-800/30 rounded-lg border border-gray-800"
              >
                <div>
                  <p className="text-sm font-medium text-gray-200">
                    {phaseLabels[entry.phase]}
                  </p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {entry.count} finding{entry.count !== 1 ? "s" : ""}
                  </p>
                </div>
                <div className="text-right">
                  <VerdictBadge verdict={entry.maxSeverity} size="sm" />
                  <p className="text-xs text-gray-500 mt-1">
                    Weight: <span className="font-mono">{entry.totalWeight}</span>
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Findings */}
      <div>
        <div className="mb-4">
          <h2 className="section-header">
            Findings{" "}
            <span className="text-gray-500 font-normal">
              ({findings.length})
            </span>
          </h2>
          <p className="section-description">
            Detailed findings grouped by scan phase.
          </p>
        </div>
        <FindingsList findings={findings} />
      </div>

      {/* Quarantine info */}
      {scan.quarantine_path && (
        <div className="card border-yellow-500/20">
          <div className="card-body flex items-start gap-3">
            <svg className="w-5 h-5 text-yellow-500 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <p className="text-sm font-medium text-yellow-400">
                Package is quarantined
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Quarantine path:{" "}
                <code className="font-mono text-gray-400">
                  {scan.quarantine_path}
                </code>
              </p>
              <p className="text-xs text-gray-500 mt-0.5">
                Approve or reject this package to release it from quarantine.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
