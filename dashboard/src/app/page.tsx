import StatsCard from "@/components/StatsCard";
import ScanTable from "@/components/ScanTable";
import type { Scan } from "@/lib/types";

// ---------------------------------------------------------------------------
// Mock data for demonstration
// ---------------------------------------------------------------------------

const mockStats = {
  total_scans: 1_284,
  threats_blocked: 23,
  packages_approved: 1_147,
  critical_findings: 7,
  scans_today: 42,
  trend_scans: 12,
  trend_threats: -8,
};

const mockRecentScans: Scan[] = [
  {
    id: "scan-001",
    package_name: "langchain-agent",
    package_version: "0.4.2",
    source: "pip",
    verdict: "CLEAN",
    score: 0,
    findings_count: 0,
    findings: [],
    quarantine_path: null,
    status: "completed",
    created_at: "2026-02-15T10:23:00Z",
    completed_at: "2026-02-15T10:23:45Z",
    approved_by: null,
    approved_at: null,
  },
  {
    id: "scan-002",
    package_name: "openai-tools",
    package_version: "1.2.0",
    source: "npm",
    verdict: "HIGH",
    score: 78,
    findings_count: 5,
    findings: [],
    quarantine_path: "/tmp/sigil/quarantine/scan-002",
    status: "completed",
    created_at: "2026-02-15T09:15:00Z",
    completed_at: "2026-02-15T09:16:12Z",
    approved_by: null,
    approved_at: null,
  },
  {
    id: "scan-003",
    package_name: "agent-framework",
    package_version: "2.1.0",
    source: "pip",
    verdict: "CRITICAL",
    score: 145,
    findings_count: 12,
    findings: [],
    quarantine_path: "/tmp/sigil/quarantine/scan-003",
    status: "completed",
    created_at: "2026-02-14T22:45:00Z",
    completed_at: "2026-02-14T22:47:30Z",
    approved_by: null,
    approved_at: null,
  },
  {
    id: "scan-004",
    package_name: "mcp-server-utils",
    package_version: "0.9.1",
    source: "npm",
    verdict: "LOW",
    score: 8,
    findings_count: 2,
    findings: [],
    quarantine_path: null,
    status: "completed",
    created_at: "2026-02-14T18:30:00Z",
    completed_at: "2026-02-14T18:30:22Z",
    approved_by: "user-001",
    approved_at: "2026-02-14T18:35:00Z",
  },
  {
    id: "scan-005",
    package_name: "llm-sandbox",
    package_version: "3.0.0-beta",
    source: "git",
    verdict: "MEDIUM",
    score: 34,
    findings_count: 4,
    findings: [],
    quarantine_path: "/tmp/sigil/quarantine/scan-005",
    status: "completed",
    created_at: "2026-02-14T15:12:00Z",
    completed_at: "2026-02-14T15:14:55Z",
    approved_by: null,
    approved_at: null,
  },
];

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function DashboardPage() {
  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
          Dashboard
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Security overview for your AI agent supply chain.
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Total Scans"
          value={mockStats.total_scans.toLocaleString()}
          subtitle="all time"
          trend={mockStats.trend_scans}
          accentColor="brand"
          icon={
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
            </svg>
          }
        />
        <StatsCard
          title="Threats Blocked"
          value={mockStats.threats_blocked}
          subtitle="this month"
          trend={mockStats.trend_threats}
          accentColor="red"
          icon={
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          }
        />
        <StatsCard
          title="Packages Approved"
          value={mockStats.packages_approved.toLocaleString()}
          subtitle="all time"
          accentColor="green"
          icon={
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          }
        />
        <StatsCard
          title="Critical Findings"
          value={mockStats.critical_findings}
          subtitle="pending review"
          accentColor="orange"
          icon={
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          }
        />
      </div>

      {/* Recent Scans */}
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <div>
            <h2 className="section-header">Recent Scans</h2>
            <p className="section-description">
              Latest package and repository scans.
            </p>
          </div>
          <a
            href="/scans"
            className="btn-ghost text-xs"
          >
            View all
          </a>
        </div>
        <div className="card-body">
          <ScanTable scans={mockRecentScans} />
        </div>
      </div>
    </div>
  );
}
