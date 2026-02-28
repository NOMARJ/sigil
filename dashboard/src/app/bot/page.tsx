import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Sigil Bot — Automated AI Package Security Scanner",
  description:
    "Sigil Bot monitors PyPI, npm, ClawHub, and GitHub for security threats in AI agent packages. Learn how automated scanning works and how to dispute results.",
  openGraph: {
    title: "Sigil Bot — Automated AI Package Security Scanner",
    description:
      "Sigil Bot monitors PyPI, npm, ClawHub, and GitHub for security threats in AI agent packages.",
    url: "https://sigilsec.ai/bot",
    type: "website",
  },
};

export default function BotPage() {
  return (
    <div className="max-w-3xl mx-auto py-12 px-4 space-y-10 text-gray-300 text-sm leading-relaxed">
      {/* Hero */}
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-brand-600 text-white font-bold text-lg">
            S
          </div>
          <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
            Sigil Bot
          </h1>
        </div>
        <p className="text-base text-gray-300">
          Sigil Bot continuously monitors package registries for security threats
          targeting the AI development ecosystem. Scan results are published
          automatically at{" "}
          <Link
            href="/scans"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            sigilsec.ai/scans
          </Link>
          .
        </p>
        <p className="text-xs text-gray-500">
          Automated scanning &middot; No code execution &middot; Static
          analysis only
        </p>
      </div>

      {/* Section 1: How It Works */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-gray-100">
          How Sigil Bot Works
        </h2>
        <p>
          Sigil Bot monitors four package registries for newly published and
          updated packages:
        </p>
        <ul className="list-disc list-inside space-y-1 text-gray-400">
          <li>
            <strong className="text-gray-300">PyPI</strong> &mdash; Python
            packages (RSS feeds + changelog API)
          </li>
          <li>
            <strong className="text-gray-300">npm</strong> &mdash; JavaScript
            packages (CouchDB changes feed)
          </li>
          <li>
            <strong className="text-gray-300">ClawHub</strong> &mdash; AI agent
            skills (REST API)
          </li>
          <li>
            <strong className="text-gray-300">GitHub</strong> &mdash; MCP
            server repositories (Search + Events API)
          </li>
        </ul>
        <p>
          When a new package or update is detected, the bot downloads the source
          code, runs a static analysis scan across six security phases, and
          publishes the results to the public scan database.
        </p>
        <div className="rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-3 text-xs text-gray-400">
          No code is executed during scanning. Sigil performs static analysis
          only &mdash; pattern matching against known threat indicators. Packages
          are never installed or run.
        </div>
      </section>

      {/* Section 2: Scanning Schedule */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-gray-100">
          Scanning Schedule
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="text-left py-2 pr-4 font-medium">Registry</th>
                <th className="text-left py-2 pr-4 font-medium">Frequency</th>
                <th className="text-left py-2 font-medium">Method</th>
              </tr>
            </thead>
            <tbody className="text-gray-400">
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">PyPI</td>
                <td className="py-2 pr-4">
                  Every 5 min (RSS) + every 60s (changelog)
                </td>
                <td className="py-2">RSS feed + XML-RPC serial API</td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">npm</td>
                <td className="py-2 pr-4">Every 60 seconds</td>
                <td className="py-2">
                  CouchDB <code className="text-gray-500">_changes</code> feed
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  ClawHub
                </td>
                <td className="py-2 pr-4">Every 6 hours</td>
                <td className="py-2">REST API pagination</td>
              </tr>
              <tr>
                <td className="py-2 pr-4 text-gray-200 font-medium">GitHub</td>
                <td className="py-2 pr-4">
                  Every 12h (search) + every 30 min (events)
                </td>
                <td className="py-2">Search API + Events API</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-xs text-gray-500">
          Frequencies may be adjusted based on registry rate limits and
          operational needs.
        </p>
      </section>

      {/* Section 3: Detection Methodology */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-gray-100">
          Detection Methodology
        </h2>
        <p>
          Sigil scans six security phases with weighted severity scoring:
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="text-left py-2 pr-4 font-medium">Phase</th>
                <th className="text-left py-2 pr-4 font-medium">Severity</th>
                <th className="text-left py-2 font-medium">What It Detects</th>
              </tr>
            </thead>
            <tbody className="text-gray-400">
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Install Hooks
                </td>
                <td className="py-2 pr-4 text-red-400 font-mono">
                  Critical 10&times;
                </td>
                <td className="py-2">
                  setup.py cmdclass, npm postinstall scripts
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Code Patterns
                </td>
                <td className="py-2 pr-4 text-orange-400 font-mono">
                  High 5&times;
                </td>
                <td className="py-2">
                  eval, exec, pickle, child_process, dynamic code execution
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Network / Exfil
                </td>
                <td className="py-2 pr-4 text-orange-400 font-mono">
                  High 3&times;
                </td>
                <td className="py-2">
                  Outbound HTTP, webhooks, DNS tunneling, sockets
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Credentials
                </td>
                <td className="py-2 pr-4 text-yellow-400 font-mono">
                  Medium 2&times;
                </td>
                <td className="py-2">
                  ENV vars, API key patterns, SSH key access
                </td>
              </tr>
              <tr className="border-b border-gray-800/50">
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Obfuscation
                </td>
                <td className="py-2 pr-4 text-orange-400 font-mono">
                  High 5&times;
                </td>
                <td className="py-2">
                  base64, charCode arrays, hex-encoded payloads
                </td>
              </tr>
              <tr>
                <td className="py-2 pr-4 text-gray-200 font-medium">
                  Provenance
                </td>
                <td className="py-2 pr-4 text-gray-400 font-mono">
                  Low&ndash;Medium 1-3&times;
                </td>
                <td className="py-2">
                  Git history anomalies, binaries, hidden files, name similarity
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p>
          Each finding has a severity weight. The total weighted score determines
          the overall verdict:{" "}
          <span className="text-green-400">LOW RISK</span>,{" "}
          <span className="text-yellow-400">MEDIUM RISK</span>,{" "}
          <span className="text-orange-400">HIGH RISK</span>, or{" "}
          <span className="text-red-400">CRITICAL RISK</span>.
        </p>
        <p className="text-xs text-gray-500">
          For full details, see the{" "}
          <Link
            href="/methodology"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            Scanning Methodology
          </Link>{" "}
          page.
        </p>
      </section>

      {/* Section 4: Scope & Filtering */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-gray-100">
          Which Packages Are Scanned
        </h2>
        <div className="space-y-2">
          <p>
            <strong className="text-gray-200">ClawHub:</strong> All skills are
            scanned. The entire registry is in scope because every skill has
            direct access to the user&apos;s environment.
          </p>
          <p>
            <strong className="text-gray-200">PyPI &amp; npm:</strong> Packages
            are filtered by AI ecosystem relevance &mdash; matching against
            keywords like{" "}
            <code className="text-gray-500">langchain</code>,{" "}
            <code className="text-gray-500">openai</code>,{" "}
            <code className="text-gray-500">anthropic</code>,{" "}
            <code className="text-gray-500">mcp</code>,{" "}
            <code className="text-gray-500">agent</code>,{" "}
            <code className="text-gray-500">llm</code>, and similar. Scoped
            packages under{" "}
            <code className="text-gray-500">@modelcontextprotocol</code>,{" "}
            <code className="text-gray-500">@langchain</code>,{" "}
            <code className="text-gray-500">@anthropic</code>, and{" "}
            <code className="text-gray-500">@openai</code> are always scanned.
          </p>
          <p>
            <strong className="text-gray-200">GitHub:</strong> Repositories
            matching MCP server patterns (topic tags, config files, import
            patterns) with at least one star or more than one commit.
          </p>
          <p className="text-xs text-gray-500">
            Packages with names closely resembling popular AI packages (potential
            typosquatting) are automatically prioritised for immediate scanning.
          </p>
        </div>
      </section>

      {/* Section 5: Bot Identity */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-gray-100">
          About Sigil Bot
        </h2>
        <p>
          Sigil Bot operates under the{" "}
          <code className="text-gray-400">sigil-bot</code> identity:
        </p>
        <ul className="list-disc list-inside space-y-1 text-gray-400">
          <li>
            <strong className="text-gray-300">Scan database:</strong> Results
            are attributed to &ldquo;Scanned by Sigil Bot&rdquo; with timestamps
          </li>
          <li>
            <strong className="text-gray-300">GitHub App:</strong> PR comments
            appear from{" "}
            <code className="text-gray-500">sigil-bot[bot]</code>
          </li>
          <li>
            <strong className="text-gray-300">Threat feed:</strong> Automated
            alerts posted to RSS and API endpoints
          </li>
        </ul>
        <div className="rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-3 text-xs text-gray-400">
          All output is automated. Scan results are systematic, algorithmic
          assessments &mdash; not editorial judgments by individuals. Results
          indicate the presence of patterns associated with known threat
          categories, not definitive classifications of malicious intent.
        </div>
      </section>

      {/* Section 6: Dispute Process */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-gray-100">
          Dispute a Scan Result
        </h2>
        <p>
          If you believe a scan result is inaccurate or your package has been
          incorrectly flagged:
        </p>
        <ol className="list-decimal list-inside space-y-2 text-gray-400">
          <li>
            <strong className="text-gray-300">Review the full report</strong> at
            the scan page to understand which findings were detected and why
          </li>
          <li>
            <strong className="text-gray-300">Submit a dispute</strong> via
            email to{" "}
            <a
              href="mailto:disputes@sigilsec.ai"
              className="text-brand-400 hover:text-brand-300 underline"
            >
              disputes@sigilsec.ai
            </a>{" "}
            with:
            <ul className="list-disc list-inside ml-5 mt-1 space-y-0.5 text-gray-500">
              <li>Package name, ecosystem, and version</li>
              <li>Which specific finding(s) you believe are incorrect</li>
              <li>
                Context explaining the legitimate purpose of the flagged pattern
              </li>
            </ul>
          </li>
          <li>
            <strong className="text-gray-300">Response time:</strong> We aim to
            review disputes within 5 business days
          </li>
          <li>
            <strong className="text-gray-300">Outcomes:</strong>
            <ul className="list-disc list-inside ml-5 mt-1 space-y-0.5 text-gray-500">
              <li>
                False positive &mdash; the finding will be suppressed for your
                package
              </li>
              <li>
                Overly broad rule &mdash; we will refine the detection rule
              </li>
              <li>
                Accurate finding &mdash; the result will remain with an
                explanation
              </li>
            </ul>
          </li>
        </ol>
        <p className="text-xs text-gray-500">
          Disputes do not remove scan results from the database. Resolved
          disputes add a &ldquo;Reviewed&rdquo; annotation to the report page.
        </p>
      </section>

      {/* Section 7: Legal Basis */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-gray-100">Legal Notice</h2>
        <p>
          Sigil Bot scans publicly available source code distributed through
          public package registries. Publishing a package to PyPI, npm, ClawHub,
          or a public GitHub repository constitutes distribution of source code
          to the public.
        </p>
        <p>
          Scan results are automated assessments based on pattern matching
          &mdash; they represent algorithmic analysis, not claims of wrongdoing.
          Results do not constitute legal advice or security certification.
        </p>
      </section>

      <hr className="border-gray-800" />

      <div className="space-y-2 text-xs text-gray-600">
        <p>
          For full terms, see our{" "}
          <Link
            href="/terms"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            Terms of Service
          </Link>{" "}
          and{" "}
          <Link
            href="/privacy"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            Privacy Policy
          </Link>
          . For questions, contact{" "}
          <a
            href="mailto:security@nomark.ai"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            security@nomark.ai
          </a>
          .
        </p>
      </div>
    </div>
  );
}
