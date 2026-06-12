import Link from "next/link";
import type { ReactElement } from "react";

const improvements = [
  {
    title: "Context-aware matching",
    body: "Documentation, tests, and source files are weighted differently so examples are not treated the same as executable production code.",
  },
  {
    title: "Confidence scoring",
    body: "Findings include confidence signals so review starts with the most credible security issues first.",
  },
  {
    title: "Safer network classification",
    body: "Known legitimate provider endpoints are handled separately from suspicious callback and exfiltration patterns.",
  },
];

export default function ScannerV2DocsPage(): ReactElement {
  return (
    <div className="mx-auto max-w-5xl space-y-8">
      <div className="space-y-3">
        <p className="text-sm font-medium text-green-400">Scanner v2</p>
        <h1 className="text-3xl font-semibold text-gray-100">
          Enhanced scanner improvements
        </h1>
        <p className="max-w-3xl text-sm leading-6 text-gray-400">
          Scanner v2 reduces noisy findings with context-aware analysis,
          confidence scoring, and more precise handling for benign patterns.
          Existing scan endpoints remain compatible while new scans use the
          enhanced scanner path.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {improvements.map((item) => (
          <section
            key={item.title}
            className="rounded-lg border border-gray-800 bg-gray-900/60 p-5"
          >
            <h2 className="text-sm font-semibold text-gray-100">{item.title}</h2>
            <p className="mt-3 text-sm leading-6 text-gray-400">{item.body}</p>
          </section>
        ))}
      </div>

      <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-6">
        <h2 className="text-lg font-semibold text-gray-100">What changed</h2>
        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <div>
            <h3 className="text-sm font-medium text-gray-200">Before</h3>
            <ul className="mt-3 space-y-2 text-sm text-gray-400">
              <li>Regex and documentation examples could inflate risk.</li>
              <li>Benign API provider calls were easier to over-classify.</li>
              <li>Reviewers had less signal about finding confidence.</li>
            </ul>
          </div>
          <div>
            <h3 className="text-sm font-medium text-gray-200">Now</h3>
            <ul className="mt-3 space-y-2 text-sm text-gray-400">
              <li>File context adjusts severity for docs and tests.</li>
              <li>Safe-domain handling reduces common network false positives.</li>
              <li>Confidence metadata helps prioritize review work.</li>
            </ul>
          </div>
        </div>
      </section>

      <div className="flex flex-wrap gap-3">
        <Link href="/docs/changelog" className="btn-primary text-sm">
          View changelog
        </Link>
        <Link href="/scans" className="btn-secondary text-sm">
          Review scans
        </Link>
      </div>
    </div>
  );
}
