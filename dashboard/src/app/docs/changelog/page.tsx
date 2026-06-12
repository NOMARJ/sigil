import Link from "next/link";
import type { ReactElement } from "react";

const releases = [
  {
    date: "2026-03-17",
    title: "Scanner v2 rollout",
    items: [
      "Context-aware false-positive reduction deployed.",
      "Confidence scoring added for findings.",
      "Progressive migration support added for legacy scans.",
      "Feature flags configured for scanner v1 fallback.",
    ],
  },
  {
    date: "2026-03-15",
    title: "False-positive hardening",
    items: [
      "Regex exec usage separated from dangerous command execution.",
      "Documentation and test file context now reduces severity.",
      "Known-safe API domains are handled as benign network patterns.",
    ],
  },
];

export default function ChangelogPage(): ReactElement {
  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <div className="space-y-3">
        <p className="text-sm font-medium text-green-400">Release notes</p>
        <h1 className="text-3xl font-semibold text-gray-100">Changelog</h1>
        <p className="max-w-3xl text-sm leading-6 text-gray-400">
          Product and scanner changes that affect dashboard review workflows,
          scan accuracy, and migration behavior.
        </p>
      </div>

      <div className="space-y-5">
        {releases.map((release) => (
          <section
            key={`${release.date}-${release.title}`}
            className="rounded-lg border border-gray-800 bg-gray-900/60 p-6"
          >
            <div className="flex flex-wrap items-baseline justify-between gap-3">
              <h2 className="text-lg font-semibold text-gray-100">
                {release.title}
              </h2>
              <time className="text-sm text-gray-500">{release.date}</time>
            </div>
            <ul className="mt-4 space-y-2 text-sm leading-6 text-gray-400">
              {release.items.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>
        ))}
      </div>

      <div className="flex flex-wrap gap-3">
        <Link href="/docs/scanner-v2" className="btn-primary text-sm">
          Scanner v2 details
        </Link>
        <Link href="/" className="btn-secondary text-sm">
          Back to dashboard
        </Link>
      </div>
    </div>
  );
}
