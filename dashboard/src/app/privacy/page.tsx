import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Privacy Policy — Sigil",
  description:
    "Privacy Policy for Sigil automated security scanning. How we handle data from public package registries.",
};

export default function PrivacyPage() {
  return (
    <div className="max-w-3xl mx-auto py-12 px-4 space-y-8 text-gray-300 text-sm leading-relaxed">
      <div>
        <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
          Privacy Policy
        </h1>
        <p className="text-xs text-gray-500 mt-1">
          Last updated: February 2026 &middot; NOMARK Pty Ltd &middot;
          Queensland, Australia
        </p>
      </div>

      <p>
        This Privacy Policy describes how NOMARK Pty Ltd (&ldquo;we&rdquo;,
        &ldquo;us&rdquo;, &ldquo;our&rdquo;) collects, uses, and handles
        information in connection with the Sigil security scanning service
        (&ldquo;Service&rdquo;).
      </p>

      {/* Data Sources */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">Data Sources</h2>
        <p>
          Sigil collects and processes data from the following public sources:
        </p>
        <ul className="list-disc list-inside space-y-1 text-gray-400">
          <li>Public package registries (PyPI, npm, ClawHub)</li>
          <li>Public GitHub repositories and profiles</li>
          <li>Public MCP server registries</li>
        </ul>
        <p>
          We do not collect data from private repositories, private registries,
          or any source requiring authentication.
        </p>
      </section>

      {/* Purpose */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          Purpose of Processing
        </h2>
        <p>
          We process publicly available package data for the purpose of security
          transparency &mdash; enabling developers to assess risk before
          installing packages. This includes:
        </p>
        <ul className="list-disc list-inside space-y-1 text-gray-400">
          <li>Automated static analysis of package source code</li>
          <li>
            Publication of scan results (risk classifications, findings,
            metadata)
          </li>
          <li>Generation of scan result badges for public display</li>
          <li>Threat intelligence aggregation for community benefit</li>
        </ul>
      </section>

      {/* Lawful Basis */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">Lawful Basis</h2>
        <p>
          Our lawful basis for processing public registry metadata is legitimate
          interest (GDPR Article 6(1)(f)). We have determined that:
        </p>
        <ul className="list-disc list-inside space-y-1 text-gray-400">
          <li>
            There is a legitimate interest in community security transparency
          </li>
          <li>
            Processing is necessary to achieve this purpose (automated scanning
            at scale)
          </li>
          <li>
            The interest is not overridden by the data subject&apos;s rights,
            given that all data is already publicly available
          </li>
        </ul>
      </section>

      {/* Data Minimisation */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          Data Minimisation
        </h2>
        <p>
          We only collect data that is already publicly available. No
          unnecessary personal data is stored. Author names and handles are
          sourced directly from public registries and are displayed only in the
          context of package metadata attribution.
        </p>
      </section>

      {/* User Rights */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">Your Rights</h2>
        <p>You have the following rights in relation to your personal data:</p>
        <ul className="list-disc list-inside space-y-1 text-gray-400">
          <li>
            <strong className="text-gray-300">Right to access:</strong> Request
            a copy of the data we hold about you
          </li>
          <li>
            <strong className="text-gray-300">Right to object:</strong> Object
            to the processing of your data under legitimate interest
          </li>
          <li>
            <strong className="text-gray-300">Right to removal:</strong> Request
            removal of your personal data from scan results
          </li>
        </ul>
        <p>
          To exercise any of these rights, contact us at{" "}
          <a
            href="mailto:security@nomark.ai"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            security@nomark.ai
          </a>
          .
        </p>
      </section>

      {/* Data Retention */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">Data Retention</h2>
        <p>
          Scan results are retained indefinitely for historical reference. When
          a package is rescanned, the previous result is updated or superseded.
          Upon a valid removal request, associated personal data will be removed
          within 30 days.
        </p>
      </section>

      {/* Cookies & Analytics */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          Cookies &amp; Analytics
        </h2>
        <p>
          The Service may use essential cookies for session management and
          authentication. We do not use third-party advertising cookies or
          cross-site tracking. Analytics, if used, are privacy-respecting and
          aggregated.
        </p>
      </section>

      {/* Contact */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">Contact</h2>
        <p>
          For privacy inquiries, data removal requests, or any questions about
          this policy, contact:
        </p>
        <p className="text-gray-400">
          NOMARK Pty Ltd
          <br />
          Email:{" "}
          <a
            href="mailto:security@nomark.ai"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            security@nomark.ai
          </a>
        </p>
      </section>

      <hr className="border-gray-800" />

      <p className="text-xs text-gray-600">
        This Privacy Policy will be reviewed by qualified external counsel
        before the Service is made publicly available.
      </p>
    </div>
  );
}
