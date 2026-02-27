import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Terms of Service — Sigil",
  description:
    "Terms of Service for Sigil automated security scanning. Provided by NOMARK Pty Ltd.",
};

export default function TermsPage() {
  return (
    <div className="max-w-3xl mx-auto py-12 px-4 space-y-8 text-gray-300 text-sm leading-relaxed">
      <div>
        <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
          Terms of Service
        </h1>
        <p className="text-xs text-gray-500 mt-1">
          Last updated: February 2026 &middot; NOMARK Pty Ltd &middot;
          Queensland, Australia
        </p>
      </div>

      <p>
        By accessing or using the Sigil service (&ldquo;Service&rdquo;),
        including the website at sigilsec.ai, the API, the CLI tool, the MCP
        server, and all related tools and services, you agree to be bound by
        these Terms of Service (&ldquo;Terms&rdquo;). If you do not agree to
        these Terms, do not use the Service.
      </p>

      {/* 7.1 No Warranty */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">1. No Warranty</h2>
        <p>
          Scan results, verdicts, risk scores, and all related outputs are
          provided &ldquo;as is&rdquo; and &ldquo;as available&rdquo; without
          warranties of any kind, whether express or implied, including but not
          limited to implied warranties of merchantability, fitness for a
          particular purpose, accuracy, or non-infringement.
        </p>
      </section>

      {/* 7.2 ACL Carve-Out */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          2. Australian Consumer Law
        </h2>
        <p>
          Nothing in these Terms excludes, restricts or modifies any consumer
          guarantee, right or remedy available under the Australian Consumer Law
          (Schedule 2 of the <em>Competition and Consumer Act 2010</em> (Cth))
          that cannot be excluded, restricted or modified by agreement.
        </p>
      </section>

      {/* 7.3 Information-Only Purpose */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          3. Information-Only Purpose
        </h2>
        <p>
          The Service provides general information only and does not constitute
          professional security, technical, or risk advice. You should not rely
          on the Service as a substitute for professional judgement.
        </p>
      </section>

      {/* 7.4 No Certification */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          4. No Certification
        </h2>
        <p>
          A scan result (including LOW RISK or any other verdict) does not
          constitute a security certification, endorsement, or recommendation.
          Verdicts reflect the output of automated pattern matching at a
          specific point in time against a specific version of a package. They
          do not represent a comprehensive security audit.
        </p>
      </section>

      {/* 7.5 Algorithmic Opinion */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          5. Algorithmic Opinion
        </h2>
        <p>
          Risk classifications reflect the output of automated analysis based on
          defined detection criteria and are statements of algorithmic opinion,
          not assertions of malicious intent by any author or publisher.
        </p>
      </section>

      {/* 7.6 No-Reliance */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">6. No-Reliance</h2>
        <p>
          Users must not rely solely on Sigil scan results when making security,
          operational, or commercial decisions. Always review source code before
          installing or executing any package.
        </p>
      </section>

      {/* 7.7 Limitation of Liability */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          7. Limitation of Liability
        </h2>
        <p>
          To the maximum extent permitted by law, NOMARK Pty Ltd shall not be
          liable for any direct, indirect, incidental, special, consequential,
          or exemplary damages arising from or relating to: reliance on scan
          results; false negatives (malicious code not detected); false
          positives (legitimate code flagged as suspicious); any action taken or
          not taken based on scan results; or any use of the Sigil badge or
          scan reports by third parties.
        </p>
      </section>

      {/* 7.8 No Continuous Monitoring */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          8. No Continuous Monitoring
        </h2>
        <p>
          NOMARK does not monitor packages continuously and is not responsible
          for changes made after a scan. Each scan represents analysis of a
          specific version at a specific point in time.
        </p>
      </section>

      {/* 7.9 Badge Usage */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">9. Badge Usage</h2>
        <p>
          The Sigil badge is provided for informational purposes. Displaying a
          Sigil badge on a package, repository, or website does not create an
          endorsement relationship between NOMARK Pty Ltd and the package author
          or publisher. Display of a Sigil badge does not imply approval,
          partnership, monitoring, or ongoing assessment by NOMARK Pty Ltd.
          Badge results may change without notice when packages are rescanned.
          Package authors are solely responsible for the security of their code
          regardless of Sigil scan results.
        </p>
      </section>

      {/* 7.10 False Positive / Dispute */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          10. False Positive / Dispute Process
        </h2>
        <p>
          Package authors who believe their package has been incorrectly flagged
          may request a review by contacting{" "}
          <a
            href="mailto:security@nomark.ai"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            security@nomark.ai
          </a>{" "}
          or opening a dispute through the scan report page. NOMARK reserves the
          right to maintain, modify, or remove scan results at its discretion.
          Filing a dispute does not guarantee a change in verdict.
        </p>
      </section>

      {/* 7.11 Automated Scanning */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          11. Automated Scanning
        </h2>
        <p>
          Packages listed in the scan database are scanned automatically without
          the package author&apos;s request or consent. NOMARK scans publicly
          available packages from public registries and repositories. Package
          authors may request removal of their scan results by contacting{" "}
          <a
            href="mailto:security@nomark.ai"
            className="text-brand-400 hover:text-brand-300 underline"
          >
            security@nomark.ai
          </a>
          , though NOMARK reserves the right to continue scanning public
          packages in the interest of community security.
        </p>
      </section>

      {/* 7.12 Data Accuracy */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          12. Data Accuracy
        </h2>
        <p>
          NOMARK makes reasonable efforts to ensure scan accuracy but does not
          guarantee that scan results are error-free, complete, or current.
          Package metadata (descriptions, author information, download counts)
          is sourced from third-party registries and may be inaccurate or
          outdated.
        </p>
      </section>

      {/* 7.13 Redistribution */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          13. Redistribution / API Use
        </h2>
        <p>
          Users must not present Sigil scan data as their own certification,
          guarantee, or security assessment. When redistributing or displaying
          Sigil scan results, the disclaimer and attribution must be preserved.
        </p>
      </section>

      {/* 7.14 Indemnification */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          14. Indemnification
        </h2>
        <p>
          Users who rely on Sigil scan results, embed Sigil badges, or
          distribute Sigil scan data agree to indemnify and hold harmless NOMARK
          Pty Ltd from any claims, damages, or expenses arising from such use.
        </p>
      </section>

      {/* 7.15 Jurisdiction */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-100">
          15. Governing Law
        </h2>
        <p>
          These Terms are governed by the laws of Queensland, Australia, and
          disputes are subject to the exclusive jurisdiction of the courts of
          Queensland.
        </p>
      </section>

      <hr className="border-gray-800" />

      <p className="text-xs text-gray-600">
        These Terms are directional and will be reviewed by qualified external
        counsel before the Service is made publicly available. For questions,
        contact{" "}
        <a
          href="mailto:legal@nomark.ai"
          className="text-brand-400 hover:text-brand-300 underline"
        >
          legal@nomark.ai
        </a>
        .
      </p>
    </div>
  );
}
