#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFile } from "child_process";
import { promisify } from "util";
import { request as httpsRequest } from "https";
import { request as httpRequest } from "http";

const execFileAsync = promisify(execFile);

const SIGIL_BINARY = process.env.SIGIL_BINARY ?? "sigil";
const SIGIL_API_URL =
  process.env.SIGIL_API_URL ?? "https://api.sigilsec.ai";

const DISCLAIMER =
  "\n---\nDisclaimer: Automated static analysis result. Not a security certification. Provided as-is without warranty. See sigilsec.ai/terms for full terms.";

// ── Helpers ────────────────────────────────────────────────────────────────

async function runSigil(
  args: string[]
): Promise<{ stdout: string; stderr: string }> {
  try {
    return await execFileAsync(SIGIL_BINARY, args, {
      timeout: 300_000,
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; message?: string };
    // sigil exits non-zero on findings — that's expected
    if (e.stdout) {
      return { stdout: e.stdout, stderr: e.stderr ?? "" };
    }
    throw new Error(e.stderr || e.message || "sigil execution failed");
  }
}

async function fetchAPI(path: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, SIGIL_API_URL);
    const doRequest = url.protocol === "http:" ? httpRequest : httpsRequest;
    const req = doRequest(url, { method: "GET" }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        const body = Buffer.concat(chunks).toString();
        const statusCode = res.statusCode ?? 0;
        if (statusCode < 200 || statusCode >= 300) {
          reject(new Error(`HTTP ${statusCode}: ${body.slice(0, 200)}`));
          return;
        }
        try {
          resolve(JSON.parse(body));
        } catch {
          resolve(body);
        }
      });
    });
    req.on("error", reject);
    req.setTimeout(30_000, () => {
      req.destroy(new Error("Request timed out"));
    });
    req.end();
  });
}

// ── Server ─────────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "sigil",
  version: "1.1.0",
});

// ── Tool: scan ─────────────────────────────────────────────────────────────

server.tool(
  "sigil_scan",
  "Scan a file or directory for security issues. Returns structured findings with severity, phase, and location. Use this to audit code before running, installing packages, or reviewing pull requests.",
  {
    path: z.string().describe("File or directory path to scan"),
    phases: z
      .string()
      .optional()
      .describe(
        "Comma-separated scan phases: install_hooks,code_patterns,network_exfil,credentials,obfuscation,provenance"
      ),
    severity: z
      .enum(["low", "medium", "high", "critical"])
      .optional()
      .describe("Minimum severity threshold"),
  },
  async ({ path, phases, severity }) => {
    const args = ["--format", "json", "scan", path];
    if (phases) args.push("--phases", phases);
    if (severity) args.push("--severity", severity);

    const { stdout } = await runSigil(args);
    const result = JSON.parse(stdout);

    const summary = `Verdict: ${result.verdict} | Score: ${result.score} | ${result.findings.length} findings | ${result.files_scanned} files scanned in ${result.duration_ms}ms`;

    let details = "";
    for (const f of result.findings) {
      details += `\n[${f.severity.toUpperCase()}] ${f.rule} — ${f.file}${f.line ? `:${f.line}` : ""}\n  ${f.snippet}\n`;
    }

    return {
      content: [
        { type: "text" as const, text: summary + "\n" + details + DISCLAIMER },
      ],
    };
  }
);

// ── Tool: scan_package ─────────────────────────────────────────────────────

server.tool(
  "sigil_scan_package",
  "Download and scan an npm or pip package in quarantine before installing it. Use this to assess risk before installation.",
  {
    manager: z
      .enum(["npm", "pip"])
      .describe("Package manager (npm or pip)"),
    package_name: z.string().describe("Package name to scan"),
    version: z
      .string()
      .optional()
      .describe("Specific version to scan"),
  },
  async ({ manager, package_name, version }) => {
    const args = ["--format", "json", manager, package_name];
    if (version) args.push("--version", version);

    const { stdout } = await runSigil(args);
    const result = JSON.parse(stdout);

    const summary = `Package: ${manager}/${package_name}${version ? `@${version}` : ""}\nVerdict: ${result.verdict} | Score: ${result.score} | ${result.findings.length} findings`;

    let details = "";
    for (const f of result.findings) {
      details += `\n[${f.severity.toUpperCase()}] ${f.rule} — ${f.file}${f.line ? `:${f.line}` : ""}\n  ${f.snippet}\n`;
    }

    return {
      content: [
        { type: "text" as const, text: summary + "\n" + details + DISCLAIMER },
      ],
    };
  }
);

// ── Tool: clone_and_scan ───────────────────────────────────────────────────

server.tool(
  "sigil_clone",
  "Clone a git repository into quarantine and scan it for security issues. Use this to audit repos before cloning them into your workspace.",
  {
    url: z.string().describe("Git repository URL"),
    branch: z.string().optional().describe("Specific branch to clone"),
  },
  async ({ url, branch }) => {
    const args = ["--format", "json", "clone", url];
    if (branch) args.push("--branch", branch);

    const { stdout } = await runSigil(args);
    const result = JSON.parse(stdout);

    const summary = `Repository: ${url}${branch ? ` (${branch})` : ""}\nVerdict: ${result.verdict} | Score: ${result.score} | ${result.findings.length} findings`;

    let details = "";
    for (const f of result.findings) {
      details += `\n[${f.severity.toUpperCase()}] ${f.rule} — ${f.file}${f.line ? `:${f.line}` : ""}\n  ${f.snippet}\n`;
    }

    return {
      content: [
        { type: "text" as const, text: summary + "\n" + details + DISCLAIMER },
      ],
    };
  }
);

// ── Tool: quarantine_list ──────────────────────────────────────────────────

server.tool(
  "sigil_quarantine",
  "List all items currently in the Sigil quarantine, showing their scan status and verdict.",
  {},
  async () => {
    const { stdout } = await runSigil(["list", "--format", "json"]);
    const entries = JSON.parse(stdout);

    if (entries.length === 0) {
      return {
        content: [{ type: "text" as const, text: "Quarantine is empty." }],
      };
    }

    let text = `${entries.length} item(s) in quarantine:\n`;
    for (const e of entries) {
      text += `\n[${e.status.toUpperCase()}] ${e.source} (${e.source_type})`;
      if (e.scan_score != null) text += ` — score: ${e.scan_score}`;
      text += `\n  ID: ${e.id}\n`;
    }

    return {
      content: [{ type: "text" as const, text }],
    };
  }
);

// ── Tool: approve / reject ─────────────────────────────────────────────────

server.tool(
  "sigil_approve",
  "Approve a quarantined item and move it to the working directory.",
  {
    quarantine_id: z.string().describe("Quarantine entry ID"),
  },
  async ({ quarantine_id }) => {
    const { stdout, stderr } = await runSigil(["approve", quarantine_id]);
    return {
      content: [
        { type: "text" as const, text: stdout || stderr || "Approved." },
      ],
    };
  }
);

server.tool(
  "sigil_reject",
  "Reject and delete a quarantined item.",
  {
    quarantine_id: z.string().describe("Quarantine entry ID"),
  },
  async ({ quarantine_id }) => {
    const { stdout, stderr } = await runSigil(["reject", quarantine_id]);
    return {
      content: [
        { type: "text" as const, text: stdout || stderr || "Rejected." },
      ],
    };
  }
);

// ── Tool: check_package (query public scan database) ─────────────────────

server.tool(
  "sigil_check_package",
  "Look up a package or skill's risk assessment in the Sigil public scan database. Works for ClawHub skills, PyPI packages, npm packages, and MCP servers.",
  {
    ecosystem: z
      .enum(["clawhub", "pypi", "npm", "github", "mcp"])
      .describe("Package ecosystem"),
    package_name: z
      .string()
      .describe("Package name, skill slug, or repo path (e.g. 'todoist-cli')"),
  },
  async ({ ecosystem, package_name }) => {
    try {
      const data = (await fetchAPI(
        `/registry/${encodeURIComponent(ecosystem)}/${encodeURIComponent(package_name)}`
      )) as Record<string, unknown>;

      if (data && typeof data === "object" && data.verdict) {
        const verdict = String(data.verdict);
        const score = Number(data.risk_score ?? 0);
        const findingsCount = Number(data.findings_count ?? 0);
        const scannedAt = String(data.scanned_at ?? "unknown");
        const badgeUrl = String(data.badge_url ?? "");
        const reportUrl = String(data.report_url ?? "");
        const version = String(data.package_version ?? "");

        let summary = `Package: ${ecosystem}/${package_name}${version ? `@${version}` : ""}\nVerdict: ${verdict} | Risk Score: ${score} | ${findingsCount} findings\nScanned: ${scannedAt}`;

        if (reportUrl) summary += `\nReport: ${reportUrl}`;
        if (badgeUrl) summary += `\nBadge: ${badgeUrl}`;

        // Include top findings if available
        const findings = data.findings as Array<Record<string, unknown>> | undefined;
        if (findings && findings.length > 0) {
          summary += "\n\nTop findings:";
          for (const f of findings.slice(0, 5)) {
            summary += `\n  [${String(f.severity ?? "MEDIUM").toUpperCase()}] ${String(f.rule ?? "")} — ${String(f.file ?? "")}${f.line ? `:${f.line}` : ""}`;
            if (f.snippet) summary += `\n    ${String(f.snippet).slice(0, 200)}`;
          }
          if (findings.length > 5) {
            summary += `\n  ... and ${findings.length - 5} more findings`;
          }
        }

        return {
          content: [{ type: "text" as const, text: summary + DISCLAIMER }],
        };
      }

      return {
        content: [
          {
            type: "text" as const,
            text: `No scan found for ${ecosystem}/${package_name}. You can scan it locally with: sigil scan <path>`,
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Could not query scan database for ${ecosystem}/${package_name}. Run a local scan instead: sigil scan <path>`,
          },
        ],
      };
    }
  }
);

// ── Tool: search_database ────────────────────────────────────────────────

server.tool(
  "sigil_search_database",
  "Search the Sigil public scan database for packages by name or keyword. Returns a list of scanned packages with their verdicts and risk scores.",
  {
    query: z.string().describe("Search query (package name or keyword)"),
    ecosystem: z
      .enum(["clawhub", "pypi", "npm", "github", "mcp"])
      .optional()
      .describe("Filter by ecosystem"),
  },
  async ({ query, ecosystem }) => {
    try {
      let path = `/registry/search?q=${encodeURIComponent(query)}`;
      if (ecosystem) path += `&ecosystem=${encodeURIComponent(ecosystem)}`;

      const data = (await fetchAPI(path)) as Record<string, unknown>;

      if (data && typeof data === "object" && Array.isArray(data.items)) {
        const items = data.items as Array<Record<string, unknown>>;
        const total = Number(data.total ?? items.length);

        if (items.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: `No results found for "${query}". The package may not have been scanned yet.`,
              },
            ],
          };
        }

        let text = `Found ${total} result(s) for "${query}":\n`;
        for (const item of items.slice(0, 10)) {
          const v = String(item.verdict ?? "UNKNOWN");
          const s = Number(item.risk_score ?? 0);
          const eco = String(item.ecosystem ?? "");
          const name = String(item.package_name ?? "");
          const ver = item.package_version ? `@${item.package_version}` : "";
          text += `\n  [${v}] ${eco}/${name}${ver} — score: ${s}`;
        }
        if (total > 10) text += `\n  ... and ${total - 10} more results`;

        return {
          content: [{ type: "text" as const, text: text + DISCLAIMER }],
        };
      }

      return {
        content: [
          { type: "text" as const, text: `No results found for "${query}".` },
        ],
      };
    } catch {
      return {
        content: [
          {
            type: "text" as const,
            text: `Could not search the scan database. Try a local scan: sigil scan <path>`,
          },
        ],
      };
    }
  }
);

// ── Tool: report_threat ──────────────────────────────────────────────────

server.tool(
  "sigil_report_threat",
  "Flag a suspicious package or skill to the Sigil threat intelligence database. Reports are reviewed by the security team.",
  {
    package_name: z.string().describe("Name of the suspicious package"),
    ecosystem: z
      .enum(["clawhub", "pypi", "npm", "github", "mcp"])
      .describe("Package ecosystem"),
    reason: z.string().describe("Why you believe this package is malicious"),
  },
  async ({ package_name, ecosystem, reason }) => {
    return {
      content: [
        {
          type: "text" as const,
          text: `Threat report noted for ${ecosystem}/${package_name}.\nReason: ${reason}\n\nTo submit formally, run: sigil report --package "${package_name}" --ecosystem "${ecosystem}" --reason "${reason}"`,
        },
      ],
    };
  }
);

// ── Resource: scan phases documentation ────────────────────────────────────

server.resource(
  "sigil://docs/phases",
  "sigil://docs/phases",
  async (uri) => ({
    contents: [
      {
        uri: uri.href,
        mimeType: "text/plain",
        text: `Sigil Scan Phases
=================

1. Install Hooks (Critical, 10x weight)
   Detects malicious install-time code: setup.py install commands,
   npm postinstall scripts, pip build hooks, Makefile targets.

2. Code Patterns (High, 5x weight)
   Flags dangerous code patterns: eval(), exec(), pickle.loads(),
   child_process.exec(), dynamic imports, reflection abuse.

3. Network/Exfiltration (High, 3x weight)
   Identifies outbound network activity: HTTP requests, webhooks,
   socket connections, DNS exfiltration, reverse shells.

4. Credentials (Medium, 2x weight)
   Finds exposed secrets: API keys, tokens, SSH keys, .env files,
   hardcoded passwords, AWS credentials.

5. Obfuscation (High, 5x weight)
   Detects code hiding techniques: base64 encoding, hex/charCode
   strings, string concatenation tricks, minified payloads.

6. Provenance (Low, 1-3x weight)
   Checks code origin: binary files, hidden dotfiles, git history
   anomalies, unsigned commits, suspicious file permissions.`,
      },
    ],
  })
);

// ── Start ──────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Sigil MCP server failed to start:", err);
  process.exit(1);
});
