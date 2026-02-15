#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

const SIGIL_BINARY = process.env.SIGIL_BINARY ?? "sigil";

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

// ── Server ─────────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "sigil",
  version: "0.1.0",
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
        { type: "text" as const, text: summary + "\n" + details },
      ],
    };
  }
);

// ── Tool: scan_package ─────────────────────────────────────────────────────

server.tool(
  "sigil_scan_package",
  "Download and scan an npm or pip package in quarantine before installing it. Use this to check if a package is safe.",
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
        { type: "text" as const, text: summary + "\n" + details },
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
        { type: "text" as const, text: summary + "\n" + details },
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
