#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFile } from "child_process";
import { promisify } from "util";
import { request as httpsRequest } from "https";
import { request as httpRequest } from "http";
// Forge tools removed - discovery feature sunset

const execFileAsync = promisify(execFile);

const SIGIL_BINARY = process.env.SIGIL_BINARY ?? "sigil";
const SIGIL_API_URL =
  process.env.SIGIL_API_URL ?? "https://api.sigilsec.ai";

const DISCLAIMER =
  "\n---\nDisclaimer: Automated static analysis result. Not a security certification. Provided as-is without warranty. See sigilsec.ai/terms for full terms.";

const INSTALL_ONE_LINER =
  "curl -fsSLO https://www.sigilsec.ai/install.sh && sh install.sh";

const SIGIL_MISSING_TEXT = `The Sigil CLI ("${SIGIL_BINARY}") was not found on this system, so this tool cannot run a scan.

To install Sigil:
  ${INSTALL_ONE_LINER}

If Sigil is already installed at a non-default location, set the SIGIL_BINARY environment variable to its full path and restart the MCP server. Database-backed tools (sigil_check_package, sigil_search_database) work without the CLI.`;

// ── Helpers ────────────────────────────────────────────────────────────────

class SigilNotInstalledError extends Error {
  constructor() {
    super(`sigil binary not found: ${SIGIL_BINARY}`);
  }
}

type TextToolResult = { content: { type: "text"; text: string }[] };

function sigilMissingResult(): TextToolResult {
  return { content: [{ type: "text" as const, text: SIGIL_MISSING_TEXT }] };
}

/**
 * Wrap a CLI-backed tool handler so a missing sigil binary degrades to a
 * normal text result (install instructions) instead of a thrown error.
 */
function guardSigil<A>(
  handler: (args: A) => Promise<TextToolResult>
): (args: A) => Promise<TextToolResult> {
  return async (args: A) => {
    try {
      return await handler(args);
    } catch (err: unknown) {
      if (err instanceof SigilNotInstalledError) {
        return sigilMissingResult();
      }
      throw err;
    }
  };
}

type SigilRun = { stdout: string; stderr: string; code: number | null };

async function runSigil(args: string[]): Promise<SigilRun> {
  try {
    const { stdout, stderr } = await execFileAsync(SIGIL_BINARY, args, {
      timeout: 300_000,
      maxBuffer: 10 * 1024 * 1024,
    });
    return { stdout, stderr, code: 0 };
  } catch (err: unknown) {
    const e = err as {
      code?: string | number;
      stdout?: string;
      stderr?: string;
      message?: string;
    };
    if (e.code === "ENOENT") {
      throw new SigilNotInstalledError();
    }
    // sigil exits 1 when findings reach the fail threshold — that's expected,
    // and stdout still carries the full result.
    if (e.stdout) {
      return {
        stdout: e.stdout,
        stderr: e.stderr ?? "",
        code: typeof e.code === "number" ? e.code : null,
      };
    }
    throw new Error(e.stderr || e.message || "sigil execution failed");
  }
}

/**
 * Run a `--format json` command and parse the single document it prints on
 * stdout. Exit code 1 (findings at or above the fail threshold) is a normal
 * result. Exit code 2 (the command itself failed) and unparseable output
 * surface the stderr text instead of a JSON parse error.
 */
async function runSigilJson(args: string[]): Promise<any> {
  const { stdout, stderr, code } = await runSigil(args);
  if (code !== null && code !== 0 && code !== 1) {
    throw new Error(
      stderr.trim() || stdout.trim() || `sigil exited with code ${code}`
    );
  }
  try {
    return JSON.parse(stdout);
  } catch {
    const head = stdout.trim().slice(0, 200);
    throw new Error(
      stderr.trim() ||
        `sigil did not return JSON${code !== null ? ` (exit code ${code})` : ""}${head ? `: ${head}` : ""}`
    );
  }
}

type ScanSummary = {
  verdict: string;
  score: string | number;
  grade?: string;
  recommendation?: string;
  findings_count: number;
  files_scanned?: number;
  duration_ms?: number;
};

/**
 * Scan summary scalars. Current binaries nest them under `summary` (verdict,
 * score, grade, recommendation, findings_count, files_scanned, duration_ms);
 * older ones put verdict/score/files_scanned/duration_ms at the top level.
 */
function summaryOf(result: any): ScanSummary {
  const s =
    result?.summary && typeof result.summary === "object" ? result.summary : {};
  const findings = Array.isArray(result?.findings) ? result.findings : null;
  return {
    verdict: String(s.verdict ?? result?.verdict ?? "UNKNOWN"),
    score: s.score ?? result?.score ?? "n/a",
    grade: s.grade ?? result?.grade,
    recommendation: s.recommendation ?? result?.recommendation,
    findings_count: findings ? findings.length : Number(s.findings_count ?? 0),
    files_scanned: s.files_scanned ?? result?.files_scanned,
    duration_ms: s.duration_ms ?? result?.duration_ms,
  };
}

/** Header line shared by the scan tools. */
function summaryLine(result: any): string {
  const s = summaryOf(result);
  const parts = [`Verdict: ${s.verdict}`, `Score: ${s.score}`];
  if (s.grade) parts.push(`Grade: ${s.grade}`);
  parts.push(`${s.findings_count} findings`);
  if (s.files_scanned != null) {
    parts.push(
      `${s.files_scanned} files scanned` +
        (s.duration_ms != null ? ` in ${s.duration_ms}ms` : "")
    );
  }
  let line = parts.join(" | ");
  if (s.recommendation) line += `\nRecommendation: ${s.recommendation}`;
  return line;
}

/** One block per finding: `[SEV] RULE — file:line` followed by the snippet. */
function findingLines(result: any): string {
  let details = "";
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  for (const f of findings) {
    details += `\n[${String(f.severity ?? "").toUpperCase()}] ${f.rule} — ${f.file}${f.line ? `:${f.line}` : ""}\n  ${f.snippet}\n`;
  }
  return details;
}

/**
 * `profile.key_risks` entries are objects ({rule, severity, file, line,
 * title}) or, from some builds, preformatted strings.
 */
function keyRiskLine(risk: unknown): string {
  if (typeof risk === "string") return risk;
  const k = (risk ?? {}) as Record<string, unknown>;
  const loc = k.file ? `${k.file}${k.line != null ? `:${k.line}` : ""}` : "";
  return `[${String(k.severity ?? "").toUpperCase()}] ${String(k.rule ?? "")}${loc ? ` ${loc}` : ""} — ${String(k.title ?? "")}`;
}

/**
 * Mirror of the CLI's residue redaction: any run of 20+ [A-Za-z0-9_-]
 * characters (tokens, keys) is cut to its first four characters plus an
 * ellipsis, and the result is capped at 120 characters.
 */
function redact(text: string): string {
  const masked = text.replace(
    /[A-Za-z0-9_-]{20,}/g,
    (run) => `${run.slice(0, 4)}…`
  );
  return Array.from(masked).slice(0, 120).join("");
}

/** Human-readable form of one residue plan action (tagged by `type`). */
function describeAction(action: any): string {
  const kind = String(action?.kind ?? action?.type ?? "unknown");
  const content =
    action?.content != null ? `: ${redact(String(action.content))}` : "";
  switch (kind) {
    case "remove_line":
      return `remove line ${action.line} from ${action.path}${content}`;
    case "chmod": {
      const mode =
        typeof action.mode === "number"
          ? `0${action.mode.toString(8)}`
          : String(action.mode ?? "");
      return `chmod ${action.path} to ${mode}`;
    }
    case "remove_file":
      return `delete file ${action.path}`;
    case "remove_dir":
      return `delete directory ${action.path}`;
    case "remove_crontab_line":
      return `remove crontab line${content}`;
    default:
      return `${kind} ${action?.path ?? ""}`.trim();
  }
}

/**
 * Startup probe: warn (on stderr — stdout is the MCP transport) if the sigil
 * binary is missing. Never exits; CLI-backed tools degrade gracefully.
 */
function probeSigilBinary(): void {
  execFile(SIGIL_BINARY, ["--version"], { timeout: 10_000 }, (err) => {
    const code = (err as NodeJS.ErrnoException | null)?.code;
    if (code === "ENOENT") {
      console.error(
        `[sigil-mcp] warning: sigil binary "${SIGIL_BINARY}" not found. ` +
          `CLI-backed tools will return install instructions instead of scan results. ` +
          `Install with: ${INSTALL_ONE_LINER} — or set SIGIL_BINARY to the binary path.`
      );
    }
  });
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
  version: "1.3.0",
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
        "Comma-separated scan phases: install_hooks,code_patterns,network_exfil,credentials,obfuscation,provenance,prompt_injection,skill_security"
      ),
    severity: z
      .enum(["low", "medium", "high", "critical"])
      .optional()
      .describe("Minimum severity threshold"),
  },
  guardSigil(async ({ path, phases, severity }) => {
    const args = ["--format", "json", "scan", path];
    if (phases) args.push("--phases", phases);
    if (severity) args.push("--severity", severity);

    const result = await runSigilJson(args);

    return {
      content: [
        {
          type: "text" as const,
          text: summaryLine(result) + "\n" + findingLines(result) + DISCLAIMER,
        },
      ],
    };
  })
);

// ── Tool: grade ────────────────────────────────────────────────────────────

server.tool(
  "sigil_grade",
  "Letter grade (A-F), recommendation, behaviour profile and key risks for a path. Cheaper to read than sigil_scan when only the verdict matters.",
  {
    path: z.string().describe("File or directory path to grade"),
  },
  guardSigil(async ({ path }) => {
    const result = await runSigilJson(["--format", "json", "scan", path]);
    const s = summaryOf(result);
    const profile = (result?.profile ?? {}) as {
      behaviors?: unknown;
      key_risks?: unknown;
    };

    let text = `Grade: ${s.grade ?? "n/a"} | Verdict: ${s.verdict} | Score: ${s.score} | ${s.findings_count} findings`;
    if (s.recommendation) text += `\nRecommendation: ${s.recommendation}`;

    const behaviors = Array.isArray(profile.behaviors)
      ? profile.behaviors.map(String)
      : [];
    text += `\nBehaviours: ${behaviors.length ? behaviors.join(", ") : "none"}`;

    const risks = Array.isArray(profile.key_risks) ? profile.key_risks : [];
    if (risks.length > 0) {
      text += "\nKey risks:";
      for (const r of risks.slice(0, 5)) text += `\n  ${keyRiskLine(r)}`;
      if (risks.length > 5) text += `\n  ... and ${risks.length - 5} more`;
    }

    return {
      content: [{ type: "text" as const, text: text + DISCLAIMER }],
    };
  })
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
  guardSigil(async ({ manager, package_name, version }) => {
    const args = ["--format", "json", manager, package_name];
    if (version) args.push("--version", version);

    const result = await runSigilJson(args);

    const summary = `Package: ${manager}/${package_name}${version ? `@${version}` : ""}\n${summaryLine(result)}`;

    return {
      content: [
        {
          type: "text" as const,
          text: summary + "\n" + findingLines(result) + DISCLAIMER,
        },
      ],
    };
  })
);

// ── Tool: clone_and_scan ───────────────────────────────────────────────────

server.tool(
  "sigil_clone",
  "Clone a git repository into quarantine and scan it for security issues. Use this to audit repos before cloning them into your workspace.",
  {
    url: z.string().describe("Git repository URL"),
    branch: z.string().optional().describe("Specific branch to clone"),
  },
  guardSigil(async ({ url, branch }) => {
    const args = ["--format", "json", "clone", url];
    if (branch) args.push("--branch", branch);

    const result = await runSigilJson(args);

    const summary = `Repository: ${url}${branch ? ` (${branch})` : ""}\n${summaryLine(result)}`;

    return {
      content: [
        {
          type: "text" as const,
          text: summary + "\n" + findingLines(result) + DISCLAIMER,
        },
      ],
    };
  })
);

// ── Tool: quarantine_list ──────────────────────────────────────────────────

server.tool(
  "sigil_quarantine",
  "List all items currently in the Sigil quarantine, showing their scan status and verdict.",
  {},
  guardSigil(async () => {
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
  })
);

// ── Tool: approve / reject ─────────────────────────────────────────────────

server.tool(
  "sigil_approve",
  "Approve a quarantined item and move it to the working directory.",
  {
    quarantine_id: z.string().describe("Quarantine entry ID"),
  },
  guardSigil(async ({ quarantine_id }) => {
    const { stdout, stderr } = await runSigil(["approve", quarantine_id]);
    return {
      content: [
        { type: "text" as const, text: stdout || stderr || "Approved." },
      ],
    };
  })
);

server.tool(
  "sigil_reject",
  "Reject and delete a quarantined item.",
  {
    quarantine_id: z.string().describe("Quarantine entry ID"),
  },
  guardSigil(async ({ quarantine_id }) => {
    const { stdout, stderr } = await runSigil(["reject", quarantine_id]);
    return {
      content: [
        { type: "text" as const, text: stdout || stderr || "Rejected." },
      ],
    };
  })
);

// ── Tool: residue_scan ─────────────────────────────────────────────────────

server.tool(
  "sigil_residue_scan",
  "Scan THIS machine for what installed agent tooling left behind: shell rc edits, cron/launchd/systemd persistence, git hooks, world-readable credential files, leftover tool directories, /etc/hosts redirects, global agent packages. Read-only; nothing is changed.",
  {
    repo: z
      .string()
      .optional()
      .describe(
        "Path to a git repository whose hooks to include (default: the current directory when it is a repository)"
      ),
  },
  guardSigil(async ({ repo }) => {
    const args = ["--format", "json", "residue", "scan"];
    if (repo) args.push("--repo", repo);

    const report = await runSigilJson(args);
    const host = report?.host ?? {};
    const sum = report?.summary ?? {};
    const items: any[] = Array.isArray(report?.items) ? report.items : [];
    const skipped: any[] = Array.isArray(report?.checks_skipped)
      ? report.checks_skipped
      : [];

    let text = `Host: ${host.os ?? "unknown"} (home: ${host.home ?? "unknown"})`;
    text += `\nResidue: ${sum.items_count ?? items.length} item(s) — ${sum.critical ?? 0} critical, ${sum.high ?? 0} high, ${sum.medium ?? 0} medium, ${sum.low ?? 0} low, ${sum.info ?? 0} info`;
    if (sum.duration_ms != null) text += ` (${sum.duration_ms}ms)`;
    if (skipped.length > 0) {
      text += `\nChecks skipped: ${skipped
        .map((c) => `${c.id ?? c.check ?? "?"} (${c.reason ?? "no reason given"})`)
        .join("; ")}`;
    }

    if (items.length === 0) text += "\n\nNo residue found.";
    for (const it of items) {
      text += `\n\n[${String(it.severity ?? "info").toUpperCase()}] ${it.id} ${it.path ?? ""}${it.line != null ? `:${it.line}` : ""} — ${it.title}`;
      if (it.evidence) text += `\n  Evidence: ${String(it.evidence).slice(0, 200)}`;
      const fix = it.fix ?? it.remediation;
      if (fix) text += `\n  Fix: ${fix}`;
    }
    text += "\n\nRead-only: nothing on this machine was changed.";

    return {
      content: [{ type: "text" as const, text: text + DISCLAIMER }],
    };
  })
);

// ── Tool: residue_plan ─────────────────────────────────────────────────────
// Apply and rollback are deliberately not exposed as tools; a human runs
// `sigil residue apply` / `sigil residue rollback` in a terminal.

server.tool(
  "sigil_residue_plan",
  "Show the reversible fixes Sigil would make for host residue, without applying them. Apply and rollback are deliberately not exposed as tools; a human runs them in a terminal.",
  {
    repo: z
      .string()
      .optional()
      .describe(
        "Path to a git repository whose hooks to include (default: the current directory when it is a repository)"
      ),
  },
  guardSigil(async ({ repo }) => {
    const args = ["--format", "json", "residue", "plan"];
    if (repo) args.push("--repo", repo);

    const plan = await runSigilJson(args);
    const actions: any[] = Array.isArray(plan?.actions) ? plan.actions : [];
    const scanned =
      plan?.source_items != null ? ` (${plan.source_items} item(s) scanned)` : "";

    let text: string;
    if (actions.length === 0) {
      text = `Residue plan: no reversible fixes are needed${scanned}.`;
    } else {
      text = `Residue plan: ${actions.length} action(s)${scanned}:`;
      for (const a of actions) {
        text += `\n${a.n ?? "-"}. [${String(a.severity ?? "").toUpperCase()}] ${a.rule ?? ""} — ${a.title ?? ""}\n   ${describeAction(a.action)}`;
      }
    }
    text +=
      "\n\nNothing has been changed. Apply with `sigil residue apply` in a terminal (it backs everything up and can be undone with `sigil residue rollback`).";

    return {
      content: [{ type: "text" as const, text: text + DISCLAIMER }],
    };
  })
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
  "Report a malicious file to the Sigil threat intelligence database by its SHA256 hash. Requires the Sigil CLI and an authenticated session (sigil login). Reports are reviewed by the security team.",
  {
    sha256: z
      .string()
      .regex(/^[a-fA-F0-9]{64}$/, "must be a 64-character hex SHA256 hash")
      .describe("SHA256 hash of the malicious file"),
    threat_type: z
      .string()
      .describe("Type of threat (e.g. malware, backdoor, exfil)"),
    description: z.string().describe("Description of the threat"),
  },
  guardSigil(async ({ sha256, threat_type, description }) => {
    try {
      const { stdout, stderr } = await runSigil([
        "report",
        sha256,
        "--threat-type",
        threat_type,
        "--description",
        description,
      ]);
      return {
        content: [
          {
            type: "text" as const,
            text: stdout || stderr || "Threat report submitted.",
          },
        ],
      };
    } catch (err: unknown) {
      if (err instanceof SigilNotInstalledError) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      return {
        content: [
          {
            type: "text" as const,
            text: `Threat report failed: ${msg}\n\nNote: reporting requires authentication (run: sigil login). Manual invocation:\n  sigil report ${sha256} --threat-type "${threat_type}" --description "<description>"`,
          },
        ],
      };
    }
  })
);

// Forge tools removed - discovery feature sunset

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
   anomalies, unsigned commits, suspicious file permissions.

7. Prompt Injection (Critical, 10x weight)
   Detects AI agent instruction injection: hidden directives in
   READMEs, docs, comments, and tool descriptions that attempt to
   override or manipulate agent behavior.

8. Skill Security (High, 5x weight)
   Audits AI agent skills and MCP tooling: permission escalation,
   overbroad tool scopes, unsafe skill and server manifests.`,
      },
    ],
  })
);

// ── Start ──────────────────────────────────────────────────────────────────

async function main() {
  probeSigilBinary();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Sigil MCP server failed to start:", err);
  process.exit(1);
});
