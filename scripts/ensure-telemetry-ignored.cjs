#!/usr/bin/env node
// ensure-telemetry-ignored.cjs
//
// Idempotent. Makes sure the current repo's .gitignore contains the NOMARK
// telemetry block, and untracks any telemetry files that were tracked before
// the block existed. Safe to run anywhere, anytime — this is the per-repo
// setup step that /sync code pull doesn't otherwise do (sync never touches
// .gitignore).
//
// Usage:
//   node scripts/ensure-telemetry-ignored.cjs           # fix mode (default)
//   node scripts/ensure-telemetry-ignored.cjs --check   # check only, exit 1 on drift
//
// Exit codes:
//   0  — success (fix: applied or no-op; check: clean)
//   1  — check mode only: drift detected (telemetry tracked or marker missing)
//   2  — fatal error (no git repo, fs failure)

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const REPO_ROOT = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const GITIGNORE = path.join(REPO_ROOT, ".gitignore");

const MARKER_BEGIN = "# BEGIN NOMARK telemetry ignore — managed by scripts/ensure-telemetry-ignored.cjs";
const MARKER_END = "# END NOMARK telemetry ignore";

// Canonical list. Edit here; next sync propagates to every project.
const TELEMETRY_PATHS = [
  ".nomark/metrics/trust/events/",
  ".nomark/metrics/trust/graph.json",
  ".nomark/metrics/trust/ledger.jsonl",
  ".nomark/metrics/trust/pending-audit.json",
  ".nomark/metrics/trust/preferences/preferences.json",
  ".nomark/metrics/trust/reports/",
  ".nomark/metrics/trust/score.json",
  ".nomark/metrics/drift.json",
  ".nomark/metrics/costs.jsonl",
  ".nomark/metrics/relay-log.jsonl",
  ".nomark/observations/",
  "tasks/instincts/pending/",
  "tasks/instincts/index.json",
];

function buildBlock() {
  const header =
    "# NOMARK telemetry — high-churn session state, flows to portfolio via graph-portfolio-sync.\n" +
    "# Do not hand-commit these paths. Edit the canonical list in scripts/ensure-telemetry-ignored.cjs.";
  return [MARKER_BEGIN, header, ...TELEMETRY_PATHS, MARKER_END].join("\n");
}

function isGitRepo() {
  try {
    execSync("git rev-parse --is-inside-work-tree", {
      cwd: REPO_ROOT,
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

function ensureBlock() {
  let contents = "";
  let existed = true;
  try {
    contents = fs.readFileSync(GITIGNORE, "utf8");
  } catch {
    existed = false;
  }

  if (contents.includes(MARKER_BEGIN)) {
    return { action: "present", existed };
  }

  const sep = contents.length && !contents.endsWith("\n") ? "\n\n" : contents.length ? "\n" : "";
  const next = contents + sep + buildBlock() + "\n";
  fs.writeFileSync(GITIGNORE, next);
  return { action: "added", existed };
}

function untrackTelemetry() {
  const untracked = [];
  const skipped = [];
  for (const p of TELEMETRY_PATHS) {
    const tracked = (() => {
      try {
        const out = execSync(`git ls-files -- "${p}"`, {
          cwd: REPO_ROOT,
          encoding: "utf8",
        });
        return out.trim().length > 0;
      } catch {
        return false;
      }
    })();
    if (!tracked) {
      skipped.push(p);
      continue;
    }
    try {
      execSync(`git rm -r --cached --quiet -- "${p}"`, {
        cwd: REPO_ROOT,
        stdio: "ignore",
      });
      untracked.push(p);
    } catch (err) {
      skipped.push(`${p} (rm failed: ${err.message.split("\n")[0]})`);
    }
  }
  return { untracked, skipped };
}

function checkOnly() {
  let gitignore = "";
  try {
    gitignore = fs.readFileSync(GITIGNORE, "utf8");
  } catch {}
  const markerMissing = !gitignore.includes(MARKER_BEGIN);

  const trackedTelemetry = [];
  for (const p of TELEMETRY_PATHS) {
    try {
      const out = execSync(`git ls-files -- "${p}"`, {
        cwd: REPO_ROOT,
        encoding: "utf8",
      });
      if (out.trim().length > 0) trackedTelemetry.push(p);
    } catch {}
  }

  if (!markerMissing && trackedTelemetry.length === 0) {
    process.stdout.write("[telemetry-ignore] check: clean\n");
    process.exit(0);
  }

  process.stderr.write("[telemetry-ignore] check: DRIFT DETECTED\n");
  if (markerMissing) {
    process.stderr.write("  .gitignore missing NOMARK telemetry marker block\n");
  }
  for (const p of trackedTelemetry) {
    process.stderr.write(`  tracked telemetry: ${p}\n`);
  }
  process.stderr.write(
    "[telemetry-ignore] fix: run `node scripts/ensure-telemetry-ignored.cjs` locally, commit, push\n"
  );
  process.exit(1);
}

function main() {
  if (!isGitRepo()) {
    process.stderr.write("[telemetry-ignore] not a git repo — skipping\n");
    process.exit(0);
  }

  const checkMode = process.argv.includes("--check");
  if (checkMode) {
    checkOnly();
    return;
  }

  const block = ensureBlock();
  const { untracked } = untrackTelemetry();

  const summary = [
    `[telemetry-ignore] .gitignore: ${block.action}`,
    `untracked: ${untracked.length}`,
  ].join(" | ");
  process.stdout.write(summary + "\n");

  if (untracked.length > 0) {
    process.stdout.write(
      "  " + untracked.join("\n  ") + "\n" +
      "[telemetry-ignore] review and commit: git status && git commit -m 'chore: untrack NOMARK telemetry'\n"
    );
  }

  process.exit(0);
}

main();
