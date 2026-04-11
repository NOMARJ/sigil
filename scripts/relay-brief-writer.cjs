#!/usr/bin/env node
/**
 * Relay Brief Writer
 * Constructs a valid continuation brief from live session state.
 * Called by autopilot at context boundaries.
 *
 * Usage:
 *   node scripts/relay-brief-writer.cjs --feature <slug> --prd <path> --depth <n> [--session <id>]
 *
 * Reads: progress.md, .nomark/metrics/trust/score.json, .nomark/config.json
 * Writes: .nomark/briefs/relay-{date}-{slug}-d{depth}.json
 * Validates against: .nomark/schemas/continuation-brief.json
 *
 * Part of F-032 — Relay Runtime
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = process.cwd();

function parseArgs() {
  const args = process.argv.slice(2);
  const parsed = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i].replace(/^--/, "");
    parsed[key] = args[i + 1];
  }
  return parsed;
}

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

function hashFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    return crypto.createHash("sha256").update(content).digest("hex");
  } catch {
    return null;
  }
}

function parseProgressMd() {
  const progressPath = path.join(ROOT, "progress.md");
  const content = fs.readFileSync(progressPath, "utf8");
  const lines = content.split("\n");

  const stories = [];
  let currentStory = null;
  let inProgressStory = null;

  for (const line of lines) {
    const storyMatch = line.match(/^### (US-\d{3}): (.+?) \[scope: (\w+)\]/);
    if (storyMatch) {
      if (currentStory) stories.push(currentStory);
      currentStory = {
        id: storyMatch[1],
        title: storyMatch[2],
        scope: storyMatch[3],
        status: "TODO",
        linear_id: null,
        files: [],
        dependencies: [],
      };
      continue;
    }

    if (currentStory) {
      const statusMatch = line.match(/\*\*Status:\*\* (\w[\w ]*)/);
      if (statusMatch) currentStory.status = statusMatch[1].trim();

      const linearMatch = line.match(/\*\*Linear:\*\* (NOM-\d+)/);
      if (linearMatch) currentStory.linear_id = linearMatch[1];

      const filesMatch = line.match(/\*\*Files:\*\* (.+)/);
      if (filesMatch) {
        currentStory.files = filesMatch[1]
          .split(",")
          .map(f => f.trim().replace(/`/g, ""))
          .filter(Boolean);
      }

      const depsMatch = line.match(/\*\*Dependencies:\*\* (.+)/);
      if (depsMatch) {
        currentStory.dependencies = depsMatch[1]
          .split(",")
          .map(d => d.trim())
          .filter(Boolean);
      }
    }
  }
  if (currentStory) stories.push(currentStory);

  const remaining = stories.filter(s => s.status === "TODO" || s.status === "IN PROGRESS" || s.status === "BLOCKED");
  inProgressStory = stories.find(s => s.status === "IN PROGRESS") || null;

  return { remaining, inProgressStory, allStories: stories };
}

function extractCapabilities(stories, config) {
  const caps = new Set(["filesystem", "git"]);

  for (const story of stories) {
    for (const file of story.files) {
      if (file.includes("hooks/") || file.includes("scripts/")) caps.add("local-toolchain:node");
      if (file.includes("docker") || file.includes("Docker")) caps.add("docker");
      if (file.includes("terraform") || file.includes(".tf")) caps.add("cloud-cli:azure");
    }

    const title = story.title.toLowerCase();
    if (title.includes("slack") || title.includes("notification")) caps.add("mcp:slack");
    if (title.includes("linear")) caps.add("mcp:linear");
    if (title.includes("n8n")) caps.add("mcp:n8n");
    if (title.includes("vercel") || title.includes("deploy")) caps.add("mcp:vercel");
    if (title.includes("approval") || title.includes("charter gate")) caps.add("interactive-approval");
  }

  return Array.from(caps);
}

function determineSpawnMechanism(capabilities, config) {
  const needsLocal = capabilities.some(c =>
    c === "docker" || c === "browser" || c === "interactive-approval"
  );

  if (needsLocal) {
    return {
      preferred: "cli_spawn",
      reason: "stories require local-only capabilities: " + capabilities.filter(c => c === "docker" || c === "browser" || c === "interactive-approval").join(", "),
      fallback: "brief_and_notify",
    };
  }

  const isTTY = process.stdout.isTTY;
  const ownerPresence = config.owner_presence?.detection === "tty" ? isTTY : false;

  if (ownerPresence) {
    return {
      preferred: "cli_spawn",
      reason: "owner present (TTY detected), CLI spawn for live visibility",
      fallback: "brief_and_notify",
    };
  }

  return {
    preferred: "cli_spawn",
    reason: "default to CLI spawn (RemoteTrigger not yet wired)",
    fallback: "brief_and_notify",
  };
}

function main() {
  const args = parseArgs();
  const featureSlug = args.feature;
  const prdPath = args.prd;
  const depth = parseInt(args.depth || "1", 10);
  const sessionId = args.session || `session-${Date.now()}`;

  if (!featureSlug || !prdPath) {
    process.stderr.write("Usage: relay-brief-writer.cjs --feature <slug> --prd <path> --depth <n>\n");
    process.exit(1);
  }

  const config = readJson(path.join(ROOT, ".nomark", "config.json"), {});
  const trustScore = readJson(path.join(ROOT, ".nomark", "metrics", "trust", "score.json"), { current: 0, autonomy_level: "restricted" });

  const maxDepthFull = config.relay?.max_depth_full || 5;
  const maxDepthSupervised = config.relay?.max_depth_supervised || 3;
  const trust = trustScore.current || 0;
  let maxDepth;
  if (trust >= 0.8) maxDepth = maxDepthFull;
  else if (trust >= 0.5) maxDepth = maxDepthSupervised;
  else maxDepth = 0;

  if (trust < 0.5) {
    process.stderr.write(`[RELAY] Trust ${trust} < 0.5 — self-continuation blocked. Writing brief as pending for manual pickup.\n`);
  }

  if (depth > maxDepth && maxDepth > 0) {
    process.stderr.write(`[RELAY] Depth ${depth} exceeds max ${maxDepth} for trust ${trust}. Writing brief as pending.\n`);
  }

  const { remaining, inProgressStory } = parseProgressMd();

  if (remaining.length === 0) {
    process.stderr.write("[RELAY] No remaining stories. Nothing to relay.\n");
    process.exit(0);
  }

  const fileHashes = {};
  for (const story of remaining) {
    for (const file of story.files) {
      const fullPath = path.join(ROOT, file);
      const hash = hashFile(fullPath);
      if (hash) fileHashes[file] = hash;
    }
  }

  const capabilities = extractCapabilities(remaining, config);
  const spawn = determineSpawnMechanism(capabilities, config);

  const prdContent = readJson(path.join(ROOT, prdPath), null);
  let acceptanceCriteria = [];
  if (prdContent && prdContent.acceptance_criteria) {
    acceptanceCriteria = prdContent.acceptance_criteria;
  }

  const featureRef = remaining[0]?.linear_id ? remaining[0].linear_id.replace(/NOM-\d+/, "F-032") : "F-032";

  const date = new Date().toISOString().split("T")[0];
  const briefId = `BRF-${date}-${featureSlug}`;
  const briefFileName = `relay-${date}-${featureSlug}-d${depth}.json`;
  const briefPath = path.join(ROOT, ".nomark", "briefs", briefFileName);

  const brief = {
    id: briefId,
    version: "2.0",
    created_at: new Date().toISOString(),
    created_by: sessionId,
    source: {
      repo: "nomark",
      session: sessionId,
      trigger: "context-boundary",
    },
    target: {
      repo: "nomark",
      capability: "fullstack",
    },
    intent: `Continue ${featureSlug} from ${inProgressStory ? inProgressStory.id : "next TODO story"}. ${remaining.length} stories remaining.`,
    type: "continuation",
    priority: "normal",
    acceptance_criteria: acceptanceCriteria,
    context: {
      linear_id: null,
      feature_ref: "F-032",
      prd_path: prdPath,
      related_commits: [],
      related_briefs: [],
      notes: `Relay depth ${depth}. Trust at relay: ${trust}. Mechanism: ${spawn.preferred}.`,
    },
    governance: {
      max_scope: "feature",
      requires_approval: [],
      charter_constraints: ["CHARTER II.4", "CHARTER II.5"],
    },
    status: trust < 0.5 ? "pending" : "pending",
    claimed_by: null,
    claimed_at: null,
    completed_at: null,
    completion_ref: null,
    relay: {
      depth,
      max_depth: maxDepth,
      parent_session: sessionId,
      chain: [],
      required_capabilities: capabilities,
      preferred_mechanism: spawn.preferred,
      reason: spawn.reason,
      fallback: spawn.fallback,
      trust_at_relay: trust,
      enforcer_verdict: null,
      enforcer_notes: null,
    },
    resume: {
      remaining_stories: remaining.map(s => ({
        id: s.id,
        title: s.title,
        status: s.status,
        scope: s.scope,
        linear_id: s.linear_id,
        dependencies: s.dependencies,
      })),
      in_progress_story: inProgressStory
        ? {
            id: inProgressStory.id,
            current_state: "Story was IN PROGRESS when relay triggered",
            phase: "unknown",
            files_modified: inProgressStory.files,
            last_test_output: null,
          }
        : null,
      file_hashes: fileHashes,
      progress_md_snapshot: "progress.md",
    },
  };

  const briefsDir = path.join(ROOT, ".nomark", "briefs");
  if (!fs.existsSync(briefsDir)) {
    fs.mkdirSync(briefsDir, { recursive: true });
  }

  fs.writeFileSync(briefPath, JSON.stringify(brief, null, 2));

  try {
    const schema = readJson(path.join(ROOT, ".nomark", "schemas", "continuation-brief.json"), null);
    if (schema) {
      const requiredFields = schema.required || [];
      const missing = requiredFields.filter(f => !(f in brief));
      if (missing.length > 0) {
        process.stderr.write(`[RELAY] Schema validation warning: missing fields: ${missing.join(", ")}\n`);
        process.exit(1);
      }

      const relayRequired = schema.properties?.relay?.required || [];
      const missingRelay = relayRequired.filter(f => !(f in brief.relay));
      if (missingRelay.length > 0) {
        process.stderr.write(`[RELAY] Schema validation warning: missing relay fields: ${missingRelay.join(", ")}\n`);
        process.exit(1);
      }

      const resumeRequired = schema.properties?.resume?.required || [];
      const missingResume = resumeRequired.filter(f => !(f in brief.resume));
      if (missingResume.length > 0) {
        process.stderr.write(`[RELAY] Schema validation warning: missing resume fields: ${missingResume.join(", ")}\n`);
        process.exit(1);
      }
    }
  } catch (e) {
    process.stderr.write(`[RELAY] Schema validation skipped: ${e.message}\n`);
  }

  process.stderr.write(
    `[RELAY] Brief written: ${briefFileName}\n` +
    `[RELAY] Stories remaining: ${remaining.length}\n` +
    `[RELAY] Trust: ${trust} | Depth: ${depth}/${maxDepth} | Mechanism: ${spawn.preferred}\n` +
    `[RELAY] Capabilities: ${capabilities.join(", ")}\n`
  );

  process.stdout.write(briefPath);
  process.exit(0);
}

main();
