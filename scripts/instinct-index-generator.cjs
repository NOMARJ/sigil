#!/usr/bin/env node
/**
 * Instinct Index Generator
 * Reads tasks/instincts/index.json and generates a compact
 * ## instinct-index section for progress.md (~15 tokens per instinct).
 *
 * Usage: node scripts/instinct-index-generator.cjs
 * Output: writes to stdout (caller appends to progress.md)
 *
 * Format: ID | pattern | conf | obs | status
 * Status codes: P=pending, V=proven, M=promoted, D=dormant
 */
const fs = require("fs");
const path = require("path");

const ROOT = process.cwd();
const INDEX_PATH = path.join(ROOT, "tasks", "instincts", "index.json");

function main() {
  let index;
  try {
    index = JSON.parse(fs.readFileSync(INDEX_PATH, "utf8"));
  } catch (e) {
    process.stderr.write(`[INSTINCT-INDEX] Cannot read ${INDEX_PATH}: ${e.message}\n`);
    process.exit(1);
  }

  const entries = Object.entries(index.instincts || {});
  if (entries.length === 0) {
    console.log("## instinct-index\n\nNo instincts recorded.\n");
    return;
  }

  const statusCode = { pending: "P", proven: "V", promoted: "M", dormant: "D" };

  const lines = ["## instinct-index", ""];
  lines.push("| ID | Pattern | Conf | Obs | St |");
  lines.push("|-----|---------|------|-----|-----|");

  for (const [id, inst] of entries) {
    if (inst.status === "dormant") continue;

    const shortId = id.replace("inst-", "");
    const pattern = (inst.tags || []).slice(0, 3).join(", ");
    const conf = (inst.confidence || 0).toFixed(1);
    const obs = inst.observations || 0;
    const st = statusCode[inst.status] || "?";

    lines.push(`| ${shortId} | ${pattern} | ${conf} | ${obs} | ${st} |`);
  }

  const dormant = entries.filter(([, i]) => i.status === "dormant").length;
  lines.push("");
  lines.push(`${entries.length} instincts (${index.stats?.proven || 0} proven, ${dormant} dormant excluded)`);
  lines.push("");

  console.log(lines.join("\n"));
}

main();
