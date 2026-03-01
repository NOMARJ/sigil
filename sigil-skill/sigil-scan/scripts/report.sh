#!/usr/bin/env bash
# report.sh — Format scan JSON into a readable markdown report.
# Accepts JSON via stdin or as a file path argument.
# Outputs markdown to stdout. Status messages to stderr.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/_lib.sh"

# ── Read input ─────────────────────────────────────────────────────────────

INPUT=""
if [ -n "${1:-}" ] && [ -f "$1" ]; then
  INPUT="$(cat "$1")"
elif [ ! -t 0 ]; then
  INPUT="$(cat)"
else
  die "Usage: report.sh <scan-result.json> or pipe JSON via stdin"
fi

if [ -z "$INPUT" ]; then
  die "No input provided"
fi

# ── Format with jq or python3 ────────────────────────────────────────────

format_with_jq() {
  echo "$INPUT" | jq -r '
    def badge:
      if . == "CRITICAL" or . == "CRITICAL RISK" or . == "CRITICAL_RISK" then "CRITICAL"
      elif . == "HIGH RISK" or . == "HIGH_RISK" then "HIGH RISK"
      elif . == "MEDIUM RISK" or . == "MEDIUM_RISK" then "MEDIUM RISK"
      elif . == "CLEAN" then "CLEAN"
      else "LOW RISK"
      end;

    def severity_icon:
      if . == "Critical" or . == "critical" then "!!!"
      elif . == "High" or . == "high" then "!!"
      elif . == "Medium" or . == "medium" then "!"
      else "."
      end;

    "# Sigil Scan Report",
    "",
    "**Target:** \(.target // "unknown")",
    "**Verdict:** [\(.verdict | badge)]",
    "**Risk Score:** \(.score // 0)",
    "**Files Scanned:** \(.files_scanned // 0)",
    "**Duration:** \(.duration_ms // 0)ms",
    "",
    "---",
    "",
    "## Phase Summary",
    "",
    "| Phase | Findings | Severity |",
    "|-------|----------|----------|",
    (if .phases then
      (.phases | to_entries[] | "| \(.key) | \(.value.findings) | \(.value.severity) |")
    else
      "| (no phase data) | - | - |"
    end),
    "",
    "---",
    "",
    "## Findings",
    "",
    if (.findings | length) == 0 then
      "No findings detected."
    else
      (
        "| Severity | Rule | File | Description |",
        "|----------|------|------|-------------|",
        (.findings | sort_by(
          if .severity == "Critical" then 0
          elif .severity == "High" then 1
          elif .severity == "Medium" then 2
          else 3 end
        )[] | "| \(.severity) | \(.rule) | \(.file)\(if .line then ":\(.line)" else "" end) | \(.snippet | gsub("\n"; " ") | .[:80]) |")
      )
    end,
    "",
    "---",
    "",
    "*Sigil provides risk assessments based on automated pattern detection. Risk assessments do not constitute a guarantee of security or a definitive determination of malicious intent.*"
  ' 2>/dev/null
}

format_with_python() {
  echo "$INPUT" | python3 -c '
import json, sys

data = json.load(sys.stdin)
verdict = data.get("verdict", "UNKNOWN")
target = data.get("target", "unknown")
score = data.get("score", 0)
files = data.get("files_scanned", 0)
duration = data.get("duration_ms", 0)
findings = data.get("findings", [])
phases = data.get("phases", {})

print("# Sigil Scan Report")
print()
print(f"**Target:** {target}")
print(f"**Verdict:** [{verdict}]")
print(f"**Risk Score:** {score}")
print(f"**Files Scanned:** {files}")
print(f"**Duration:** {duration}ms")
print()
print("---")
print()
print("## Phase Summary")
print()
print("| Phase | Findings | Severity |")
print("|-------|----------|----------|")
for phase, info in phases.items():
    print(f"| {phase} | {info.get(\"findings\", 0)} | {info.get(\"severity\", \"clean\")} |")
print()
print("---")
print()
print("## Findings")
print()

if not findings:
    print("No findings detected.")
else:
    print("| Severity | Rule | File | Description |")
    print("|----------|------|------|-------------|")
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for f in sorted(findings, key=lambda x: severity_order.get(x.get("severity", "Low"), 3)):
        file_loc = f.get("file", "")
        if f.get("line"):
            file_loc += f":{f[\"line\"]}"
        snippet = f.get("snippet", "").replace("\n", " ")[:80]
        print(f"| {f.get(\"severity\", \"\")} | {f.get(\"rule\", \"\")} | {file_loc} | {snippet} |")

print()
print("---")
print()
print("*Sigil provides risk assessments based on automated pattern detection. Risk assessments do not constitute a guarantee of security or a definitive determination of malicious intent.*")
' 2>/dev/null
}

# ── Main ───────────────────────────────────────────────────────────────────

if command -v jq >/dev/null 2>&1; then
  format_with_jq
elif command -v python3 >/dev/null 2>&1; then
  format_with_python
else
  die "report.sh requires jq or python3 for JSON parsing"
fi
