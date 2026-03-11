"""
Initiative 2 — State of Agent Skill Security: Analysis Script

Connects to Azure SQL Database (MSSQL) using pyodbc (sync) and prints a
structured report covering:

  1. Total skills scanned (ecosystem='skills')
  2. Verdict distribution
  3. Detection delta count — Sigil HIGH/CRITICAL, all providers safe/null
  4. Phase breakdown — which scan phases fire and which have no provider overlap
  5. Top 10 publishers by average risk score

Usage:
    python scripts/initiative2_analysis.py

Environment:
    SIGIL_DATABASE_URL — ODBC connection string (falls back to hardcoded default)
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict
from typing import Any

import pyodbc

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_DSN = (
    "Driver={ODBC Driver 18 for SQL Server};"
    "Server=tcp:sigil-sql-w2-46iy6y.database.windows.net,1433;"
    "Database=sigil;"
    "Uid=sigil_admin;"
    "Pwd=zKwTAOb3b3KXC1U6SvmJCnAuO;"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
)

# Phases emitted by the Sigil engine (keys found inside findings_json items)
_PHASE_KEYS = [
    "install_hooks",
    "code_patterns",
    "network_exfil",
    "credentials",
    "obfuscation",
    "provenance",
]

# Provider verdict values considered "benign" for detection-delta logic
_BENIGN_VERDICTS = {"safe", "low_risk", "unknown"}

# Provider names as stored in provider_assessments_json / gen_verdict etc.
_PROVIDERS = ["gen", "socket", "snyk"]


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def _get_connection() -> pyodbc.Connection:
    dsn = os.environ.get("SIGIL_DATABASE_URL", _DEFAULT_DSN)
    return pyodbc.connect(dsn)


def _fetchall(conn: pyodbc.Connection, sql: str) -> list[dict[str, Any]]:
    cursor = conn.cursor()
    cursor.execute(sql)
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _parse_json_field(row: dict[str, Any], field: str) -> Any:
    """Safely parse a JSON string field; return None on failure."""
    raw = row.get(field)
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------


def section_total_skills(conn: pyodbc.Connection) -> int:
    rows = _fetchall(
        conn,
        "SELECT COUNT(*) AS cnt FROM public_scans WHERE ecosystem = 'skills'",
    )
    return rows[0]["cnt"] if rows else 0


def section_verdict_distribution(conn: pyodbc.Connection) -> dict[str, int]:
    rows = _fetchall(
        conn,
        """
        SELECT verdict, COUNT(*) AS cnt
        FROM public_scans
        WHERE ecosystem = 'skills'
        GROUP BY verdict
        ORDER BY cnt DESC
        """,
    )
    return {r["verdict"]: r["cnt"] for r in rows}


def section_detection_delta(conn: pyodbc.Connection) -> int:
    """Count rows in the detection_delta view (falls back to inline query)."""
    try:
        rows = _fetchall(conn, "SELECT COUNT(*) AS cnt FROM detection_delta")
        return rows[0]["cnt"] if rows else 0
    except pyodbc.Error:
        # View may not exist yet — run equivalent inline query
        rows = _fetchall(
            conn,
            """
            SELECT COUNT(*) AS cnt
            FROM public_scans
            WHERE ecosystem = 'skills'
              AND verdict IN ('HIGH_RISK', 'CRITICAL')
              AND (gen_verdict    IS NULL OR gen_verdict    IN ('safe', 'low_risk', 'unknown'))
              AND (socket_verdict IS NULL OR socket_verdict IN ('safe', 'low_risk', 'unknown'))
              AND (snyk_verdict   IS NULL OR snyk_verdict   IN ('safe', 'low_risk', 'unknown'))
            """,
        )
        return rows[0]["cnt"] if rows else 0


def section_phase_breakdown(
    conn: pyodbc.Connection,
) -> dict[str, dict[str, Any]]:
    """
    Parse findings_json for every skills scan and count how many scans each
    phase contributed findings to.  Also determine which phases have NO
    overlap with provider flags (i.e. they exclusively appear in detection-delta
    rows where all providers are benign/null).

    Returns a dict keyed by phase name:
        {
            "total_scans_with_findings": int,
            "delta_scans_with_findings": int,
            "no_provider_overlap": bool,
        }
    """
    # Fetch all skills scans — only the columns we need
    rows = _fetchall(
        conn,
        """
        SELECT
            verdict,
            findings_json,
            gen_verdict,
            socket_verdict,
            snyk_verdict
        FROM public_scans
        WHERE ecosystem = 'skills'
        """,
    )

    # Per-phase counters
    phase_all: Counter[str] = Counter()
    phase_delta: Counter[str] = Counter()

    for row in rows:
        findings = _parse_json_field(row, "findings_json")
        if not isinstance(findings, list) or not findings:
            continue

        # Determine which phases have findings in this scan
        phases_with_findings: set[str] = set()
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            phase = finding.get("phase") or finding.get("type") or finding.get("category")
            if phase and phase in _PHASE_KEYS:
                phases_with_findings.add(phase)

        if not phases_with_findings:
            continue

        # Is this a detection-delta row?
        verdict = row.get("verdict", "")
        gen_v = row.get("gen_verdict")
        sock_v = row.get("socket_verdict")
        snyk_v = row.get("snyk_verdict")

        is_sigil_high = verdict in ("HIGH_RISK", "CRITICAL")
        gen_benign = gen_v is None or gen_v in _BENIGN_VERDICTS
        sock_benign = sock_v is None or sock_v in _BENIGN_VERDICTS
        snyk_benign = snyk_v is None or snyk_v in _BENIGN_VERDICTS
        is_delta = is_sigil_high and gen_benign and sock_benign and snyk_benign

        for phase in phases_with_findings:
            phase_all[phase] += 1
            if is_delta:
                phase_delta[phase] += 1

    result: dict[str, dict[str, Any]] = {}
    for phase in _PHASE_KEYS:
        total = phase_all[phase]
        delta = phase_delta[phase]
        # "No provider overlap" means every scan where this phase fires is in
        # the delta set — i.e. providers never flag these.
        no_overlap = total > 0 and total == delta
        result[phase] = {
            "total_scans_with_findings": total,
            "delta_scans_with_findings": delta,
            "no_provider_overlap": no_overlap,
        }

    return result


def section_top_publishers(
    conn: pyodbc.Connection, n: int = 10
) -> list[dict[str, Any]]:
    """
    Parse the package_name field (format: "owner/repo/skill-name") to extract
    the owner, then rank owners by average risk_score descending.

    Returns a list of dicts: [{"owner": str, "scans": int, "avg_risk": float}]
    """
    rows = _fetchall(
        conn,
        """
        SELECT package_name, risk_score
        FROM public_scans
        WHERE ecosystem = 'skills'
        """,
    )

    owner_scores: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        name = row.get("package_name") or ""
        parts = name.split("/")
        owner = parts[0] if parts else "unknown"
        if owner:
            score = row.get("risk_score") or 0.0
            owner_scores[owner].append(float(score))

    ranked = sorted(
        [
            {
                "owner": owner,
                "scans": len(scores),
                "avg_risk": round(sum(scores) / len(scores), 2),
            }
            for owner, scores in owner_scores.items()
        ],
        key=lambda x: x["avg_risk"],
        reverse=True,
    )
    return ranked[:n]


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _hr(char: str = "-", width: int = 60) -> str:
    return char * width


def _print_header(title: str) -> None:
    print()
    print(_hr("="))
    print(f"  {title}")
    print(_hr("="))


def _print_section(title: str) -> None:
    print()
    print(_hr("-"))
    print(f"  {title}")
    print(_hr("-"))


# ---------------------------------------------------------------------------
# Main report
# ---------------------------------------------------------------------------


def run_report() -> None:
    print(_hr("="))
    print("  INITIATIVE 2 — State of Agent Skill Security")
    print("  Sigil Detection Analysis Report")
    print(_hr("="))

    try:
        conn = _get_connection()
    except pyodbc.Error as exc:
        print(f"\n[ERROR] Could not connect to database: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        # ------------------------------------------------------------------
        # 1. Total skills scanned
        # ------------------------------------------------------------------
        _print_section("1. Total Skills Scanned")
        total = section_total_skills(conn)
        print(f"  Skills scanned (ecosystem='skills'): {total:,}")

        # ------------------------------------------------------------------
        # 2. Verdict distribution
        # ------------------------------------------------------------------
        _print_section("2. Verdict Distribution")
        distribution = section_verdict_distribution(conn)
        if distribution:
            max_label = max(len(k) for k in distribution)
            for verdict, count in distribution.items():
                pct = (count / total * 100) if total else 0.0
                bar = "#" * int(pct / 2)
                print(f"  {verdict:<{max_label}}  {count:>6,}  ({pct:5.1f}%)  {bar}")
        else:
            print("  No data.")

        # ------------------------------------------------------------------
        # 3. Detection delta
        # ------------------------------------------------------------------
        _print_section("3. Detection Delta")
        delta_count = section_detection_delta(conn)
        pct_delta = (delta_count / total * 100) if total else 0.0
        print(
            f"  Sigil HIGH/CRITICAL with all providers safe/null: "
            f"{delta_count:,} ({pct_delta:.1f}% of total)"
        )
        print()
        print(
            "  These are skills that Sigil's specialised agent-skill engine flags"
        )
        print(
            "  as high risk but Gen, Socket, and Snyk consider safe or have not assessed."
        )

        # ------------------------------------------------------------------
        # 4. Phase breakdown
        # ------------------------------------------------------------------
        _print_section("4. Phase Breakdown")
        phases = section_phase_breakdown(conn)
        if any(v["total_scans_with_findings"] > 0 for v in phases.values()):
            col_w = 20
            print(
                f"  {'Phase':<{col_w}}  {'All Scans':>10}  {'Delta Scans':>12}  "
                f"{'Delta %':>8}  No Provider Overlap"
            )
            print(f"  {_hr('-', col_w)}  {'----------':>10}  {'------------':>12}  {'-------':>8}  -------------------")
            for phase in _PHASE_KEYS:
                data = phases[phase]
                all_cnt = data["total_scans_with_findings"]
                delta_cnt = data["delta_scans_with_findings"]
                if all_cnt == 0:
                    delta_pct = 0.0
                else:
                    delta_pct = delta_cnt / all_cnt * 100
                no_overlap = "YES  <-- exclusive to Sigil" if data["no_provider_overlap"] else "no"
                print(
                    f"  {phase:<{col_w}}  {all_cnt:>10,}  {delta_cnt:>12,}  "
                    f"{delta_pct:>7.1f}%  {no_overlap}"
                )
            print()
            print("  'No Provider Overlap' = every scan where this phase fires is in the")
            print("  detection delta (providers never independently flag these patterns).")
        else:
            print(
                "  No phase data available — findings_json may be empty or phases may not"
            )
            print("  use the expected 'phase' key in finding objects.")

        # ------------------------------------------------------------------
        # 5. Top 10 publishers by risk score
        # ------------------------------------------------------------------
        _print_section("5. Top 10 Publishers by Average Risk Score")
        publishers = section_top_publishers(conn)
        if publishers:
            print(f"  {'Rank':<6}  {'Owner':<30}  {'Scans':>6}  {'Avg Risk':>9}")
            print(f"  {'----':<6}  {'-----':<30}  {'------':>6}  {'---------':>9}")
            for i, pub in enumerate(publishers, 1):
                print(
                    f"  {i:<6}  {pub['owner']:<30}  {pub['scans']:>6,}  {pub['avg_risk']:>9.2f}"
                )
        else:
            print("  No publisher data available.")

    finally:
        conn.close()

    print()
    print(_hr("="))
    print("  Report complete.")
    print(_hr("="))
    print()


if __name__ == "__main__":
    run_report()
