#!/usr/bin/env python3
"""
Safe bulk classification with comprehensive duplicate handling.
Uses MERGE operation to handle duplicates gracefully.
"""

import pyodbc
import json
import uuid
from datetime import datetime, timezone
import sys
import time

# Database connection
SERVER = "sigil-sql-w2-46iy6y.database.windows.net"
DATABASE = "sigil"
USERNAME = "sigil_admin"
PASSWORD = "hUkVA6s1G7z4Smqf!"


def get_connection():
    """Get database connection with optimized settings."""
    conn_str = (
        f"Driver={{ODBC Driver 18 for SQL Server}};"
        f"Server=tcp:{SERVER},1433;"
        f"Database={DATABASE};"
        f"Uid={USERNAME};"
        f"Pwd={PASSWORD};"
        f"Encrypt=yes;"
        f"TrustServerCertificate=no;"
        f"Connection Timeout=30;"
    )
    return pyodbc.connect(conn_str)


def classify_package(
    package_name, ecosystem, version, risk_score, findings_count, verdict
):
    """Enhanced classification logic with comprehensive categorization."""

    package_name_lower = (package_name or "").lower()

    # Determine category and subcategory
    category = "general"
    subcategory = "utility"

    # MCP packages (highest priority)
    if "mcp" in package_name_lower or "model-context" in package_name_lower:
        category = "mcp"
        if "server" in package_name_lower:
            subcategory = "mcp-server"
        elif "client" in package_name_lower:
            subcategory = "mcp-client"
        else:
            subcategory = "mcp-tool"

    # Skills packages
    elif (
        "skill" in package_name_lower
        or "clawbot" in package_name_lower
        or "clawhub" in package_name_lower
    ):
        category = "skills"
        if "ai" in package_name_lower or "agent" in package_name_lower:
            subcategory = "ai-skill"
        else:
            subcategory = "general-skill"

    # AI/Agent packages
    elif any(
        kw in package_name_lower
        for kw in ["agent", "assistant", "bot", "ai-", "chatbot"]
    ):
        category = "ai-agents"
        if "chat" in package_name_lower:
            subcategory = "chatbot"
        else:
            subcategory = "agent-tool"

    # LLM packages
    elif any(
        kw in package_name_lower
        for kw in [
            "llm",
            "openai",
            "anthropic",
            "claude",
            "gpt",
            "gemini",
            "langchain",
            "llamaindex",
        ]
    ):
        category = "llm-tools"
        if any(kw in package_name_lower for kw in ["chain", "index"]):
            subcategory = "llm-framework"
        else:
            subcategory = "llm-integration"

    # Security packages
    elif any(
        kw in package_name_lower
        for kw in [
            "security",
            "auth",
            "encrypt",
            "firewall",
            "scanner",
            "vulner",
            "malware",
        ]
    ):
        category = "security"
        if any(kw in package_name_lower for kw in ["auth", "login"]):
            subcategory = "authentication"
        elif any(kw in package_name_lower for kw in ["scan", "detect"]):
            subcategory = "scanner"
        else:
            subcategory = "security-tool"

    # Database packages
    elif any(
        kw in package_name_lower
        for kw in ["database", "sql", "mongo", "redis", "postgres", "mysql", "sqlite"]
    ):
        category = "data"
        subcategory = "database"

    # Web packages
    elif any(
        kw in package_name_lower
        for kw in [
            "http",
            "express",
            "flask",
            "fastapi",
            "server",
            "api",
            "rest",
            "graphql",
        ]
    ):
        category = "web"
        if "api" in package_name_lower or "rest" in package_name_lower:
            subcategory = "api-framework"
        else:
            subcategory = "web-framework"

    # Crypto packages
    elif any(
        kw in package_name_lower
        for kw in [
            "crypto",
            "bitcoin",
            "ethereum",
            "wallet",
            "miner",
            "blockchain",
            "web3",
        ]
    ):
        category = "crypto"
        if any(kw in package_name_lower for kw in ["wallet", "miner"]):
            subcategory = "cryptocurrency-tool"
        else:
            subcategory = "cryptocurrency"

    # ML packages
    elif any(
        kw in package_name_lower
        for kw in [
            "tensorflow",
            "pytorch",
            "scikit",
            "pandas",
            "numpy",
            "ml",
            "machine-learning",
            "keras",
        ]
    ):
        category = "ml"
        subcategory = "ml-library"

    # CLI tools
    elif any(
        kw in package_name_lower for kw in ["cli", "command", "terminal", "console"]
    ):
        category = "cli"
        subcategory = "cli-tool"

    # Testing tools
    elif any(
        kw in package_name_lower
        for kw in ["test", "jest", "mocha", "pytest", "unittest"]
    ):
        category = "testing"
        subcategory = "test-framework"

    # Calculate confidence score
    confidence_score = 0.7  # Base confidence

    # Boost confidence based on findings and risk
    if findings_count > 0:
        confidence_score = min(1.0, confidence_score + 0.15)
    if risk_score > 7:
        confidence_score = min(1.0, confidence_score + 0.15)

    # Higher confidence for well-known categories
    if category in ["mcp", "skills", "ai-agents", "llm-tools", "security"]:
        confidence_score = min(1.0, confidence_score + 0.1)

    # Generate risk level
    risk_level = "low"
    if risk_score >= 9:
        risk_level = "critical"
    elif risk_score >= 7:
        risk_level = "high"
    elif risk_score >= 4:
        risk_level = "medium"

    # Generate description
    description = f"{ecosystem.upper()} package in {category}/{subcategory} category. "

    if findings_count > 0:
        description += f"Security scan found {findings_count} potential issues with {risk_level} risk level. "
    else:
        description += "No security issues detected in initial scan. "

    if verdict and verdict != "UNKNOWN":
        description += f"Verdict: {verdict}. "

    description += f"Classified with {confidence_score:.0%} confidence."

    # Risk indicators
    risk_indicators = []
    if risk_score >= 7:
        risk_indicators.append("high-risk")
    if findings_count > 5:
        risk_indicators.append("multiple-threats")
    elif findings_count > 0:
        risk_indicators.append(f"threats-{findings_count}")
    if category in ["crypto", "security"]:
        risk_indicators.append("sensitive-category")

    # Import patterns based on ecosystem
    import_patterns = []
    if ecosystem == "npm":
        import_patterns = ["require()", "import"]
    elif ecosystem == "pypi":
        import_patterns = ["import", "__import__"]
    elif ecosystem == "gem":
        import_patterns = ["require", "load"]
    elif ecosystem == "cargo":
        import_patterns = ["use", "extern crate"]
    else:
        import_patterns = ["import"]

    # Metadata
    metadata = {
        "risk_score": float(risk_score) if risk_score else 0,
        "findings_count": findings_count or 0,
        "verdict": verdict or "UNKNOWN",
        "category_confidence": confidence_score,
        "classification_date": datetime.now(timezone.utc).isoformat(),
    }

    return {
        "ecosystem": ecosystem or "unknown",
        "package_name": package_name or "unknown",
        "package_version": version or "0.0.0",
        "category": category,
        "subcategory": subcategory,
        "confidence_score": confidence_score,
        "description_summary": description[:500],
        "environment_vars": "[]",
        "network_protocols": "[]",
        "file_patterns": "[]",
        "import_patterns": json.dumps(import_patterns),
        "risk_indicators": json.dumps(risk_indicators),
        "classifier_version": "v2.0.0-safe",
        "metadata_json": json.dumps(metadata),
    }


def process_batch_safe(cursor, batch_data):
    """Process batch using individual INSERT with duplicate checking."""

    inserted = 0
    skipped = 0
    errors = 0

    for row in batch_data:
        try:
            # Parse row data
            row[0]
            package_name = row[1] or "unknown"
            ecosystem = row[2] or "unknown"
            version = row[3] or "0.0.0"
            risk_score = float(row[4]) if row[4] else 0.0
            findings_count = int(row[5]) if row[5] else 0
            verdict = row[6]

            # Check if already exists using all three key fields
            cursor.execute(
                """
                SELECT COUNT(*) FROM forge_classification 
                WHERE ecosystem = ? AND package_name = ? AND package_version = ?
            """,
                (ecosystem, package_name, version),
            )

            if cursor.fetchone()[0] > 0:
                skipped += 1
                continue

            # Classify the package
            classification = classify_package(
                package_name, ecosystem, version, risk_score, findings_count, verdict
            )

            # Insert with individual error handling
            cursor.execute(
                """
                INSERT INTO forge_classification (
                    id, ecosystem, package_name, package_version, category,
                    subcategory, confidence_score, description_summary,
                    environment_vars, network_protocols, file_patterns,
                    import_patterns, risk_indicators, classified_at,
                    updated_at, classifier_version, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    str(uuid.uuid4()),
                    classification["ecosystem"],
                    classification["package_name"],
                    classification["package_version"],
                    classification["category"],
                    classification["subcategory"],
                    classification["confidence_score"],
                    classification["description_summary"],
                    classification["environment_vars"],
                    classification["network_protocols"],
                    classification["file_patterns"],
                    classification["import_patterns"],
                    classification["risk_indicators"],
                    datetime.now(timezone.utc),
                    datetime.now(timezone.utc),
                    classification["classifier_version"],
                    classification["metadata_json"],
                ),
            )

            inserted += 1

        except Exception as e:
            errors += 1
            if errors <= 3:  # Only print first 3 errors
                print(f"  Error: {e}")
                if "UNIQUE KEY constraint" in str(e):
                    print(f"    Duplicate: {ecosystem}/{package_name}@{version}")

    return inserted, skipped, errors


def main():
    """Main function with robust duplicate handling."""

    batch_size = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    max_batches = int(sys.argv[2]) if len(sys.argv) > 2 else None

    print("=" * 60)
    print("SAFE CLASSIFICATION - DUPLICATE-RESISTANT PROCESSOR")
    print("=" * 60)

    conn = get_connection()
    cursor = conn.cursor()

    # Get current state
    cursor.execute("SELECT COUNT(*) FROM forge_classification")
    existing_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM public_scans")
    total_scans = cursor.fetchone()[0]

    # Get unclassified count using proper join
    cursor.execute("""
        SELECT COUNT(*) FROM public_scans ps
        LEFT JOIN forge_classification fc ON (
            ps.ecosystem = fc.ecosystem AND 
            ps.package_name = fc.package_name AND 
            ps.package_version = fc.package_version
        )
        WHERE fc.id IS NULL
    """)
    unclassified_count = cursor.fetchone()[0]

    print(f"Current classified: {existing_count:,}")
    print(f"Total scans: {total_scans:,}")
    print(f"Unclassified: {unclassified_count:,}")
    print(f"Coverage: {(existing_count / total_scans) * 100:.1f}%")
    print(f"Batch size: {batch_size}")
    if max_batches:
        print(f"Max batches: {max_batches}")
    print()

    if unclassified_count == 0:
        print("✅ All packages already classified!")
        return

    # Process in batches
    offset = 0
    total_inserted = 0
    total_skipped = 0
    total_errors = 0
    batch_num = 0

    start_time = time.time()

    while True:
        batch_num += 1

        if max_batches and batch_num > max_batches:
            break

        # Fetch unclassified packages using LEFT JOIN
        print(f"Batch {batch_num}: Fetching unclassified packages...")

        cursor.execute(f"""
            SELECT 
                CAST(ps.id AS NVARCHAR(50)) as id,
                ps.package_name,
                ps.ecosystem,
                ps.package_version,
                ps.risk_score,
                ps.findings_count,
                ps.verdict
            FROM public_scans ps
            LEFT JOIN forge_classification fc ON (
                ps.ecosystem = fc.ecosystem AND 
                ps.package_name = fc.package_name AND 
                ps.package_version = fc.package_version
            )
            WHERE fc.id IS NULL
            ORDER BY ps.created_at DESC
            OFFSET {offset} ROWS
            FETCH NEXT {batch_size} ROWS ONLY
        """)

        batch_data = cursor.fetchall()

        if not batch_data:
            print("No more unclassified packages found.")
            break

        print(f"  Processing {len(batch_data)} packages...")

        # Process the batch
        inserted, skipped, errors = process_batch_safe(cursor, batch_data)

        total_inserted += inserted
        total_skipped += skipped
        total_errors += errors

        # Commit after each batch
        conn.commit()

        # Progress report
        elapsed = time.time() - start_time
        rate = total_inserted / elapsed if elapsed > 0 else 0

        print(f"  ✓ Inserted: {inserted}, Skipped: {skipped}, Errors: {errors}")
        print(f"  Total progress: {total_inserted} inserted ({rate:.1f}/sec)")

        # Get updated coverage
        cursor.execute("SELECT COUNT(*) FROM forge_classification")
        current_classified = cursor.fetchone()[0]
        coverage = (current_classified / total_scans) * 100
        print(f"  Coverage: {coverage:.1f}% ({current_classified:,}/{total_scans:,})")
        print()

        offset += batch_size

        # Short pause to avoid overwhelming database
        if batch_num % 5 == 0:
            time.sleep(1)

    # Final statistics
    elapsed = time.time() - start_time

    print("=" * 60)
    print("SAFE CLASSIFICATION COMPLETE")
    print("=" * 60)
    print(f"Time elapsed: {elapsed:.1f} seconds")
    print(f"Total inserted: {total_inserted:,}")
    print(f"Total skipped: {total_skipped:,}")
    print(f"Total errors: {total_errors:,}")

    if total_inserted > 0:
        print(f"Average rate: {total_inserted / elapsed:.1f} packages/second")

    # Show final category distribution
    cursor.execute("""
        SELECT category, COUNT(*) as count
        FROM forge_classification
        GROUP BY category
        ORDER BY count DESC
    """)

    print("\nFinal category distribution:")
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]:,} packages")

    # Final coverage
    cursor.execute("SELECT COUNT(*) FROM forge_classification")
    final_count = cursor.fetchone()[0]
    final_coverage = (final_count / total_scans) * 100

    print(f"\nFinal coverage: {final_coverage:.1f}% ({final_count:,}/{total_scans:,})")

    cursor.close()
    conn.close()

    print("\n✅ Safe classification complete!")


if __name__ == "__main__":
    main()
