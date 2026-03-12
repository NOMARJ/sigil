#!/usr/bin/env python3
"""
Populate forge_classification table from public_scans data.
Matches the actual table structure in production.
"""

import pyodbc
import json
from datetime import datetime, timezone
import sys
import uuid

# Database connection
SERVER = "sigil-sql-w2-46iy6y.database.windows.net"
DATABASE = "sigil"
USERNAME = "sigil_admin"
PASSWORD = "hUkVA6s1G7z4Smqf!"


def get_connection():
    """Get database connection."""
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


def classify_package(scan):
    """Classify a package based on scan data."""
    package_name = (scan.package_name or "").lower()
    ecosystem = scan.ecosystem or "unknown"
    version = scan.package_version or "0.0.0"
    risk_score = scan.risk_score or 0
    threats = scan.findings_count or 0

    # Determine category and subcategory
    category = "general"
    subcategory = "utility"

    # MCP packages
    if "mcp" in package_name or "model-context" in package_name:
        category = "mcp"
        if "server" in package_name:
            subcategory = "mcp-server"
        elif "client" in package_name:
            subcategory = "mcp-client"
        else:
            subcategory = "mcp-tool"

    # Skills packages
    elif (
        "skill" in package_name
        or "clawbot" in package_name
        or "clawhub" in package_name
    ):
        category = "skills"
        if "ai" in package_name:
            subcategory = "ai-skill"
        else:
            subcategory = "general-skill"

    # AI/Agent packages
    elif any(
        keyword in package_name for keyword in ["agent", "assistant", "bot", "ai-"]
    ):
        category = "ai-agents"
        subcategory = "agent-tool"

    # LLM packages
    elif any(
        keyword in package_name
        for keyword in ["llm", "openai", "anthropic", "claude", "gpt", "gemini"]
    ):
        category = "llm-tools"
        subcategory = "llm-integration"

    # Security packages
    elif any(
        keyword in package_name
        for keyword in ["security", "auth", "encrypt", "secure", "firewall"]
    ):
        category = "security"
        subcategory = "security-tool"

    # Database packages
    elif any(
        keyword in package_name
        for keyword in ["database", "sql", "mongo", "redis", "postgres"]
    ):
        category = "data"
        subcategory = "database"

    # Web/HTTP packages
    elif any(
        keyword in package_name
        for keyword in ["http", "express", "flask", "fastapi", "server", "api"]
    ):
        category = "web"
        subcategory = "web-framework"

    # Crypto packages (high risk)
    elif any(
        keyword in package_name
        for keyword in ["crypto", "bitcoin", "ethereum", "wallet", "miner"]
    ):
        category = "crypto"
        subcategory = "cryptocurrency"

    # Calculate confidence score based on name matching and scan results
    confidence_score = 0.8  # Base confidence
    if threats > 0:
        confidence_score = min(1.0, confidence_score + 0.1)
    if risk_score > 7:
        confidence_score = min(1.0, confidence_score + 0.1)

    # Generate description summary
    risk_level = "low"
    if risk_score >= 9:
        risk_level = "critical"
    elif risk_score >= 7:
        risk_level = "high"
    elif risk_score >= 4:
        risk_level = "medium"

    description = f"{ecosystem.upper()} package in {category}/{subcategory} category. "
    if threats > 0:
        description += f"Found {threats} potential threats with {risk_level} risk. "
    else:
        description += "No immediate threats detected. "

    # Parse findings for patterns (no longer available in query)
    findings = {}

    # Extract environment variables if detected
    env_vars = []
    if findings.get("credentials", {}).get("env_access"):
        env_vars = ["process.env", "os.environ"]

    # Extract network protocols
    network_protocols = []
    if findings.get("network", {}).get("http_requests"):
        network_protocols.append("http")
    if findings.get("network", {}).get("websocket"):
        network_protocols.append("websocket")
    if findings.get("network", {}).get("dns"):
        network_protocols.append("dns")

    # File patterns
    file_patterns = []
    if findings.get("filesystem", {}).get("file_access"):
        file_patterns = ["*.json", "*.txt", "*.log"]

    # Import patterns based on ecosystem
    import_patterns = []
    if ecosystem == "npm":
        import_patterns = ["require()", "import"]
    elif ecosystem == "pypi":
        import_patterns = ["import", "from...import"]

    # Risk indicators
    risk_indicators = []
    if risk_score >= 7:
        risk_indicators.append("high-risk")
    if threats > 0:
        risk_indicators.append(f"threats-{threats}")
    if findings.get("obfuscation"):
        risk_indicators.append("obfuscated-code")
    if findings.get("install_hooks"):
        risk_indicators.append("install-hooks")

    # Metadata
    metadata = {
        "scan_id": str(scan.id) if scan.id else None,
        "risk_score": risk_score,
        "threats_found": threats,
        "verdict": scan.verdict if hasattr(scan, "verdict") else None,
    }

    return {
        "id": str(uuid.uuid4()),
        "ecosystem": ecosystem,
        "package_name": scan.package_name,  # Use original case
        "package_version": version,
        "category": category,
        "subcategory": subcategory,
        "confidence_score": confidence_score,
        "description_summary": description[:500],  # Limit length
        "environment_vars": json.dumps(env_vars),
        "network_protocols": json.dumps(network_protocols),
        "file_patterns": json.dumps(file_patterns),
        "import_patterns": json.dumps(import_patterns),
        "risk_indicators": json.dumps(risk_indicators),
        "classified_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "classifier_version": "v1.0.0",
        "metadata_json": json.dumps(metadata),
    }


def main():
    """Main function."""
    limit = 1000
    if len(sys.argv) > 1:
        limit = int(sys.argv[1])

    print(f"Populating forge_classification table with {limit} packages...")

    conn = get_connection()
    cursor = conn.cursor()

    # Check current state
    cursor.execute("SELECT COUNT(*) FROM forge_classification")
    existing_count = cursor.fetchone()[0]
    print(f"Current rows in forge_classification: {existing_count}")

    # Get unclassified scans (excluding problematic column types)
    print(f"Fetching top {limit} scans from public_scans...")
    cursor.execute(f"""
        SELECT TOP {limit}
            CAST(id AS NVARCHAR(50)) as id, 
            package_name, ecosystem, package_version, risk_score, 
            findings_count, verdict
        FROM public_scans
        WHERE package_name NOT IN (
            SELECT DISTINCT package_name 
            FROM forge_classification 
            WHERE package_name IS NOT NULL
        )
        ORDER BY created_at DESC
    """)

    scans = cursor.fetchall()
    print(f"Found {len(scans)} unclassified packages")

    if len(scans) == 0:
        print("No unclassified packages found!")
        return

    classified = 0
    errors = 0
    skipped = 0

    for scan in scans:
        try:
            # Check if already classified (by package name + version)
            cursor.execute(
                """
                SELECT COUNT(*) FROM forge_classification 
                WHERE package_name = ? AND package_version = ?
            """,
                (scan.package_name, scan.package_version or "0.0.0"),
            )

            if cursor.fetchone()[0] > 0:
                skipped += 1
                continue

            # Classify the package
            classification = classify_package(scan)

            # Insert into forge_classification
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
                    classification["id"],
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
                    classification["classified_at"],
                    classification["updated_at"],
                    classification["classifier_version"],
                    classification["metadata_json"],
                ),
            )

            classified += 1

            if classified % 100 == 0:
                conn.commit()
                print(
                    f"Progress: {classified} classified, {skipped} skipped, {errors} errors"
                )

        except Exception as e:
            errors += 1
            if errors <= 5:  # Only print first 5 errors
                print(f"Error classifying {scan.package_name}: {e}")

    conn.commit()

    print("\n" + "=" * 50)
    print("Classification complete!")
    print(f"Packages processed: {len(scans)}")
    print(f"Successfully classified: {classified}")
    print(f"Skipped (already classified): {skipped}")
    print(f"Errors: {errors}")

    # Show category distribution
    cursor.execute("""
        SELECT 
            category,
            COUNT(*) as count,
            AVG(confidence_score) as avg_confidence
        FROM forge_classification
        GROUP BY category
        ORDER BY count DESC
    """)

    print("\nCategory distribution:")
    for row in cursor.fetchall():
        print(
            f"  {row.category}: {row.count} packages (avg confidence: {row.avg_confidence:.2f})"
        )

    # Show total count
    cursor.execute("SELECT COUNT(*) FROM forge_classification")
    total = cursor.fetchone()[0]
    print(f"\nTotal classified packages: {total}")

    cursor.close()
    conn.close()
    print("\n✅ Forge classification data populated successfully!")


if __name__ == "__main__":
    main()
