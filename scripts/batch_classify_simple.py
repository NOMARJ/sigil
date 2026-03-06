#!/usr/bin/env python3
"""
Simple batch classification script to populate forge_classification table.
"""

import pyodbc
import json
from datetime import datetime
import sys

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
    package_name = scan.package_name.lower() if scan.package_name else ""
    ecosystem = scan.ecosystem or "unknown"
    severity = scan.severity or 0
    threats = scan.threats_found or 0

    # Determine category
    category = "general"
    if "mcp" in package_name:
        category = "mcp"
    elif "skill" in package_name or "clawbot" in package_name:
        category = "skills"
    elif "agent" in package_name or "bot" in package_name:
        category = "agent"
    elif "llm" in package_name or "openai" in package_name or "claude" in package_name:
        category = "llm"

    # Determine tool type
    tool_type = "other"
    if "mcp" in package_name:
        tool_type = "mcp-server"
    elif "skill" in package_name:
        tool_type = "skill"
    elif ecosystem == "npm":
        tool_type = "npm-package"
    elif ecosystem == "pypi":
        tool_type = "python-package"

    # Calculate trust score
    trust_score = 100
    if severity >= 9:
        trust_score = 10  # Critical
    elif severity >= 7:
        trust_score = 30  # High
    elif severity >= 4:
        trust_score = 60  # Medium
    elif severity >= 1:
        trust_score = 80  # Low

    # Severity level
    if severity >= 9:
        severity_level = "critical"
    elif severity >= 7:
        severity_level = "high"
    elif severity >= 4:
        severity_level = "medium"
    elif severity >= 1:
        severity_level = "low"
    else:
        severity_level = "safe"

    return {
        "scan_id": scan.id,
        "package_name": package_name,
        "ecosystem": ecosystem,
        "category": category,
        "tool_type": tool_type,
        "trust_score": trust_score,
        "severity_level": severity_level,
        "threats_detected": threats,
    }


def main():
    """Main function."""
    limit = 1000
    if len(sys.argv) > 1:
        limit = int(sys.argv[1])

    print(f"Batch classifying first {limit} packages...")

    conn = get_connection()
    cursor = conn.cursor()

    # Create table if not exists
    print("Ensuring forge_classification table exists...")
    cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_classification')
        CREATE TABLE forge_classification (
            id UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
            public_scan_id UNIQUEIDENTIFIER,
            package_name NVARCHAR(255) NOT NULL,
            ecosystem NVARCHAR(50) NOT NULL,
            category NVARCHAR(100),
            tool_type NVARCHAR(50),
            trust_score INT,
            severity_level NVARCHAR(20),
            threats_detected INT DEFAULT 0,
            capabilities NVARCHAR(MAX),
            classified_at DATETIME DEFAULT GETDATE(),
            FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE CASCADE
        )
    """)

    # Create indexes (wrapped in try-catch for existing tables)
    try:
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_class_scan')
            CREATE INDEX idx_forge_class_scan ON forge_classification(public_scan_id)
        """)
    except:
        pass  # Index might already exist

    try:
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_class_package')
            CREATE INDEX idx_forge_class_package ON forge_classification(package_name, ecosystem)
        """)
    except:
        pass

    try:
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_class_category')
            CREATE INDEX idx_forge_class_category ON forge_classification(category)
        """)
    except:
        pass

    conn.commit()

    # Get scans to process
    print(f"Fetching top {limit} scans...")
    cursor.execute(f"""
        SELECT TOP {limit}
            id, package_name, ecosystem, severity, threats_found
        FROM public_scans
        WHERE id NOT IN (SELECT public_scan_id FROM forge_classification WHERE public_scan_id IS NOT NULL)
        ORDER BY created_at DESC
    """)

    scans = cursor.fetchall()
    print(f"Found {len(scans)} unclassified scans")

    classified = 0
    errors = 0

    for scan in scans:
        try:
            # Classify the package
            classification = classify_package(scan)

            # Insert into forge_classification
            cursor.execute(
                """
                INSERT INTO forge_classification (
                    public_scan_id, package_name, ecosystem, category, 
                    tool_type, trust_score, severity_level, threats_detected
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    classification["scan_id"],
                    classification["package_name"],
                    classification["ecosystem"],
                    classification["category"],
                    classification["tool_type"],
                    classification["trust_score"],
                    classification["severity_level"],
                    classification["threats_detected"],
                ),
            )

            classified += 1

            if classified % 100 == 0:
                conn.commit()
                print(f"Progress: {classified}/{len(scans)} classified")

        except Exception as e:
            errors += 1
            print(f"Error classifying {scan.package_name}: {e}")

    conn.commit()

    print("\n" + "=" * 50)
    print("Classification complete!")
    print(f"Total scans processed: {len(scans)}")
    print(f"Successfully classified: {classified}")
    print(f"Errors: {errors}")

    # Show statistics
    cursor.execute("""
        SELECT 
            category,
            COUNT(*) as count,
            AVG(trust_score) as avg_trust
        FROM forge_classification
        GROUP BY category
        ORDER BY count DESC
    """)

    print("\nCategory distribution:")
    for row in cursor.fetchall():
        print(
            f"  {row.category}: {row.count} packages (avg trust: {row.avg_trust:.1f})"
        )

    cursor.close()
    conn.close()
    print("\n✅ Done!")


if __name__ == "__main__":
    main()
