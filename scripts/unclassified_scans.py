#!/usr/bin/env python3
"""List public_scans that have not been classified yet."""

import pyodbc
import csv
from datetime import datetime

# Database connection
conn = pyodbc.connect(
    "Driver={ODBC Driver 18 for SQL Server};"
    "Server=tcp:sigil-sql-w2-46iy6y.database.windows.net,1433;"
    "Database=sigil;"
    "Uid=sigil_admin;"
    "Pwd=hUkVA6s1G7z4Smqf!;"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
    "Connection Timeout=30;"
)
cursor = conn.cursor()

print("Finding unclassified public_scans...")

# Get unclassified packages using LEFT JOIN
cursor.execute("""
    SELECT 
        ps.package_name,
        ps.ecosystem,
        ps.package_version,
        ps.risk_score,
        ps.findings_count,
        ps.verdict,
        ps.created_at
    FROM public_scans ps
    LEFT JOIN forge_classification fc ON (
        ps.ecosystem = fc.ecosystem AND 
        ps.package_name = fc.package_name AND 
        ps.package_version = fc.package_version
    )
    WHERE fc.id IS NULL
    ORDER BY ps.created_at DESC
""")

unclassified = cursor.fetchall()

print(f"Found {len(unclassified):,} unclassified packages")

# Save to CSV file
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
filename = f"unclassified_scans_{timestamp}.csv"

with open(filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)

    # Write header
    writer.writerow(
        [
            "package_name",
            "ecosystem",
            "package_version",
            "risk_score",
            "findings_count",
            "verdict",
            "created_at",
        ]
    )

    # Write data
    for row in unclassified:
        writer.writerow(
            [
                row[0] or "",  # package_name
                row[1] or "",  # ecosystem
                row[2] or "",  # package_version
                row[3] or 0,  # risk_score
                row[4] or 0,  # findings_count
                row[5] or "",  # verdict
                row[6],  # created_at
            ]
        )

print(f"✅ Saved to {filename}")

# Show sample of unclassified packages by ecosystem
cursor.execute("""
    SELECT 
        ps.ecosystem,
        COUNT(*) as count
    FROM public_scans ps
    LEFT JOIN forge_classification fc ON (
        ps.ecosystem = fc.ecosystem AND 
        ps.package_name = fc.package_name AND 
        ps.package_version = fc.package_version
    )
    WHERE fc.id IS NULL
    GROUP BY ps.ecosystem
    ORDER BY count DESC
""")

print("\nUnclassified packages by ecosystem:")
for row in cursor.fetchall():
    print(f"  {row[0] or 'unknown'}: {row[1]:,} packages")

# Show high-risk unclassified packages
cursor.execute("""
    SELECT TOP 20
        ps.package_name,
        ps.ecosystem,
        ps.risk_score,
        ps.findings_count,
        ps.verdict
    FROM public_scans ps
    LEFT JOIN forge_classification fc ON (
        ps.ecosystem = fc.ecosystem AND 
        ps.package_name = fc.package_name AND 
        ps.package_version = fc.package_version
    )
    WHERE fc.id IS NULL AND ps.risk_score > 5
    ORDER BY ps.risk_score DESC, ps.findings_count DESC
""")

high_risk = cursor.fetchall()
if high_risk:
    print(f"\nTop 20 high-risk unclassified packages:")
    print(
        "Package Name".ljust(40) + "Ecosystem".ljust(12) + "Risk".ljust(6) + "Findings"
    )
    print("-" * 70)
    for row in high_risk:
        name = (row[0] or "unknown")[:39]
        eco = (row[1] or "unknown")[:11]
        risk = f"{row[2] or 0:.1f}"
        findings = row[3] or 0
        print(f"{name:<40} {eco:<12} {risk:<6} {findings}")

cursor.close()
conn.close()

print(f"\n✅ Complete! {len(unclassified):,} unclassified packages saved to {filename}")
