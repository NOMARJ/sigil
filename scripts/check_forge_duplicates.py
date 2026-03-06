#!/usr/bin/env python3
"""Check for duplicates and data quality in forge_classification."""

import pyodbc
import json

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

print("=" * 60)
print("FORGE CLASSIFICATION DATA QUALITY CHECK")
print("=" * 60)

# Check for duplicates
cursor.execute("""
    SELECT ecosystem, package_name, package_version, COUNT(*) as cnt
    FROM forge_classification
    GROUP BY ecosystem, package_name, package_version
    HAVING COUNT(*) > 1
""")

duplicates = cursor.fetchall()
if duplicates:
    print(f"\n❌ Found {len(duplicates)} duplicate entries:")
    for dup in duplicates[:10]:  # Show first 10
        print(f"  {dup[0]}/{dup[1]}@{dup[2]} - {dup[3]} copies")
else:
    print("\n✅ No duplicates found")

# Check for missing descriptions
cursor.execute("""
    SELECT COUNT(*) 
    FROM forge_classification 
    WHERE description_summary IS NULL OR description_summary = ''
""")
missing_desc = cursor.fetchone()[0]
print(f"\n📝 Missing descriptions: {missing_desc}")

# Check field population
cursor.execute("""
    SELECT TOP 5 
        package_name,
        category,
        subcategory,
        confidence_score,
        LEN(description_summary) as desc_len,
        risk_indicators
    FROM forge_classification
    ORDER BY classified_at DESC
""")

print("\n📊 Sample of recent classifications:")
for row in cursor.fetchall():
    print(
        f"  {row[0][:30]:<30} | {row[1]:<10} | {row[2]:<15} | conf:{row[3]:.2f} | desc:{row[4]:>3} chars"
    )

# Get statistics
cursor.execute("""
    SELECT 
        COUNT(*) as total,
        COUNT(DISTINCT package_name) as unique_packages,
        AVG(confidence_score) as avg_confidence,
        COUNT(CASE WHEN category = 'mcp' THEN 1 END) as mcp_count,
        COUNT(CASE WHEN category = 'skills' THEN 1 END) as skills_count,
        COUNT(CASE WHEN category = 'ai-agents' THEN 1 END) as ai_agents_count
    FROM forge_classification
""")

stats = cursor.fetchone()
print(f"\n📈 Statistics:")
print(f"  Total entries: {stats[0]:,}")
print(f"  Unique packages: {stats[1]:,}")
print(f"  Avg confidence: {stats[2]:.2f}")
print(f"  MCP packages: {stats[3]:,}")
print(f"  Skills packages: {stats[4]:,}")
print(f"  AI Agent packages: {stats[5]:,}")

cursor.close()
conn.close()
