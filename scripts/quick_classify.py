#!/usr/bin/env python3
"""Quick and simple classification to populate forge_classification."""

import pyodbc
import json
import uuid
from datetime import datetime, timezone
import sys

# Connection
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

limit = int(sys.argv[1]) if len(sys.argv) > 1 else 1000

print(f"Classifying {limit} packages...")

# Get packages (simple query)
cursor.execute(f"""
    SELECT TOP {limit}
        package_name, ecosystem, package_version, risk_score, findings_count
    FROM public_scans
    WHERE package_name NOT IN (
        SELECT package_name FROM forge_classification
    )
""")

packages = cursor.fetchall()
print(f"Found {len(packages)} unclassified packages")

inserted = 0
for pkg in packages:
    name = pkg[0]
    eco = pkg[1] or 'unknown'
    ver = pkg[2] or '0.0.0'
    risk = float(pkg[3]) if pkg[3] else 0
    findings = pkg[4] or 0
    
    # Quick category determination
    name_lower = name.lower()
    if 'mcp' in name_lower:
        cat, subcat = 'mcp', 'mcp-server'
    elif 'skill' in name_lower or 'claw' in name_lower:
        cat, subcat = 'skills', 'ai-skill'
    elif any(x in name_lower for x in ['agent', 'bot', 'ai-']):
        cat, subcat = 'ai-agents', 'agent-tool'
    elif any(x in name_lower for x in ['llm', 'openai', 'gpt', 'claude']):
        cat, subcat = 'llm-tools', 'llm-integration'
    elif any(x in name_lower for x in ['crypto', 'bitcoin', 'ethereum']):
        cat, subcat = 'crypto', 'cryptocurrency'
    else:
        cat, subcat = 'general', 'utility'
    
    conf = 0.7 + (0.2 if findings > 0 else 0) + (0.1 if risk > 7 else 0)
    conf = min(1.0, conf)
    
    desc = f"{eco.upper()} package in {cat} category."
    if findings > 0:
        desc += f" {findings} issues found."
    
    try:
        cursor.execute("""
            INSERT INTO forge_classification (
                id, ecosystem, package_name, package_version,
                category, subcategory, confidence_score, description_summary,
                environment_vars, network_protocols, file_patterns,
                import_patterns, risk_indicators, classified_at,
                updated_at, classifier_version, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()), eco, name, ver,
            cat, subcat, conf, desc[:500],
            '[]', '[]', '[]', '[]', '[]',
            datetime.now(timezone.utc), datetime.now(timezone.utc),
            'quick-v1', '{}'
        ))
        inserted += 1
        
        if inserted % 100 == 0:
            conn.commit()
            print(f"Inserted {inserted}...")
    except Exception as e:
        pass  # Skip duplicates/errors
        
conn.commit()

# Final stats
cursor.execute("SELECT COUNT(*) FROM forge_classification")
total = cursor.fetchone()[0]

print(f"\n✅ Done! Inserted {inserted} new packages")
print(f"Total classified: {total}")

cursor.close()
conn.close()