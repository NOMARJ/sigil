#!/usr/bin/env python3
"""Ultra-fast bulk classification using batch inserts."""

import pyodbc
import json
import uuid
from datetime import datetime, timezone
import sys
import time

def main():
    batch_size = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    
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
    
    print(f"Bulk classifying {batch_size} packages...")
    start_time = time.time()
    
    # Get unclassified packages
    cursor.execute(f"""
        SELECT TOP {batch_size}
            package_name, ecosystem, package_version, risk_score, findings_count
        FROM public_scans
        WHERE package_name NOT IN (
            SELECT package_name FROM forge_classification
        )
        ORDER BY created_at DESC
    """)
    
    packages = cursor.fetchall()
    if not packages:
        print("No unclassified packages found.")
        return
    
    print(f"Processing {len(packages)} packages...")
    
    # Prepare bulk insert data
    rows = []
    for pkg in packages:
        name = pkg[0]
        eco = pkg[1] or 'unknown'
        ver = pkg[2] or '0.0.0'
        risk = float(pkg[3]) if pkg[3] else 0
        findings = pkg[4] or 0
        
        # Quick categorization
        name_lower = name.lower()
        if 'mcp' in name_lower:
            cat = 'mcp'
        elif 'skill' in name_lower or 'claw' in name_lower:
            cat = 'skills'
        elif any(x in name_lower for x in ['agent', 'bot']):
            cat = 'ai-agents'
        elif any(x in name_lower for x in ['llm', 'openai', 'gpt']):
            cat = 'llm-tools'
        elif any(x in name_lower for x in ['crypto', 'bitcoin']):
            cat = 'crypto'
        elif any(x in name_lower for x in ['web', 'http', 'api']):
            cat = 'web'
        elif any(x in name_lower for x in ['data', 'sql', 'mongo']):
            cat = 'data'
        elif any(x in name_lower for x in ['security', 'auth']):
            cat = 'security'
        elif any(x in name_lower for x in ['ml', 'tensor', 'torch']):
            cat = 'ml'
        else:
            cat = 'general'
        
        subcat = cat + '-tool'
        conf = 0.7 + (0.2 if findings > 0 else 0) + (0.1 if risk > 7 else 0)
        conf = min(1.0, conf)
        desc = f"{eco.upper()} {cat} package."
        
        rows.append((
            str(uuid.uuid4()), eco, name, ver, cat, subcat, conf, 
            desc[:500], '[]', '[]', '[]', '[]', '[]',
            datetime.now(timezone.utc), datetime.now(timezone.utc),
            'bulk-v1', '{}'
        ))
    
    # Bulk insert using executemany (much faster)
    sql = """
        INSERT INTO forge_classification (
            id, ecosystem, package_name, package_version,
            category, subcategory, confidence_score, description_summary,
            environment_vars, network_protocols, file_patterns,
            import_patterns, risk_indicators, classified_at,
            updated_at, classifier_version, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    
    try:
        cursor.executemany(sql, rows)
        conn.commit()
        
        elapsed = time.time() - start_time
        rate = len(rows) / elapsed
        
        print(f"✅ Inserted {len(rows)} packages in {elapsed:.1f}s ({rate:.0f} pkg/sec)")
        
        # Get total count
        cursor.execute("SELECT COUNT(*) FROM forge_classification")
        total = cursor.fetchone()[0]
        print(f"Total classified: {total:,}")
        
    except Exception as e:
        print(f"Error during bulk insert: {e}")
        conn.rollback()
    
    cursor.close()
    conn.close()

if __name__ == "__main__":
    main()