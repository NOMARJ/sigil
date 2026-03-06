#!/usr/bin/env python3
"""Simple list of unclassified public_scans and classify them."""

import pyodbc
import json
import uuid
from datetime import datetime, timezone
import time

# Database connection
SERVER = "sigil-sql-w2-46iy6y.database.windows.net"
DATABASE = "sigil"
USERNAME = "sigil_admin"
PASSWORD = "hUkVA6s1G7z4Smqf!"

def get_connection():
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

def classify_package(package_name, ecosystem, version, risk_score, findings_count, verdict):
    """Enhanced classification logic."""
    
    package_name_lower = (package_name or '').lower()
    
    # Determine category and subcategory
    category = 'general'
    subcategory = 'utility'
    
    # MCP packages (highest priority)
    if 'mcp' in package_name_lower or 'model-context' in package_name_lower:
        category = 'mcp'
        subcategory = 'mcp-server' if 'server' in package_name_lower else 'mcp-tool'
    
    # Skills packages
    elif 'skill' in package_name_lower or 'clawbot' in package_name_lower or 'clawhub' in package_name_lower:
        category = 'skills'
        subcategory = 'ai-skill' if 'ai' in package_name_lower else 'general-skill'
    
    # AI/Agent packages  
    elif any(kw in package_name_lower for kw in ['agent', 'assistant', 'bot', 'ai-', 'chatbot']):
        category = 'ai-agents'
        subcategory = 'chatbot' if 'chat' in package_name_lower else 'agent-tool'
    
    # LLM packages
    elif any(kw in package_name_lower for kw in ['llm', 'openai', 'anthropic', 'claude', 'gpt', 'gemini', 'langchain']):
        category = 'llm-tools'
        subcategory = 'llm-integration'
    
    # Security packages
    elif any(kw in package_name_lower for kw in ['security', 'auth', 'encrypt', 'firewall', 'scanner']):
        category = 'security'
        subcategory = 'security-tool'
    
    # Database packages
    elif any(kw in package_name_lower for kw in ['database', 'sql', 'mongo', 'redis', 'postgres', 'mysql']):
        category = 'data'
        subcategory = 'database'
    
    # Web packages
    elif any(kw in package_name_lower for kw in ['http', 'express', 'flask', 'fastapi', 'server', 'api', 'rest']):
        category = 'web'
        subcategory = 'web-framework'
    
    # Crypto packages
    elif any(kw in package_name_lower for kw in ['crypto', 'bitcoin', 'ethereum', 'wallet', 'miner', 'blockchain']):
        category = 'crypto'
        subcategory = 'cryptocurrency'
    
    # ML packages
    elif any(kw in package_name_lower for kw in ['tensorflow', 'pytorch', 'scikit', 'pandas', 'numpy', 'ml']):
        category = 'ml'
        subcategory = 'ml-library'
    
    # Calculate confidence score
    confidence_score = 0.7
    if findings_count > 0:
        confidence_score = min(1.0, confidence_score + 0.15)
    if risk_score > 7:
        confidence_score = min(1.0, confidence_score + 0.15)
    
    # Generate risk level
    risk_level = 'low'
    if risk_score >= 9:
        risk_level = 'critical'
    elif risk_score >= 7:
        risk_level = 'high'
    elif risk_score >= 4:
        risk_level = 'medium'
    
    # Generate description
    description = f"{ecosystem.upper()} package in {category}/{subcategory} category. "
    if findings_count > 0:
        description += f"Found {findings_count} potential issues with {risk_level} risk level. "
    else:
        description += "No security issues detected in initial scan. "
    
    if verdict and verdict != 'UNKNOWN':
        description += f"Verdict: {verdict}. "
    
    # Risk indicators
    risk_indicators = []
    if risk_score >= 7:
        risk_indicators.append('high-risk')
    if findings_count > 5:
        risk_indicators.append('multiple-threats')
    elif findings_count > 0:
        risk_indicators.append(f'threats-{findings_count}')
    
    # Metadata
    metadata = {
        'risk_score': float(risk_score) if risk_score else 0,
        'findings_count': findings_count or 0,
        'verdict': verdict or 'UNKNOWN'
    }
    
    return {
        'ecosystem': ecosystem or 'unknown',
        'package_name': package_name or 'unknown',
        'package_version': version or '0.0.0',
        'category': category,
        'subcategory': subcategory,
        'confidence_score': confidence_score,
        'description_summary': description[:500],
        'environment_vars': '[]',
        'network_protocols': '[]',
        'file_patterns': '[]',
        'import_patterns': '[\"require()\"]' if ecosystem == 'npm' else '[\"import\"]',
        'risk_indicators': json.dumps(risk_indicators),
        'classifier_version': 'v2.0.0-targeted',
        'metadata_json': json.dumps(metadata)
    }

def main():
    print("=" * 60)
    print("UNCLASSIFIED SCANS - LIST AND CLASSIFY")
    print("=" * 60)
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get count of unclassified packages (avoiding datetime issues)
    print("Getting unclassified package count...")
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
    print(f"Found {unclassified_count:,} unclassified packages")
    
    if unclassified_count == 0:
        print("✅ All packages already classified!")
        return
    
    # Get sample of unclassified packages by ecosystem
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
    
    print(f"\nStarting classification of {unclassified_count:,} packages...")
    
    # Process in batches of 100
    batch_size = 100
    total_inserted = 0
    total_skipped = 0
    total_errors = 0
    
    start_time = time.time()
    
    for batch_num in range(1, min(51, (unclassified_count // batch_size) + 1)):  # Max 50 batches
        print(f"\nBatch {batch_num}: Processing {batch_size} packages...")
        
        # Get batch of unclassified packages
        cursor.execute(f"""
            SELECT TOP {batch_size}
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
            ORDER BY ps.id
        """)
        
        batch_data = cursor.fetchall()
        
        if not batch_data:
            print("No more unclassified packages found.")
            break
        
        # Process each package in the batch
        batch_inserted = 0
        batch_skipped = 0
        batch_errors = 0
        
        for row in batch_data:
            try:
                package_name = row[0] or 'unknown'
                ecosystem = row[1] or 'unknown'
                version = row[2] or '0.0.0'
                risk_score = float(row[3]) if row[3] else 0.0
                findings_count = int(row[4]) if row[4] else 0
                verdict = row[5]
                
                # Double-check not already classified
                cursor.execute("""
                    SELECT COUNT(*) FROM forge_classification 
                    WHERE ecosystem = ? AND package_name = ? AND package_version = ?
                """, (ecosystem, package_name, version))
                
                if cursor.fetchone()[0] > 0:
                    batch_skipped += 1
                    continue
                
                # Classify the package
                classification = classify_package(
                    package_name, ecosystem, version,
                    risk_score, findings_count, verdict
                )
                
                # Insert classification
                cursor.execute("""
                    INSERT INTO forge_classification (
                        id, ecosystem, package_name, package_version, category,
                        subcategory, confidence_score, description_summary,
                        environment_vars, network_protocols, file_patterns,
                        import_patterns, risk_indicators, classified_at,
                        updated_at, classifier_version, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    classification['ecosystem'],
                    classification['package_name'],
                    classification['package_version'],
                    classification['category'],
                    classification['subcategory'],
                    classification['confidence_score'],
                    classification['description_summary'],
                    classification['environment_vars'],
                    classification['network_protocols'],
                    classification['file_patterns'],
                    classification['import_patterns'],
                    classification['risk_indicators'],
                    datetime.now(timezone.utc),
                    datetime.now(timezone.utc),
                    classification['classifier_version'],
                    classification['metadata_json']
                ))
                
                batch_inserted += 1
                
            except Exception as e:
                batch_errors += 1
                if batch_errors <= 3:
                    print(f"    Error: {e}")
        
        # Commit batch
        conn.commit()
        
        total_inserted += batch_inserted
        total_skipped += batch_skipped
        total_errors += batch_errors
        
        elapsed = time.time() - start_time
        rate = total_inserted / elapsed if elapsed > 0 else 0
        
        print(f"  ✓ Inserted: {batch_inserted}, Skipped: {batch_skipped}, Errors: {batch_errors}")
        print(f"  Total: {total_inserted} inserted ({rate:.1f}/sec)")
    
    # Final statistics
    elapsed = time.time() - start_time
    
    print("\n" + "=" * 60)
    print("CLASSIFICATION COMPLETE")
    print("=" * 60)
    print(f"Time elapsed: {elapsed:.1f} seconds")
    print(f"Total inserted: {total_inserted:,}")
    print(f"Total skipped: {total_skipped:,}")
    print(f"Total errors: {total_errors:,}")
    
    if total_inserted > 0:
        print(f"Average rate: {total_inserted/elapsed:.1f} packages/second")
    
    # Get final count
    cursor.execute("SELECT COUNT(*) FROM forge_classification")
    final_count = cursor.fetchone()[0]
    print(f"Total classified packages: {final_count:,}")
    
    cursor.close()
    conn.close()
    
    print("\n✅ Targeted classification complete!")

if __name__ == "__main__":
    main()