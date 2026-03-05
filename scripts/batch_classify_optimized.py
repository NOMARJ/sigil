#!/usr/bin/env python3
"""
Optimized batch classification for forge_classification table.
Processes public_scans data in efficient batches.
"""

import pyodbc
import json
import uuid
from datetime import datetime, timezone
import sys
import time

# Database connection parameters
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
    conn = pyodbc.connect(conn_str)
    conn.autocommit = False  # Use transactions for better performance
    return conn

def classify_package(package_name, ecosystem, version, risk_score, findings_count, verdict):
    """Classify a package based on its data."""
    
    package_name_lower = (package_name or '').lower()
    
    # Determine category and subcategory
    category = 'general'
    subcategory = 'utility'
    
    # MCP packages
    if 'mcp' in package_name_lower or 'model-context' in package_name_lower:
        category = 'mcp'
        subcategory = 'mcp-server' if 'server' in package_name_lower else 'mcp-tool'
    # Skills packages
    elif 'skill' in package_name_lower or 'clawbot' in package_name_lower or 'clawhub' in package_name_lower:
        category = 'skills'
        subcategory = 'ai-skill' if 'ai' in package_name_lower else 'general-skill'
    # AI/Agent packages
    elif any(kw in package_name_lower for kw in ['agent', 'assistant', 'bot', 'ai-']):
        category = 'ai-agents'
        subcategory = 'agent-tool'
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
    elif any(kw in package_name_lower for kw in ['tensorflow', 'pytorch', 'scikit', 'pandas', 'numpy', 'ml', 'machine-learning']):
        category = 'ml'
        subcategory = 'ml-library'
    
    # Calculate confidence score
    confidence_score = 0.7  # Base confidence
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
    if verdict:
        description += f"Verdict: {verdict}."
    
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
        'ecosystem': ecosystem,
        'package_name': package_name,
        'package_version': version or '0.0.0',
        'category': category,
        'subcategory': subcategory,
        'confidence_score': confidence_score,
        'description_summary': description[:500],
        'environment_vars': '[]',
        'network_protocols': '[]',
        'file_patterns': '[]',
        'import_patterns': '["require()"]' if ecosystem == 'npm' else '["import"]',
        'risk_indicators': json.dumps(risk_indicators),
        'classifier_version': 'v1.0.0-optimized',
        'metadata_json': json.dumps(metadata)
    }

def process_batch(cursor, batch_data):
    """Process a batch of scan data."""
    
    inserted = 0
    skipped = 0
    errors = 0
    
    for row in batch_data:
        try:
            # Parse row data
            scan_id = row[0]
            package_name = row[1]
            ecosystem = row[2] or 'unknown'
            version = row[3] or '0.0.0'
            risk_score = float(row[4]) if row[4] else 0.0
            findings_count = int(row[5]) if row[5] else 0
            verdict = row[6]
            
            # Skip if already exists
            cursor.execute("""
                SELECT COUNT(*) FROM forge_classification 
                WHERE package_name = ? AND package_version = ?
            """, (package_name, version))
            
            if cursor.fetchone()[0] > 0:
                skipped += 1
                continue
            
            # Classify the package
            classification = classify_package(
                package_name, ecosystem, version,
                risk_score, findings_count, verdict
            )
            
            # Insert into forge_classification
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
            
            inserted += 1
            
        except Exception as e:
            errors += 1
            if errors <= 3:  # Only print first 3 errors
                print(f"  Error: {e}")
    
    return inserted, skipped, errors

def main():
    """Main function to process all scans."""
    
    batch_size = 1000
    total_limit = None
    if len(sys.argv) > 1:
        total_limit = int(sys.argv[1])
    
    print("="*60)
    print("FORGE CLASSIFICATION - BATCH PROCESSOR")
    print("="*60)
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get current state
    cursor.execute("SELECT COUNT(*) FROM forge_classification")
    existing_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM public_scans")
    total_scans = cursor.fetchone()[0]
    
    print(f"Current classified: {existing_count}")
    print(f"Total scans available: {total_scans}")
    print(f"Batch size: {batch_size}")
    if total_limit:
        print(f"Processing limit: {total_limit}")
    print()
    
    # Process in batches
    offset = 0
    total_inserted = 0
    total_skipped = 0
    total_errors = 0
    batch_num = 0
    
    start_time = time.time()
    
    while True:
        batch_num += 1
        
        # Check if we've hit the limit
        if total_limit and offset >= total_limit:
            break
        
        # Fetch batch (avoiding problematic columns)
        print(f"Batch {batch_num}: Fetching rows {offset}-{offset+batch_size}...")
        
        cursor.execute(f"""
            SELECT 
                CAST(id AS NVARCHAR(50)) as id,
                package_name,
                ecosystem,
                package_version,
                risk_score,
                findings_count,
                verdict
            FROM public_scans
            ORDER BY created_at DESC
            OFFSET {offset} ROWS
            FETCH NEXT {batch_size} ROWS ONLY
        """)
        
        batch_data = cursor.fetchall()
        
        if not batch_data:
            print("No more data to process.")
            break
        
        print(f"  Processing {len(batch_data)} packages...")
        
        # Process the batch
        inserted, skipped, errors = process_batch(cursor, batch_data)
        
        total_inserted += inserted
        total_skipped += skipped
        total_errors += errors
        
        # Commit every batch
        conn.commit()
        
        # Progress report
        elapsed = time.time() - start_time
        rate = total_inserted / elapsed if elapsed > 0 else 0
        
        print(f"  ✓ Inserted: {inserted}, Skipped: {skipped}, Errors: {errors}")
        print(f"  Total progress: {total_inserted} inserted ({rate:.1f}/sec)")
        print()
        
        offset += batch_size
        
        # Short pause to avoid overwhelming the database
        if batch_num % 5 == 0:
            time.sleep(1)
    
    # Final statistics
    elapsed = time.time() - start_time
    
    print("="*60)
    print("CLASSIFICATION COMPLETE")
    print("="*60)
    print(f"Time elapsed: {elapsed:.1f} seconds")
    print(f"Total inserted: {total_inserted}")
    print(f"Total skipped: {total_skipped}")
    print(f"Total errors: {total_errors}")
    print(f"Average rate: {total_inserted/elapsed:.1f} packages/second")
    
    # Show category distribution
    cursor.execute("""
        SELECT category, COUNT(*) as count
        FROM forge_classification
        GROUP BY category
        ORDER BY count DESC
    """)
    
    print("\nCategory distribution:")
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]} packages")
    
    # Final count
    cursor.execute("SELECT COUNT(*) FROM forge_classification")
    final_count = cursor.fetchone()[0]
    print(f"\nTotal classified packages: {final_count}")
    
    cursor.close()
    conn.close()
    
    print("\n✅ Done!")

if __name__ == "__main__":
    main()