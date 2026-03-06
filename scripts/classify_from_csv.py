#!/usr/bin/env python3
"""
Classify packages specifically from the unclassified CSV file.
This ensures we're only processing the known backlog, not new incoming scans.
"""

import pyodbc
import json
import uuid
import csv
from datetime import datetime, timezone
import sys

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
    elif any(kw in package_name_lower for kw in ['agent', 'assistant', 'bot', 'ai-', 'chatbot']):
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
    elif any(kw in package_name_lower for kw in ['tensorflow', 'pytorch', 'scikit', 'pandas', 'numpy', 'ml']):
        category = 'ml'
        subcategory = 'ml-library'
    
    # Calculate confidence score
    confidence_score = 0.7
    if findings_count > 0:
        confidence_score = min(1.0, confidence_score + 0.15)
    if risk_score > 7:
        confidence_score = min(1.0, confidence_score + 0.15)
    
    # Generate description
    risk_level = 'critical' if risk_score >= 9 else 'high' if risk_score >= 7 else 'medium' if risk_score >= 4 else 'low'
    description = f"{ecosystem.upper()} package in {category}/{subcategory} category. "
    
    if findings_count > 0:
        description += f"Found {findings_count} potential issues with {risk_level} risk level. "
    else:
        description += "No security issues detected in initial scan. "
    
    if verdict and verdict != 'UNKNOWN':
        description += f"Verdict: {verdict}."
    
    # Risk indicators
    risk_indicators = []
    if risk_score >= 7:
        risk_indicators.append('high-risk')
    if findings_count > 5:
        risk_indicators.append('multiple-threats')
    elif findings_count > 0:
        risk_indicators.append(f'threats-{findings_count}')
    
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
        'classifier_version': 'v2.0.0-csv',
        'metadata_json': json.dumps({
            'risk_score': float(risk_score) if risk_score else 0,
            'findings_count': findings_count or 0,
            'verdict': verdict or 'UNKNOWN',
            'source': 'csv_backlog'
        })
    }

def main():
    csv_file = sys.argv[1] if len(sys.argv) > 1 else 'unclassified_top1000_20260306_135331.csv'
    
    print("=" * 60)
    print("CSV-BASED CLASSIFICATION - TARGETED BACKLOG PROCESSOR")
    print("=" * 60)
    print(f"Reading from: {csv_file}")
    
    # Read CSV file
    packages = []
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                packages.append({
                    'package_name': row.get('package_name', ''),
                    'ecosystem': row.get('ecosystem', ''),
                    'package_version': row.get('package_version', ''),
                    'risk_score': float(row.get('risk_score', 0)),
                    'findings_count': int(row.get('findings_count', 0)),
                    'verdict': row.get('verdict', '')
                })
        print(f"Loaded {len(packages)} packages from CSV")
    except FileNotFoundError:
        print(f"❌ Error: Could not find CSV file: {csv_file}")
        return
    except Exception as e:
        print(f"❌ Error reading CSV: {e}")
        return
    
    # Connect to database
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get current count
    cursor.execute("SELECT COUNT(*) FROM forge_classification")
    start_count = cursor.fetchone()[0]
    print(f"Starting with {start_count:,} classified packages")
    print()
    
    # Process packages
    total_inserted = 0
    total_skipped = 0
    total_errors = 0
    
    for i, pkg in enumerate(packages, 1):
        try:
            # Check if already classified
            cursor.execute("""
                SELECT COUNT(*) FROM forge_classification 
                WHERE ecosystem = ? AND package_name = ? AND package_version = ?
            """, (pkg['ecosystem'], pkg['package_name'], pkg['package_version']))
            
            if cursor.fetchone()[0] > 0:
                total_skipped += 1
                continue
            
            # Classify the package
            classification = classify_package(
                pkg['package_name'], 
                pkg['ecosystem'], 
                pkg['package_version'],
                pkg['risk_score'], 
                pkg['findings_count'], 
                pkg['verdict']
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
            
            total_inserted += 1
            
            # Progress report every 50 packages
            if i % 50 == 0:
                conn.commit()
                print(f"Progress: {i}/{len(packages)} - Inserted: {total_inserted}, Skipped: {total_skipped}")
                
        except Exception as e:
            total_errors += 1
            if total_errors <= 5:
                print(f"  Error on {pkg['package_name']}: {e}")
    
    # Final commit
    conn.commit()
    
    # Get final count
    cursor.execute("SELECT COUNT(*) FROM forge_classification")
    end_count = cursor.fetchone()[0]
    
    # Summary
    print("\n" + "=" * 60)
    print("CSV CLASSIFICATION COMPLETE")
    print("=" * 60)
    print(f"Packages processed: {len(packages)}")
    print(f"Successfully classified: {total_inserted}")
    print(f"Already classified: {total_skipped}")
    print(f"Errors: {total_errors}")
    print(f"Total classified in database: {end_count:,} (+{end_count - start_count})")
    print()
    print("✅ CSV backlog processing complete!")
    
    cursor.close()
    conn.close()

if __name__ == "__main__":
    main()