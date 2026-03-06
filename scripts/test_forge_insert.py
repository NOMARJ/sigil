#!/usr/bin/env python3
"""Test inserting a single row into forge_classification."""

import pyodbc
import uuid
from datetime import datetime, timezone

# Database connection
conn_str = (
    "Driver={ODBC Driver 18 for SQL Server};"
    "Server=tcp:sigil-sql-w2-46iy6y.database.windows.net,1433;"
    "Database=sigil;"
    "Uid=sigil_admin;"
    "Pwd=hUkVA6s1G7z4Smqf!;"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
    "Connection Timeout=10;"
)

print("Connecting to database...")
conn = pyodbc.connect(conn_str)
cursor = conn.cursor()

# Test insert
test_data = {
    "id": str(uuid.uuid4()),
    "ecosystem": "npm",
    "package_name": "test-mcp-server",
    "package_version": "1.0.0",
    "category": "mcp",
    "subcategory": "mcp-server",
    "confidence_score": 0.95,
    "description_summary": "Test MCP server package for forge classification",
    "environment_vars": "[]",
    "network_protocols": '["http"]',
    "file_patterns": "[]",
    "import_patterns": '["require()"]',
    "risk_indicators": "[]",
    "classified_at": datetime.now(timezone.utc),
    "updated_at": datetime.now(timezone.utc),
    "classifier_version": "test-v1",
    "metadata_json": "{}",
}

print("Inserting test row...")
try:
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
            test_data["id"],
            test_data["ecosystem"],
            test_data["package_name"],
            test_data["package_version"],
            test_data["category"],
            test_data["subcategory"],
            test_data["confidence_score"],
            test_data["description_summary"],
            test_data["environment_vars"],
            test_data["network_protocols"],
            test_data["file_patterns"],
            test_data["import_patterns"],
            test_data["risk_indicators"],
            test_data["classified_at"],
            test_data["updated_at"],
            test_data["classifier_version"],
            test_data["metadata_json"],
        ),
    )

    conn.commit()
    print("✅ Successfully inserted test row!")

    # Check count
    cursor.execute("SELECT COUNT(*) FROM forge_classification")
    count = cursor.fetchone()[0]
    print(f"Total rows in forge_classification: {count}")

except Exception as e:
    print(f"❌ Error: {e}")

cursor.close()
conn.close()
