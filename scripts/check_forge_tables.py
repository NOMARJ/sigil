#!/usr/bin/env python3
"""Check forge tables structure."""

import pyodbc

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

conn = pyodbc.connect(conn_str)
cursor = conn.cursor()

print("Checking forge tables...\n")

# Check if forge_classification exists
cursor.execute("""
    SELECT TABLE_NAME 
    FROM INFORMATION_SCHEMA.TABLES 
    WHERE TABLE_NAME LIKE 'forge%'
""")

tables = cursor.fetchall()
print(f"Found {len(tables)} forge tables:")
for table in tables:
    print(f"  - {table[0]}")

# Check columns in forge_classification if it exists
if any("forge_classification" in str(t) for t in tables):
    print("\nforge_classification columns:")
    cursor.execute("""
        SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = 'forge_classification'
        ORDER BY ORDINAL_POSITION
    """)
    for col in cursor.fetchall():
        print(f"  - {col[0]}: {col[1]} (nullable: {col[2]})")

    # Check row count
    cursor.execute("SELECT COUNT(*) FROM forge_classification")
    count = cursor.fetchone()[0]
    print(f"\nRows in forge_classification: {count}")
else:
    print("\nforge_classification table does not exist!")

# Check public_scans count
cursor.execute("SELECT COUNT(*) FROM public_scans")
scan_count = cursor.fetchone()[0]
print(f"\nTotal rows in public_scans: {scan_count}")

cursor.close()
conn.close()
