#!/usr/bin/env python3
"""Quick fix for forge_trust_score_history table issue."""

import pyodbc
import sys

# Database connection parameters
SERVER = "sigil-sql-w2-46iy6y.database.windows.net"
DATABASE = "sigil"
USERNAME = "sigil_admin"
PASSWORD = "hUkVA6s1G7z4Smqf!"


def main():
    conn_str = (
        f"Driver={{ODBC Driver 18 for SQL Server}};"
        f"Server=tcp:{SERVER},1433;"
        f"Database={DATABASE};"
        f"Uid={USERNAME};"
        f"Pwd={PASSWORD};"
        f"Encrypt=yes;"
        f"TrustServerCertificate=no;"
        f"Connection Timeout=10;"
    )

    print("Connecting to database...")
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    conn.autocommit = True  # Enable autocommit for DDL

    print("Dropping problematic constraint if exists...")
    try:
        cursor.execute("""
            IF EXISTS (
                SELECT * FROM sys.foreign_keys 
                WHERE name = 'FK__forge_tru__scan___5708E33C'
            )
            ALTER TABLE forge_trust_score_history 
            DROP CONSTRAINT FK__forge_tru__scan___5708E33C
        """)
        print("✓ Constraint dropped")
    except Exception as e:
        print(f"  Note: {e}")

    print("Checking if table exists...")
    cursor.execute("""
        SELECT COUNT(*) FROM sys.tables 
        WHERE name = 'forge_trust_score_history'
    """)
    exists = cursor.fetchone()[0] > 0

    if exists:
        print("✓ Table already exists")
        # Just ensure the foreign key is correct
        print("Adding correct foreign key...")
        try:
            cursor.execute("""
                ALTER TABLE forge_trust_score_history 
                ADD CONSTRAINT FK_forge_trust_history_scan 
                FOREIGN KEY (public_scan_id) 
                REFERENCES public_scans(id) ON DELETE CASCADE
            """)
            print("✓ Foreign key added")
        except Exception as e:
            print(f"  Note: {e}")
    else:
        print("Creating forge_trust_score_history table...")
        cursor.execute("""
            CREATE TABLE forge_trust_score_history (
                id UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
                public_scan_id UNIQUEIDENTIFIER,
                package_name NVARCHAR(255) NOT NULL,
                ecosystem NVARCHAR(50) NOT NULL,
                trust_score INT NOT NULL,
                previous_score INT,
                change_reason NVARCHAR(MAX),
                recorded_at DATETIME DEFAULT GETDATE(),
                FOREIGN KEY (public_scan_id) 
                REFERENCES public_scans(id) ON DELETE CASCADE
            )
        """)
        print("✓ Table created")

    cursor.close()
    conn.close()
    print("\n✨ Done!")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
