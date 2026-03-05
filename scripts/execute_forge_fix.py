#!/usr/bin/env python3
"""Execute forge table fixes directly in MSSQL database."""

import pyodbc
import sys

# Database connection parameters
SERVER = "sigil-sql-w2-46iy6y.database.windows.net"
DATABASE = "sigil"
USERNAME = "sigil_admin"
PASSWORD = "hUkVA6s1G7z4Smqf!"

def execute_forge_fix():
    """Execute the forge table fix SQL commands."""
    
    # Connection string
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
    
    try:
        print("Connecting to Azure SQL Database...")
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        
        print("Connected successfully!")
        
        # First, check if the problematic constraint exists and drop it
        print("\nChecking for existing foreign key constraint...")
        cursor.execute("""
            IF EXISTS (
                SELECT * FROM sys.foreign_keys 
                WHERE name = 'FK__forge_tru__scan___5708E33C'
            )
            BEGIN
                ALTER TABLE forge_trust_score_history 
                DROP CONSTRAINT FK__forge_tru__scan___5708E33C;
                PRINT 'Dropped existing constraint FK__forge_tru__scan___5708E33C';
            END
        """)
        
        # Create forge_trust_score_history table if it doesn't exist
        print("Creating forge_trust_score_history table...")
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_trust_score_history')
            BEGIN
                CREATE TABLE forge_trust_score_history (
                    id UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
                    public_scan_id UNIQUEIDENTIFIER,
                    package_name NVARCHAR(255) NOT NULL,
                    ecosystem NVARCHAR(50) NOT NULL,
                    trust_score INT NOT NULL,
                    previous_score INT,
                    change_reason NVARCHAR(MAX),
                    recorded_at DATETIME DEFAULT GETDATE(),
                    FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE CASCADE
                );
                
                CREATE INDEX idx_forge_trust_history_scan ON forge_trust_score_history(public_scan_id);
                CREATE INDEX idx_forge_trust_history_package ON forge_trust_score_history(package_name, ecosystem);
                CREATE INDEX idx_forge_trust_history_time ON forge_trust_score_history(recorded_at);
                
                PRINT 'Created forge_trust_score_history table';
            END
            ELSE
            BEGIN
                -- If table exists, ensure it has the correct foreign key
                IF NOT EXISTS (
                    SELECT * FROM sys.foreign_keys fk
                    JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
                    JOIN sys.columns c ON fkc.parent_column_id = c.column_id AND fkc.parent_object_id = c.object_id
                    WHERE fk.parent_object_id = OBJECT_ID('forge_trust_score_history')
                    AND c.name = 'public_scan_id'
                )
                BEGIN
                    ALTER TABLE forge_trust_score_history 
                    ADD CONSTRAINT FK_forge_trust_history_scan 
                    FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE CASCADE;
                    
                    PRINT 'Added correct foreign key constraint';
                END
            END
        """)
        
        # Create other forge tables
        print("Creating forge_analytics table...")
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_analytics')
            BEGIN
                CREATE TABLE forge_analytics (
                    id UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
                    public_scan_id UNIQUEIDENTIFIER,
                    package_name NVARCHAR(255) NOT NULL,
                    ecosystem NVARCHAR(50) NOT NULL,
                    downloads_last_week INT DEFAULT 0,
                    downloads_last_month INT DEFAULT 0,
                    stars_count INT DEFAULT 0,
                    forks_count INT DEFAULT 0,
                    dependencies_count INT DEFAULT 0,
                    dependents_count INT DEFAULT 0,
                    last_updated DATETIME DEFAULT GETDATE(),
                    FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE SET NULL
                );
                
                CREATE INDEX idx_forge_analytics_scan ON forge_analytics(public_scan_id);
                CREATE INDEX idx_forge_analytics_package ON forge_analytics(package_name, ecosystem);
                CREATE INDEX idx_forge_analytics_downloads ON forge_analytics(downloads_last_month DESC);
                
                PRINT 'Created forge_analytics table';
            END
        """)
        
        # Create forge_security_reports table
        print("Creating forge_security_reports table...")
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_security_reports')
            BEGIN
                CREATE TABLE forge_security_reports (
                    id UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
                    public_scan_id UNIQUEIDENTIFIER,
                    package_name NVARCHAR(255) NOT NULL,
                    ecosystem NVARCHAR(50) NOT NULL,
                    vulnerability_score INT DEFAULT 0,
                    cve_count INT DEFAULT 0,
                    critical_issues INT DEFAULT 0,
                    high_issues INT DEFAULT 0,
                    medium_issues INT DEFAULT 0,
                    low_issues INT DEFAULT 0,
                    report_data NVARCHAR(MAX),
                    generated_at DATETIME DEFAULT GETDATE(),
                    FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE CASCADE
                );
                
                CREATE INDEX idx_forge_security_scan ON forge_security_reports(public_scan_id);
                CREATE INDEX idx_forge_security_package ON forge_security_reports(package_name, ecosystem);
                CREATE INDEX idx_forge_security_score ON forge_security_reports(vulnerability_score DESC);
                
                PRINT 'Created forge_security_reports table';
            END
        """)
        
        # Create forge_package_metrics table
        print("Creating forge_package_metrics table...")
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_package_metrics')
            BEGIN
                CREATE TABLE forge_package_metrics (
                    id UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
                    public_scan_id UNIQUEIDENTIFIER,
                    package_name NVARCHAR(255) NOT NULL,
                    ecosystem NVARCHAR(50) NOT NULL,
                    quality_score INT DEFAULT 0,
                    popularity_score INT DEFAULT 0,
                    maintenance_score INT DEFAULT 0,
                    community_score INT DEFAULT 0,
                    overall_rating FLOAT DEFAULT 0.0,
                    last_calculated DATETIME DEFAULT GETDATE(),
                    FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE SET NULL
                );
                
                CREATE INDEX idx_forge_metrics_scan ON forge_package_metrics(public_scan_id);
                CREATE INDEX idx_forge_metrics_package ON forge_package_metrics(package_name, ecosystem);
                CREATE INDEX idx_forge_metrics_rating ON forge_package_metrics(overall_rating DESC);
                
                PRINT 'Created forge_package_metrics table';
            END
        """)
        
        # Commit changes
        conn.commit()
        print("\n✅ All forge tables created/fixed successfully!")
        
        # Verify tables exist
        print("\nVerifying tables...")
        cursor.execute("""
            SELECT 
                t.name AS table_name,
                COUNT(c.column_id) AS column_count,
                COUNT(fk.name) AS foreign_key_count
            FROM sys.tables t
            LEFT JOIN sys.columns c ON t.object_id = c.object_id
            LEFT JOIN sys.foreign_keys fk ON t.object_id = fk.parent_object_id
            WHERE t.name IN (
                'forge_trust_score_history',
                'forge_analytics',
                'forge_security_reports',
                'forge_package_metrics'
            )
            GROUP BY t.name
            ORDER BY t.name
        """)
        
        for row in cursor.fetchall():
            print(f"  • {row.table_name}: {row.column_count} columns, {row.foreign_key_count} foreign keys")
        
        cursor.close()
        conn.close()
        
        print("\n✨ Forge table fixes completed successfully!")
        return 0
        
    except pyodbc.Error as e:
        print(f"\n❌ Database error: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(execute_forge_fix())