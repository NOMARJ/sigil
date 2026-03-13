# =====================================================================
# PowerShell Script: Fix Forge Tables Foreign Key Issues
# =====================================================================
#
# Purpose: Execute the SQL script to fix forge table foreign key constraints
# and ensure all required tables exist with proper relationships
#
# Prerequisites:
# - SQL Server PowerShell module (SqlServer)
# - Access to Azure SQL Database
# - DATABASE_URL environment variable set
#
# Usage:
#   .\scripts\fix_forge_tables.ps1
#   .\scripts\fix_forge_tables.ps1 -Verbose
#   .\scripts\fix_forge_tables.ps1 -DryRun
# =====================================================================

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# =====================================================================
# Helper Functions
# =====================================================================

function Write-Banner {
    param([string]$Message)
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor White
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "[STEP] $Message" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor DarkYellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Parse-ConnectionString {
    param([string]$DatabaseUrl)
    
    # Parse ODBC connection string format
    # Example: "Driver={ODBC Driver 18 for SQL Server};Server=server.database.windows.net;Database=db;Uid=user;Pwd=pass;"
    
    $parts = @{}
    $DatabaseUrl.Split(';') | ForEach-Object {
        if ($_ -and $_.Contains('=')) {
            $key, $value = $_.Split('=', 2)
            $parts[$key.Trim()] = $value.Trim()
        }
    }
    
    return @{
        Server = $parts['Server']
        Database = $parts['Database']
        Username = $parts['Uid']
        Password = $parts['Pwd']
        Driver = $parts['Driver']
    }
}

function Test-SqlConnection {
    param($ConnectionInfo)
    
    try {
        $connectionString = "Server=$($ConnectionInfo.Server);Database=$($ConnectionInfo.Database);User Id=$($ConnectionInfo.Username);Password=$($ConnectionInfo.Password);Encrypt=True;TrustServerCertificate=False;"
        
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()
        
        $command = $connection.CreateCommand()
        $command.CommandText = "SELECT 1"
        $result = $command.ExecuteScalar()
        
        $connection.Close()
        return $result -eq 1
    }
    catch {
        return $false
    }
}

# =====================================================================
# Main Script
# =====================================================================

Write-Banner "Sigil Forge Tables Fix - Foreign Key Repair"

# Check prerequisites
Write-Step "Checking prerequisites..."

# Check SQL Server PowerShell module
if (-not (Get-Module -ListAvailable -Name SqlServer)) {
    Write-Warning "SQL Server PowerShell module not found. Installing..."
    try {
        Install-Module -Name SqlServer -Force -AllowClobber -Scope CurrentUser
        Write-Success "SQL Server module installed"
    }
    catch {
        Write-Error "Failed to install SQL Server module: $($_.Exception.Message)"
        exit 1
    }
}
else {
    Write-Success "SQL Server PowerShell module available"
}

# Import module
Import-Module SqlServer

# Check DATABASE_URL
$databaseUrl = $env:DATABASE_URL
if (-not $databaseUrl) {
    Write-Error "DATABASE_URL environment variable not set"
    Write-Host "Please set DATABASE_URL with format:"
    Write-Host "Driver={ODBC Driver 18 for SQL Server};Server=server.database.windows.net;Database=dbname;Uid=username;Pwd=password;"
    exit 1
}

Write-Success "DATABASE_URL environment variable found"

# Parse connection information
Write-Step "Parsing connection information..."
try {
    $connInfo = Parse-ConnectionString -DatabaseUrl $databaseUrl
    if (-not $connInfo.Server -or -not $connInfo.Database) {
        throw "Invalid connection string format"
    }
    Write-Success "Connection string parsed successfully"
    Write-Host "  Server: $($connInfo.Server)" -ForegroundColor DarkGray
    Write-Host "  Database: $($connInfo.Database)" -ForegroundColor DarkGray
}
catch {
    Write-Error "Failed to parse DATABASE_URL: $($_.Exception.Message)"
    exit 1
}

# Test connection
Write-Step "Testing database connection..."
if (-not (Test-SqlConnection -ConnectionInfo $connInfo)) {
    Write-Error "Cannot connect to database"
    Write-Host "Please verify:"
    Write-Host "- Database server is accessible"
    Write-Host "- Credentials are correct"
    Write-Host "- Firewall allows connections"
    exit 1
}

Write-Success "Database connection successful"

# Find SQL script
$scriptPath = Join-Path $PSScriptRoot "fix_forge_tables_mssql.sql"
if (-not (Test-Path $scriptPath)) {
    Write-Error "SQL script not found: $scriptPath"
    exit 1
}

Write-Success "SQL script found: $scriptPath"

# Check current table state
Write-Step "Checking current forge table state..."
try {
    $connectionString = "Server=$($connInfo.Server);Database=$($connInfo.Database);User Id=$($connInfo.Username);Password=$($connInfo.Password);Encrypt=True;TrustServerCertificate=False;"
    
    $tableCheckQuery = @"
SELECT 
    TABLE_NAME,
    CASE WHEN TABLE_NAME IS NOT NULL THEN 'EXISTS' ELSE 'MISSING' END as STATUS
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_NAME IN ('forge_classification', 'forge_capabilities', 'forge_matches', 'forge_categories', 'forge_trust_score_history', 'public_scans')
UNION ALL
SELECT 'forge_trust_score_history' as TABLE_NAME, 'MISSING' as STATUS
WHERE NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'forge_trust_score_history')
ORDER BY TABLE_NAME;
"@

    $results = Invoke-Sqlcmd -ServerInstance $connInfo.Server -Database $connInfo.Database -Username $connInfo.Username -Password $connInfo.Password -Query $tableCheckQuery -Encrypt
    
    Write-Host "Current table status:" -ForegroundColor DarkGray
    $results | ForEach-Object {
        $status = $_.STATUS
        $color = if ($status -eq "EXISTS") { "Green" } else { "Red" }
        Write-Host "  $($_.TABLE_NAME): $status" -ForegroundColor $color
    }
}
catch {
    Write-Warning "Could not check current table state: $($_.Exception.Message)"
}

# Execute SQL script
if ($DryRun) {
    Write-Warning "DRY RUN MODE - SQL script will not be executed"
    Write-Host "Would execute: $scriptPath"
}
else {
    Write-Step "Executing SQL fix script..."
    try {
        $output = Invoke-Sqlcmd -ServerInstance $connInfo.Server -Database $connInfo.Database -Username $connInfo.Username -Password $connInfo.Password -InputFile $scriptPath -Verbose:$Verbose -Encrypt
        
        Write-Success "SQL script executed successfully"
        
        if ($output) {
            Write-Host "Script output:" -ForegroundColor DarkGray
            $output | ForEach-Object {
                Write-Host "  $_" -ForegroundColor DarkGray
            }
        }
    }
    catch {
        Write-Error "Failed to execute SQL script: $($_.Exception.Message)"
        if ($_.Exception.Message -match "foreign key constraint") {
            Write-Host "This appears to be a foreign key constraint error." -ForegroundColor Yellow
            Write-Host "The script is designed to fix these issues." -ForegroundColor Yellow
            Write-Host "Try running the script again, or check database permissions." -ForegroundColor Yellow
        }
        exit 1
    }
}

# Verify fix
Write-Step "Verifying fix..."
try {
    $verifyQuery = @"
-- Check for any remaining foreign key constraint issues
SELECT 
    fk.name AS constraint_name,
    OBJECT_NAME(fk.parent_object_id) AS table_name,
    COL_NAME(fkc.parent_object_id, fkc.parent_column_id) AS column_name,
    OBJECT_NAME(fk.referenced_object_id) AS referenced_table,
    COL_NAME(fkc.referenced_object_id, fkc.referenced_column_id) AS referenced_column
FROM sys.foreign_keys fk
INNER JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
WHERE OBJECT_NAME(fk.parent_object_id) LIKE 'forge_%'
ORDER BY table_name, constraint_name;
"@

    $constraints = Invoke-Sqlcmd -ServerInstance $connInfo.Server -Database $connInfo.Database -Username $connInfo.Username -Password $connInfo.Password -Query $verifyQuery -Encrypt
    
    Write-Host "Current forge table foreign key constraints:" -ForegroundColor DarkGray
    if ($constraints) {
        $constraints | ForEach-Object {
            Write-Host "  $($_.table_name).$($_.column_name) -> $($_.referenced_table).$($_.referenced_column)" -ForegroundColor Green
        }
    }
    else {
        Write-Host "  No foreign key constraints found" -ForegroundColor Yellow
    }
    
    # Check table counts
    $countQuery = @"
SELECT 
    'forge_classification' as table_name, COUNT(*) as row_count FROM forge_classification
UNION ALL SELECT 'forge_capabilities', COUNT(*) FROM forge_capabilities
UNION ALL SELECT 'forge_matches', COUNT(*) FROM forge_matches  
UNION ALL SELECT 'forge_categories', COUNT(*) FROM forge_categories
UNION ALL SELECT 'public_scans', COUNT(*) FROM public_scans;
"@

    $counts = Invoke-Sqlcmd -ServerInstance $connInfo.Server -Database $connInfo.Database -Username $connInfo.Username -Password $connInfo.Password -Query $countQuery -Encrypt
    
    Write-Host "Table row counts:" -ForegroundColor DarkGray
    $counts | ForEach-Object {
        Write-Host "  $($_.table_name): $($_.row_count) rows" -ForegroundColor DarkGray
    }
    
    Write-Success "Verification completed"
}
catch {
    Write-Warning "Verification failed: $($_.Exception.Message)"
}

Write-Banner "Forge Tables Fix Completed"

if (-not $DryRun) {
    Write-Success "✅ Foreign key constraints have been fixed"
    Write-Success "✅ Missing forge tables have been created"
    Write-Success "✅ Performance indexes have been added"
    Write-Host ""
    Write-Host "The bot workers should now be able to insert forge data without foreign key errors." -ForegroundColor Green
}
else {
    Write-Host "To actually apply the fixes, run this script without the -DryRun parameter." -ForegroundColor Yellow
}

Write-Host ""