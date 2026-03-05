#!/bin/bash
# =====================================================================
# Bash Script: Fix Forge Tables Foreign Key Issues
# =====================================================================
#
# Purpose: Execute the SQL script to fix forge table foreign key constraints
# and ensure all required tables exist with proper relationships
#
# Prerequisites:
# - sqlcmd installed (Microsoft SQL Server command-line tools)
# - Access to Azure SQL Database  
# - DATABASE_URL environment variable set
#
# Usage:
#   ./scripts/fix_forge_tables.sh
#   ./scripts/fix_forge_tables.sh --dry-run
#   ./scripts/fix_forge_tables.sh --verbose
# =====================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Script options
DRY_RUN=false
VERBOSE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--verbose]"
            echo ""
            echo "Options:"
            echo "  --dry-run    Show what would be executed without making changes"
            echo "  --verbose    Enable verbose output"
            echo "  -h, --help   Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  DATABASE_URL    ODBC connection string for Azure SQL Database"
            echo ""
            echo "Example:"
            echo "  export DATABASE_URL='Driver={ODBC Driver 18 for SQL Server};Server=myserver.database.windows.net;Database=sigil;Uid=myuser;Pwd=mypassword;'"
            echo "  $0"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Helper functions
write_banner() {
    echo -e "\n${CYAN}======================================================================${NC}"
    echo -e "${CYAN} $1${NC}"
    echo -e "${CYAN}======================================================================${NC}\n"
}

write_step() {
    echo -e "${YELLOW}[STEP]${NC} $1"
}

write_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

write_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

write_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

parse_connection_string() {
    local conn_str="$1"
    
    # Extract server, database, username, password from ODBC connection string
    SERVER=$(echo "$conn_str" | grep -oP 'Server=\K[^;]+' || echo "")
    DATABASE=$(echo "$conn_str" | grep -oP 'Database=\K[^;]+' || echo "")
    USERNAME=$(echo "$conn_str" | grep -oP 'Uid=\K[^;]+' || echo "")
    PASSWORD=$(echo "$conn_str" | grep -oP 'Pwd=\K[^;]+' || echo "")
    
    if [[ -z "$SERVER" || -z "$DATABASE" || -z "$USERNAME" || -z "$PASSWORD" ]]; then
        write_error "Invalid DATABASE_URL format"
        echo "Expected format: Driver={ODBC Driver 18 for SQL Server};Server=server.database.windows.net;Database=dbname;Uid=username;Pwd=password;"
        exit 1
    fi
}

test_sqlcmd() {
    if ! command -v sqlcmd &> /dev/null; then
        write_error "sqlcmd command not found"
        echo "Please install Microsoft SQL Server command-line tools:"
        echo ""
        echo "Ubuntu/Debian:"
        echo "  curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -"
        echo "  curl https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/mssql-tools.list | sudo tee /etc/apt/sources.list.d/mssql-tools.list"
        echo "  sudo apt-get update && sudo apt-get install -y mssql-tools unixodbc-dev"
        echo ""
        echo "CentOS/RHEL:"
        echo "  sudo curl -o /etc/yum.repos.d/msprod.repo https://packages.microsoft.com/config/rhel/8/mssql-tools.repo"
        echo "  sudo yum install -y mssql-tools unixODBC-devel"
        echo ""
        echo "macOS:"
        echo "  brew install mssql-tools18"
        exit 1
    fi
}

test_connection() {
    write_step "Testing database connection..."
    
    if $DRY_RUN; then
        write_warning "DRY RUN: Skipping connection test"
        return 0
    fi
    
    local test_query="SELECT 1 as test"
    
    if sqlcmd -S "$SERVER" -d "$DATABASE" -U "$USERNAME" -P "$PASSWORD" -C -Q "$test_query" -h -1 -W &>/dev/null; then
        write_success "Database connection successful"
    else
        write_error "Cannot connect to database"
        echo "Please verify:"
        echo "- Database server is accessible: $SERVER"
        echo "- Database exists: $DATABASE"  
        echo "- Credentials are correct: $USERNAME"
        echo "- Firewall allows connections"
        exit 1
    fi
}

check_current_tables() {
    write_step "Checking current forge table state..."
    
    if $DRY_RUN; then
        write_warning "DRY RUN: Skipping table state check"
        return 0
    fi
    
    local table_check_query="
    SELECT 
        TABLE_NAME,
        CASE WHEN TABLE_NAME IS NOT NULL THEN 'EXISTS' ELSE 'MISSING' END as STATUS
    FROM INFORMATION_SCHEMA.TABLES 
    WHERE TABLE_NAME IN ('forge_classification', 'forge_capabilities', 'forge_matches', 'forge_categories', 'forge_trust_score_history', 'public_scans')
    ORDER BY TABLE_NAME;
    "
    
    echo -e "${GRAY}Current table status:${NC}"
    
    sqlcmd -S "$SERVER" -d "$DATABASE" -U "$USERNAME" -P "$PASSWORD" -C -Q "$table_check_query" -h -1 -W | while read -r line; do
        if [[ "$line" == *"EXISTS"* ]]; then
            echo -e "  ${GREEN}$line${NC}"
        elif [[ "$line" == *"MISSING"* ]]; then
            echo -e "  ${RED}$line${NC}"
        else
            echo -e "  ${GRAY}$line${NC}"
        fi
    done
}

execute_sql_script() {
    local script_path="$1"
    
    if [[ ! -f "$script_path" ]]; then
        write_error "SQL script not found: $script_path"
        exit 1
    fi
    
    write_success "SQL script found: $script_path"
    
    if $DRY_RUN; then
        write_warning "DRY RUN MODE - SQL script will not be executed"
        echo "Would execute: $script_path"
        return 0
    fi
    
    write_step "Executing SQL fix script..."
    
    local sqlcmd_args=(-S "$SERVER" -d "$DATABASE" -U "$USERNAME" -P "$PASSWORD" -C -i "$script_path")
    
    if $VERBOSE; then
        sqlcmd_args+=(-e)
    fi
    
    if sqlcmd "${sqlcmd_args[@]}"; then
        write_success "SQL script executed successfully"
    else
        write_error "Failed to execute SQL script"
        echo "Check database permissions and connection settings"
        exit 1
    fi
}

verify_fix() {
    write_step "Verifying fix..."
    
    if $DRY_RUN; then
        write_warning "DRY RUN: Skipping verification"
        return 0
    fi
    
    # Check foreign key constraints
    local fk_query="
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
    "
    
    echo -e "${GRAY}Current forge table foreign key constraints:${NC}"
    local fk_output
    fk_output=$(sqlcmd -S "$SERVER" -d "$DATABASE" -U "$USERNAME" -P "$PASSWORD" -C -Q "$fk_query" -h -1 -W)
    
    if [[ -n "$fk_output" && "$fk_output" != *"0 rows affected"* ]]; then
        echo "$fk_output" | while read -r line; do
            echo -e "  ${GREEN}$line${NC}"
        done
    else
        echo -e "  ${YELLOW}No foreign key constraints found${NC}"
    fi
    
    # Check table counts
    local count_query="
    SELECT 'forge_classification' as table_name, COUNT(*) as row_count FROM forge_classification
    UNION ALL SELECT 'forge_capabilities', COUNT(*) FROM forge_capabilities  
    UNION ALL SELECT 'forge_matches', COUNT(*) FROM forge_matches
    UNION ALL SELECT 'forge_categories', COUNT(*) FROM forge_categories
    UNION ALL SELECT 'public_scans', COUNT(*) FROM public_scans;
    "
    
    echo -e "${GRAY}Table row counts:${NC}"
    sqlcmd -S "$SERVER" -d "$DATABASE" -U "$USERNAME" -P "$PASSWORD" -C -Q "$count_query" -h -1 -W | while read -r line; do
        echo -e "  ${GRAY}$line${NC}"
    done
    
    write_success "Verification completed"
}

# =====================================================================
# Main Script Execution
# =====================================================================

write_banner "Sigil Forge Tables Fix - Foreign Key Repair"

# Check prerequisites
write_step "Checking prerequisites..."

test_sqlcmd
write_success "sqlcmd command available"

# Check DATABASE_URL
if [[ -z "${DATABASE_URL:-}" ]]; then
    write_error "DATABASE_URL environment variable not set"
    echo "Please set DATABASE_URL with format:"
    echo "export DATABASE_URL='Driver={ODBC Driver 18 for SQL Server};Server=server.database.windows.net;Database=dbname;Uid=username;Pwd=password;'"
    exit 1
fi

write_success "DATABASE_URL environment variable found"

# Parse connection information
write_step "Parsing connection information..."
parse_connection_string "$DATABASE_URL"
write_success "Connection string parsed successfully"
echo -e "  ${GRAY}Server: $SERVER${NC}"
echo -e "  ${GRAY}Database: $DATABASE${NC}"

# Test connection
test_connection

# Check current table state
check_current_tables

# Find and execute SQL script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_SCRIPT="$SCRIPT_DIR/fix_forge_tables_mssql.sql"

execute_sql_script "$SQL_SCRIPT"

# Verify the fix
verify_fix

# Final summary
write_banner "Forge Tables Fix Completed"

if [[ "$DRY_RUN" == "false" ]]; then
    write_success "✅ Foreign key constraints have been fixed"
    write_success "✅ Missing forge tables have been created" 
    write_success "✅ Performance indexes have been added"
    echo ""
    echo -e "${GREEN}The bot workers should now be able to insert forge data without foreign key errors.${NC}"
else
    echo -e "${YELLOW}To actually apply the fixes, run this script without the --dry-run parameter.${NC}"
fi

echo ""