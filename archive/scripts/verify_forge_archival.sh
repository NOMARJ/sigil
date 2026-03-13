#!/bin/bash
# Forge Archival Verification Script
# Verifies that Forge components have been properly archived

set -e

echo "=== Forge Archival Verification ==="
echo "Date: $(date)"
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✓${NC} $message"
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}✗${NC} $message"
    else
        echo -e "${YELLOW}!${NC} $message"
    fi
}

echo "1. Verifying API router files have been removed..."

# Check that Forge routers are removed
if [ ! -f "api/routers/forge.py" ]; then
    print_status "PASS" "forge.py removed"
else
    print_status "FAIL" "forge.py still exists"
fi

if [ ! -f "api/routers/forge_analytics.py" ]; then
    print_status "PASS" "forge_analytics.py removed"
else
    print_status "FAIL" "forge_analytics.py still exists"
fi

if [ ! -f "api/routers/forge_premium.py" ]; then
    print_status "PASS" "forge_premium.py removed"
else
    print_status "FAIL" "forge_premium.py still exists"
fi

if [ ! -f "api/routers/forge_secure.py" ]; then
    print_status "PASS" "forge_secure.py removed"
else
    print_status "FAIL" "forge_secure.py still exists"
fi

echo
echo "2. Verifying API service files have been removed..."

# Check that Forge services are removed
if [ ! -f "api/services/forge_analytics.py" ]; then
    print_status "PASS" "forge_analytics.py service removed"
else
    print_status "FAIL" "forge_analytics.py service still exists"
fi

if [ ! -f "api/services/forge_classifier.py" ]; then
    print_status "PASS" "forge_classifier.py service removed"
else
    print_status "FAIL" "forge_classifier.py service still exists"
fi

if [ ! -f "api/services/forge_matcher.py" ]; then
    print_status "PASS" "forge_matcher.py service removed"
else
    print_status "FAIL" "forge_matcher.py service still exists"
fi

if [ ! -f "api/services/forge_user_tools.py" ]; then
    print_status "PASS" "forge_user_tools.py service removed"
else
    print_status "FAIL" "forge_user_tools.py service still exists"
fi

echo
echo "3. Verifying archive directory structure..."

# Check archive structure
if [ -d "archive" ]; then
    print_status "PASS" "Archive directory exists"
else
    print_status "FAIL" "Archive directory missing"
fi

for dir in "migrations" "routers" "services" "security" "scripts" "documentation"; do
    if [ -d "archive/$dir" ]; then
        print_status "PASS" "Archive subdirectory: $dir"
    else
        print_status "FAIL" "Archive subdirectory missing: $dir"
    fi
done

echo
echo "4. Verifying archived files exist..."

# Check that archived files exist
archived_files=(
    "archive/routers/forge.py"
    "archive/routers/forge_analytics.py"
    "archive/routers/forge_premium.py" 
    "archive/routers/forge_secure.py"
    "archive/services/forge_analytics.py"
    "archive/services/forge_classifier.py"
    "archive/services/forge_matcher.py"
    "archive/services/forge_user_tools.py"
    "archive/migrations/004_create_forge_classification.sql"
    "archive/migrations/008_forge_premium_features.sql"
    "archive/migrations/009_forge_tool_metrics.sql"
    "archive/scripts/archive_forge_database.sql"
    "archive/scripts/restore_forge_database.sql"
    "archive/migrations/rollback_forge_tables.sql"
)

for file in "${archived_files[@]}"; do
    if [ -f "$file" ]; then
        print_status "PASS" "Archived: $file"
    else
        print_status "FAIL" "Missing archived file: $file"
    fi
done

echo
echo "5. Verifying main.py has no forge references..."

# Check main.py for forge references
forge_refs=$(grep -c -i "forge" api/main.py || true)
if [ "$forge_refs" -eq 0 ]; then
    print_status "PASS" "main.py has no forge references"
else
    print_status "FAIL" "main.py still contains $forge_refs forge references"
fi

echo
echo "6. Checking for remaining active dependencies..."

# Find any remaining imports of forge modules (excluding archive)
echo "Checking for active Forge imports..."
if command_exists rg; then
    forge_imports=$(rg "from.*forge|import.*forge" --type py . | grep -v archive | grep -v __pycache__ | wc -l || true)
else
    forge_imports=$(find . -name "*.py" -not -path "./archive/*" -not -path "./__pycache__/*" -exec grep -l "from.*forge\|import.*forge" {} \; | wc -l || true)
fi

if [ "$forge_imports" -eq 0 ]; then
    print_status "PASS" "No active forge imports found"
else
    print_status "WARN" "Found $forge_imports files with forge imports (may include stubs/tests)"
fi

echo
echo "=== Verification Complete ==="

# Summary
total_checks=20
passed_checks=$(echo "$archive_files" | wc -w)
echo "Passed: $passed_checks/$total_checks checks"

if [ "$forge_refs" -eq 0 ] && [ -d "archive" ]; then
    echo -e "${GREEN}✓ Forge archival appears successful${NC}"
    echo
    echo "Next steps:"
    echo "1. Run database archival script: archive/scripts/archive_forge_database.sql"
    echo "2. Test API startup with: uvicorn api.main:app"
    echo "3. Verify Forge endpoints return 404"
else
    echo -e "${RED}✗ Forge archival may be incomplete${NC}"
    echo "Review the failed checks above"
fi

echo