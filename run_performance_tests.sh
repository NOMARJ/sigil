#!/bin/bash

# Forge Premium Performance Testing Suite
# Runs all performance tests and generates consolidated report

set -e

echo "=========================================="
echo "Forge Premium Performance Testing Suite"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create results directory
RESULTS_DIR="performance_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "Results will be saved to: $RESULTS_DIR"
echo ""

# Function to run test and check result
run_test() {
    local test_name=$1
    local test_command=$2
    local output_file=$3
    
    echo -n "Running $test_name... "
    
    if $test_command > "$RESULTS_DIR/$output_file" 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Check $RESULTS_DIR/$output_file for details"
        return 1
    fi
}

# Track overall results
TESTS_PASSED=0
TESTS_FAILED=0

echo "=== Phase 1: Frontend Performance ==="
echo ""

# Check if dashboard dependencies are installed
if [ ! -d "dashboard/node_modules" ]; then
    echo "Installing dashboard dependencies..."
    cd dashboard && npm install && cd ..
fi

# Build dashboard to check bundle size
echo -n "Building dashboard for bundle analysis... "
if cd dashboard && npm run build > "../$RESULTS_DIR/build_output.log" 2>&1 && cd ..; then
    echo -e "${GREEN}✓ Complete${NC}"
    
    # Extract bundle sizes
    echo ""
    echo "Bundle Size Analysis:"
    grep -A 30 "Route (app)" "$RESULTS_DIR/build_output.log" | head -25
    echo ""
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ Build failed${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Run Lighthouse tests if available
if command -v lighthouse &> /dev/null; then
    echo ""
    echo "=== Phase 2: Lighthouse Performance ==="
    echo ""
    
    # Make sure dev server is running
    echo "Starting development server..."
    cd dashboard && npm run dev > "../$RESULTS_DIR/dev_server.log" 2>&1 &
    DEV_SERVER_PID=$!
    cd ..
    sleep 5
    
    if run_test "Lighthouse Core Web Vitals" \
        "lighthouse http://localhost:3000/forge/tools --quiet --chrome-flags='--headless' --only-categories=performance --output=json" \
        "lighthouse_report.json"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    
    kill $DEV_SERVER_PID 2>/dev/null || true
else
    echo -e "${YELLOW}⚠ Lighthouse not installed, skipping Core Web Vitals tests${NC}"
fi

echo ""
echo "=== Phase 3: API Load Testing ==="
echo ""

# Check Python dependencies
if ! python3 -c "import locust" 2>/dev/null; then
    echo "Installing Python performance testing dependencies..."
    pip3 install locust asyncpg redis aiohttp --quiet
fi

# Start API server in background
echo "Starting API server..."
cd api && python3 main.py > "../$RESULTS_DIR/api_server.log" 2>&1 &
API_SERVER_PID=$!
cd ..
sleep 3

# Run Locust load tests
if command -v locust &> /dev/null; then
    if run_test "API Load Testing (100 users)" \
        "locust -f api/tests/performance/locustfile.py --host http://localhost:8000 --users 100 --spawn-rate 10 --run-time 60s --headless --only-summary" \
        "locust_results.txt"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "${YELLOW}⚠ Locust not installed, skipping load tests${NC}"
fi

echo ""
echo "=== Phase 4: Database Performance ==="
echo ""

# Check if PostgreSQL is running
if pg_isready -q 2>/dev/null; then
    if run_test "Database Query Performance" \
        "python3 api/tests/performance/test_database_performance.py" \
        "database_performance.json"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "${YELLOW}⚠ PostgreSQL not running, skipping database tests${NC}"
fi

echo ""
echo "=== Phase 5: Redis Cache Performance ==="
echo ""

# Check if Redis is running
if redis-cli ping > /dev/null 2>&1; then
    if run_test "Redis Cache Performance" \
        "python3 api/tests/performance/test_redis_cache_performance.py" \
        "redis_performance.json"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "${YELLOW}⚠ Redis not running, skipping cache tests${NC}"
fi

# Clean up background processes
kill $API_SERVER_PID 2>/dev/null || true

echo ""
echo "=== Phase 6: k6 Load Testing ==="
echo ""

if command -v k6 &> /dev/null; then
    # Start servers again for k6
    cd dashboard && npm run dev > "../$RESULTS_DIR/dev_server_k6.log" 2>&1 &
    DEV_SERVER_PID=$!
    cd ..
    
    cd api && python3 main.py > "../$RESULTS_DIR/api_server_k6.log" 2>&1 &
    API_SERVER_PID=$!
    cd ..
    
    sleep 5
    
    if run_test "k6 Comprehensive Load Test" \
        "k6 run dashboard/performance/k6-forge-load-test.js --quiet --summary-export=$RESULTS_DIR/k6_summary.json" \
        "k6_results.txt"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    
    kill $DEV_SERVER_PID 2>/dev/null || true
    kill $API_SERVER_PID 2>/dev/null || true
else
    echo -e "${YELLOW}⚠ k6 not installed, skipping k6 load tests${NC}"
    echo "  Install with: brew install k6 (macOS) or download from https://k6.io"
fi

echo ""
echo "=========================================="
echo "Performance Test Summary"
echo "=========================================="
echo ""

TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))
PASS_RATE=0
if [ $TOTAL_TESTS -gt 0 ]; then
    PASS_RATE=$((TESTS_PASSED * 100 / TOTAL_TESTS))
fi

echo "Tests Executed: $TOTAL_TESTS"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo "Pass Rate: $PASS_RATE%"
echo ""

# Generate consolidated report
echo "Generating consolidated report..."
cat > "$RESULTS_DIR/SUMMARY.md" << EOF
# Forge Premium Performance Test Results

**Date:** $(date)
**Tests Passed:** $TESTS_PASSED / $TOTAL_TESTS
**Pass Rate:** $PASS_RATE%

## Test Results

### Frontend Performance
- Bundle Size: Check build_output.log
- Lighthouse: Check lighthouse_report.json

### API Performance  
- Load Testing: Check locust_results.txt
- k6 Results: Check k6_results.txt

### Database Performance
- Query Analysis: Check database_performance.json

### Redis Performance
- Cache Analysis: Check redis_performance.json

## Recommendations

Based on the test results, please review:
1. Any failed tests for immediate fixes
2. Performance metrics against targets
3. Optimization opportunities identified

For detailed analysis, see individual test result files.
EOF

echo -e "${GREEN}✓ Report generated: $RESULTS_DIR/SUMMARY.md${NC}"
echo ""

# Final assessment
if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ ALL PERFORMANCE TESTS PASSED!${NC}"
    echo "The Forge Premium features are ready for production deployment."
    exit 0
else
    echo -e "${RED}⚠️  Some tests failed. Review results before deployment.${NC}"
    echo "Check $RESULTS_DIR for detailed results."
    exit 1
fi